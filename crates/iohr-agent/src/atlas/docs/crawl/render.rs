//! The headless render fallback: a page whose static HTML has no readable text and no
//! links is loaded once in a local Chrome or Chromium (`--headless --dump-dom`) and the
//! DOM it prints is read instead.
//!
//! No browser library is linked: the browser on the machine is run as a process, so the
//! dependency set stays as it was. The trade-off: the browser fetches the page's own
//! scripts and styles itself, outside the crawler's pacing. Its name resolution is pinned
//! with `--host-resolver-rules` to the one address the policy admitted for the page's
//! host and every other name fails, so scripts from a CDN do not load and a page that
//! needs them stays empty (recorded with `rendered: true` and its empty outline).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt as _;
use url::Url;

/// Longest a render may take.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Names a Chrome or Chromium binary is found under on `PATH`, then fixed macOS paths.
const NAMES: &[&str] = &[
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
];
const MAC_APPS: &[&str] = &[
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
];

/// The first Chrome or Chromium on this machine, if any.
#[must_use]
pub fn find_browser() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for n in NAMES {
            let p = dir.join(n);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    MAC_APPS.iter().map(PathBuf::from).find(|p| p.is_file())
}

/// Loads `page` in `browser` with its host pinned to `addr` and returns the DOM it
/// printed, at most `max_bytes`.
///
/// # Errors
/// The browser did not start, failed, or took longer than 30 seconds.
pub async fn dump_dom(
    browser: &Path,
    page: &Url,
    addr: std::net::IpAddr,
    user_agent: &str,
    max_bytes: usize,
) -> Result<String, String> {
    let host = page.host_str().ok_or("the page has no host")?;
    let profile = std::env::temp_dir().join(format!(
        "iohr-render-{}-{}",
        std::process::id(),
        uuid::Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&profile).map_err(|e| format!("cannot make a profile: {e}"))?;
    let rules = format!("MAP {host} {addr}, MAP * ~NOTFOUND");
    let mut child = tokio::process::Command::new(browser)
        .arg("--headless")
        .arg("--disable-gpu")
        .arg("--no-first-run")
        .arg("--disable-extensions")
        .arg("--disable-sync")
        .arg("--disable-background-networking")
        .arg("--virtual-time-budget=5000")
        .arg(format!("--user-agent={user_agent}"))
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("--host-resolver-rules={rules}"))
        .arg("--dump-dom")
        .arg(page.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("cannot start the browser: {e}"))?;
    let out = child.stdout.take();
    let run = async {
        let mut buf = Vec::new();
        if let Some(out) = out {
            let limit = u64::try_from(max_bytes).unwrap_or(u64::MAX);
            out.take(limit)
                .read_to_end(&mut buf)
                .await
                .map_err(|e| format!("cannot read the browser's output: {e}"))?;
        }
        let status = child
            .wait()
            .await
            .map_err(|e| format!("the browser failed: {e}"))?;
        if !status.success() {
            return Err(format!("the browser exited with {status}"));
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    };
    let res = tokio::time::timeout(TIMEOUT, run)
        .await
        .unwrap_or_else(|_| Err("the render took longer than 30 s".into()));
    let _ = std::fs::remove_dir_all(&profile);
    res
}
