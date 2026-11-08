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
//!
//! Pinning names does not cover a script that fetches an IP address directly, so every
//! request goes to a proxy that cannot be reached except the page's own host: an address
//! literal, loopback included, fails like any other name. WebRTC may only use the proxy,
//! so it cannot send UDP past it. The browser starts from an empty environment plus the
//! base set (`crate::child_env::BASE`): the agent's own settings never reach it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt as _;
use url::Url;

/// A proxy that never answers: the `.invalid` name is refused by the resolver rules too.
const NO_EGRESS_PROXY: &str = "http://iohr-no-egress.invalid:1";

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

/// The browser's flags, the page's URL last.
fn browser_args(
    host: &str,
    addr: std::net::IpAddr,
    user_agent: &str,
    profile: &Path,
) -> Vec<String> {
    vec![
        "--headless".into(),
        "--disable-gpu".into(),
        "--no-first-run".into(),
        "--disable-extensions".into(),
        "--disable-sync".into(),
        "--disable-background-networking".into(),
        "--virtual-time-budget=5000".into(),
        format!("--user-agent={user_agent}"),
        format!("--user-data-dir={}", profile.display()),
        format!("--host-resolver-rules=MAP {host} {addr}, MAP * ~NOTFOUND"),
        // Everything but the page's own host goes to a proxy no name resolves to, so an
        // address literal fails too; `<-loopback>` drops the implicit loopback exception.
        format!("--proxy-server={NO_EGRESS_PROXY}"),
        format!("--proxy-bypass-list={host};<-loopback>"),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
        "--dump-dom".into(),
    ]
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
    let mut cmd = tokio::process::Command::new(browser);
    crate::child_env::isolate_tokio(
        &mut cmd,
        crate::child_env::BASE,
        std::iter::empty::<(&str, &str)>(),
    );
    let mut child = cmd
        .args(browser_args(host, addr, user_agent, &profile))
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A stand-in browser: writes its flags and environment next to itself, prints a DOM.
    fn fake_browser(dir: &Path) -> std::io::Result<PathBuf> {
        let p = dir.join("browser");
        let out = dir.join("seen.txt");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{o}'\nenv >> '{o}'\nprintf '<html><body>ok</body></html>'\n",
                o = out.display()
            ),
        )?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))?;
        Ok(p)
    }

    /// Run in a child the test below starts with the agent's credentials set.
    #[tokio::test]
    async fn probe_render_child() {
        let Some(dir) = std::env::var_os("IOHR_RENDER_PROBE") else {
            return;
        };
        let browser = fake_browser(Path::new(&dir)).unwrap();
        let page = Url::parse("https://docs.example.com/start").unwrap();
        let dom = dump_dom(
            &browser,
            &page,
            "192.0.2.10".parse().unwrap(),
            "iohr-test",
            4096,
        )
        .await
        .unwrap();
        assert!(dom.contains("ok"), "{dom}");
    }

    #[test]
    fn the_browser_reaches_only_the_page_host_and_never_sees_the_agent_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "atlas::docs::crawl::render::tests::probe_render_child",
                "--exact",
            ])
            .env("IOHR_RENDER_PROBE", dir.path())
            .env("IOHR_AGENT_ENROLLMENT_TOKEN", "sentinel-enrol")
            .env("VAULT_TOKEN", "sentinel-vault")
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let seen = std::fs::read_to_string(dir.path().join("seen.txt")).unwrap();
        let lines: Vec<&str> = seen.lines().collect();
        for flag in [
            "--host-resolver-rules=MAP docs.example.com 192.0.2.10, MAP * ~NOTFOUND",
            "--proxy-server=http://iohr-no-egress.invalid:1",
            "--proxy-bypass-list=docs.example.com;<-loopback>",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "https://docs.example.com/start",
        ] {
            assert!(lines.contains(&flag), "{flag} missing: {seen}");
        }
        assert!(seen.contains("PATH="), "{seen}");
        assert!(!seen.contains("sentinel"), "{seen}");
        assert!(
            !seen.contains("VAULT_TOKEN") && !seen.contains("IOHR_AGENT_"),
            "{seen}"
        );
        assert!(!seen.contains("IOHR_RENDER_PROBE"), "{seen}");
    }
}
