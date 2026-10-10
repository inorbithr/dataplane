//! The console bundle, served under `/console/` (RFC 0100.1 §2; RFC 0100.4 1.8, slice 1).
//!
//! The bundle is the `agent` build of InOrbit's console (`ui/console`, `CONSOLE_TARGET=agent`):
//! static files that call the local API on this same origin. In this slice it is read from
//! `[admin] console_dir`, a directory the operator controls; a signed bundle verified before
//! the first file is served replaces it in a later phase.
//!
//! The page's rules hold, with one change the console needs (RFC 0100.1 §2): scripts. The
//! CSP admits the bundle's own files (`script-src 'self'`) and each inline script of the
//! HTML page being served by its SHA-256, computed here from the file's bytes, so nothing
//! injected into a page runs. `connect-src 'self'`, `frame-ancestors 'none'`, no CORS.
//!
//! Paths are resolved inside the directory only: no `..`, no hidden files, no symlink out
//! (the canonical path must stay under the canonical directory), files up to [`MAX_FILE`].

use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use sha2::{Digest as _, Sha256};

/// Where the bundle is served.
pub(super) const PREFIX: &str = "/console";
/// The largest file served.
pub(super) const MAX_FILE: u64 = 16 * 1024 * 1024;

/// One file to send.
#[derive(Debug)]
pub(super) struct File {
    /// Content type.
    pub(super) ctype: &'static str,
    /// The bytes.
    pub(super) body: Vec<u8>,
    /// The CSP for this answer.
    pub(super) csp: String,
}

/// Whether the path is the bundle's.
#[must_use]
pub(super) fn is_console(path: &str) -> bool {
    path == PREFIX || path.starts_with("/console/")
}

/// The file for a request path under `/console`, or `None` (404).
#[must_use]
pub(super) fn file(dir: &Path, path: &str) -> Option<File> {
    let rel = path.strip_prefix(PREFIX)?.trim_start_matches('/');
    let resolved = resolve(dir, rel)?;
    let meta = std::fs::metadata(&resolved).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    let body = std::fs::read(&resolved).ok()?;
    let ctype = content_type(&resolved);
    let csp = if ctype.starts_with("text/html") {
        csp_for_html(&body)
    } else {
        csp_for_html(&[])
    };
    Some(File { ctype, body, csp })
}

/// `rel` inside `dir`: the file itself, or `rel/index.html`, or `rel.html`.
fn resolve(dir: &Path, rel: &str) -> Option<PathBuf> {
    if rel.contains('\\') || rel.contains('\0') {
        return None;
    }
    let decoded = url::form_urlencoded::parse(format!("p={rel}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())?;
    let candidate = Path::new(&decoded);
    for c in candidate.components() {
        match c {
            Component::Normal(s) => {
                if s.to_string_lossy().starts_with('.') {
                    return None;
                }
            }
            _ => return None,
        }
    }
    let root = std::fs::canonicalize(dir).ok()?;
    let base = root.join(candidate);
    let tries = if rel.is_empty() || rel.ends_with('/') {
        vec![base.join("index.html")]
    } else {
        vec![
            base.clone(),
            base.join("index.html"),
            base.with_extension("html"),
        ]
    };
    tries.into_iter().find_map(|p| {
        let canonical = std::fs::canonicalize(&p).ok()?;
        (canonical.starts_with(&root) && canonical.is_file()).then_some(canonical)
    })
}

fn content_type(p: &Path) -> &'static str {
    match p.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "application/octet-stream",
    }
}

/// The CSP for an HTML page of the bundle: its own files, plus each inline script of
/// `html` by hash.
#[must_use]
pub(super) fn csp_for_html(html: &[u8]) -> String {
    let hashes: Vec<String> = inline_scripts(html)
        .into_iter()
        .map(|s| {
            format!(
                "'sha256-{}'",
                base64::engine::general_purpose::STANDARD.encode(Sha256::digest(s))
            )
        })
        .collect();
    format!(
        "default-src 'none'; script-src 'self'{}{}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        if hashes.is_empty() { "" } else { " " },
        hashes.join(" ")
    )
}

/// The bodies of `<script>` elements without a `src`, byte for byte.
fn inline_scripts(html: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let lower: Vec<u8> = html.iter().map(u8::to_ascii_lowercase).collect();
    let mut at = 0;
    while let Some(open) = find(&lower[at..], b"<script") {
        let start = at + open;
        let Some(tag_end) = find(&lower[start..], b">") else {
            break;
        };
        let tag = &lower[start..start + tag_end];
        let body_start = start + tag_end + 1;
        let Some(close) = find(&lower[body_start..], b"</script") else {
            break;
        };
        // A tag that only begins with "<script" (`<scripts>`) is not one.
        let real = tag
            .get(7)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b'>')
            || tag.len() == 7;
        if real && find(tag, b" src=").is_none() {
            out.push(&html[body_start..body_start + close]);
        }
        at = body_start + close + 8;
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("monitors")).unwrap();
        std::fs::create_dir_all(d.path().join("_next/static")).unwrap();
        std::fs::write(
            d.path().join("index.html"),
            "<html><script>self.a=1</script><script src=\"/console/_next/static/x.js\"></script></html>",
        )
        .unwrap();
        std::fs::write(d.path().join("monitors/index.html"), "<p>m</p>").unwrap();
        std::fs::write(d.path().join("_next/static/x.js"), "1").unwrap();
        std::fs::write(d.path().join(".secret"), "no").unwrap();
        d
    }

    #[test]
    fn serves_files_and_index_pages() {
        let d = bundle();
        let root = file(d.path(), "/console/").unwrap();
        assert!(root.ctype.starts_with("text/html"));
        assert!(file(d.path(), "/console/monitors/").is_some());
        assert!(file(d.path(), "/console/monitors").is_some());
        let js = file(d.path(), "/console/_next/static/x.js").unwrap();
        assert_eq!(js.ctype, "text/javascript; charset=utf-8");
    }

    #[test]
    fn never_leaves_the_directory() {
        let d = bundle();
        let outside = d.path().parent().unwrap().join("iohr-outside.txt");
        std::fs::write(&outside, "secret").unwrap();
        for p in [
            "/console/../iohr-outside.txt",
            "/console/%2e%2e/iohr-outside.txt",
            "/console/.secret",
            "/console/monitors/..%2f..%2fiohr-outside.txt",
            "/console\\..\\x",
        ] {
            assert!(file(d.path(), p).is_none(), "{p}");
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, d.path().join("link.txt")).unwrap();
            assert!(file(d.path(), "/console/link.txt").is_none());
        }
        let _ = std::fs::remove_file(outside);
    }

    #[test]
    fn the_csp_admits_only_the_pages_own_inline_scripts() {
        let d = bundle();
        let page = file(d.path(), "/console/").unwrap();
        let want = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b"self.a=1"));
        assert!(
            page.csp.contains(&format!("'sha256-{want}'")),
            "{}",
            page.csp
        );
        assert!(page.csp.contains("script-src 'self'"));
        assert!(page.csp.contains("frame-ancestors 'none'"));
        assert!(page.csp.contains("connect-src 'self'"));
        assert!(!page.csp.contains("unsafe-eval"));
        assert!(!page.csp.contains("script-src 'self' 'unsafe-inline'"));
        // An external script is not hashed, and an inline one with odd casing is.
        assert_eq!(
            inline_scripts(b"<SCRIPT>x</SCRIPT><script src=a></script>").len(),
            1
        );
        assert_eq!(inline_scripts(b"<scripts>no</scripts>").len(), 0);
    }
}
