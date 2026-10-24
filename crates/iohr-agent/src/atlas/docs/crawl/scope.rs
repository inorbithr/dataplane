//! Which URLs a crawl reads, how it tells two URLs apart, and how it sorts the links it
//! does not follow (RFC 0163).

use serde::{Deserialize, Serialize};
use url::Url;

use super::super::html::looks_like_spec;

/// The registrable domain of `host` by the Public Suffix List (`velebit.ai` for
/// `docs.velebit.ai`, `example.co.uk` for `www.example.co.uk`), else the host itself (an
/// address, `localhost`).
#[must_use]
pub fn registrable(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return host;
    }
    psl::domain_str(&host).map_or(host.clone(), str::to_owned)
}

/// Whether `host` is `scope` or one of its subdomains.
#[must_use]
pub fn in_scope(host: &str, scope: &str) -> bool {
    let host = host.trim_end_matches('.');
    host.eq_ignore_ascii_case(scope)
        || host.len().checked_sub(scope.len() + 1).is_some_and(|at| {
            host.as_bytes()[at] == b'.' && host[at + 1..].eq_ignore_ascii_case(scope)
        })
}

/// Query parameters that only track a visit.
fn tracking(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("utm_")
        || matches!(
            n.as_str(),
            "gclid"
                | "dclid"
                | "fbclid"
                | "msclkid"
                | "yclid"
                | "igshid"
                | "mc_cid"
                | "mc_eid"
                | "_hsenc"
                | "_hsmi"
                | "_ga"
                | "_gl"
                | "ref_src"
                | "mkt_tok"
        )
}

/// `u` without its fragment and tracking parameters: what is requested.
#[must_use]
pub fn clean(u: &Url) -> Url {
    let mut u = u.clone();
    u.set_fragment(None);
    if u.query().is_some() {
        let kept: Vec<(String, String)> = u
            .query_pairs()
            .filter(|(k, _)| !tracking(k))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        if kept.is_empty() {
            u.set_query(None);
        } else {
            u.query_pairs_mut().clear().extend_pairs(kept);
        }
    }
    u
}

/// The visited-set key: [`clean`], scheme and host in lower case and the default port
/// dropped (the URL parser does both), and a trailing slash folded.
#[must_use]
pub fn key(u: &Url) -> String {
    let mut u = clean(u);
    let path = u.path().to_owned();
    if path.len() > 1 && path.ends_with('/') {
        u.set_path(path.trim_end_matches('/'));
    }
    u.to_string()
}

/// Files that are never requested: images, video, audio, fonts, archives, installers,
/// styles and scripts.
#[must_use]
pub fn is_media(u: &Url) -> bool {
    let p = u.path().to_ascii_lowercase();
    let Some((_, ext)) = p.rsplit_once('.') else {
        return false;
    };
    matches!(
        ext,
        "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "webp"
            | "avif"
            | "svg"
            | "ico"
            | "bmp"
            | "tif"
            | "tiff"
            | "heic"
            | "mp4"
            | "webm"
            | "mov"
            | "avi"
            | "mkv"
            | "m4v"
            | "mp3"
            | "wav"
            | "ogg"
            | "flac"
            | "m4a"
            | "aac"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
            | "eot"
            | "zip"
            | "gz"
            | "tgz"
            | "bz2"
            | "xz"
            | "tar"
            | "rar"
            | "7z"
            | "dmg"
            | "pkg"
            | "exe"
            | "msi"
            | "apk"
            | "aab"
            | "ipa"
            | "iso"
            | "bin"
            | "css"
            | "js"
            | "mjs"
            | "map"
            | "wasm"
    )
}

/// What an outgoing link points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkClass {
    /// An app store listing: Google Play, the App Store, Microsoft Store, a browser
    /// extension store.
    AppStore,
    /// A code host: GitHub, GitLab, Bitbucket, Codeberg.
    CodeHost,
    /// A package registry: npm, `PyPI`, crates.io, Maven Central, `NuGet`, Docker Hub and
    /// the like.
    Registry,
    /// API documentation, or an `OpenAPI` or Swagger document.
    ApiDocs,
    /// A sign-up, sign-in or dashboard page.
    SignUp,
    /// Anything else.
    Other,
}

impl LinkClass {
    /// Its name in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppStore => "app_store",
            Self::CodeHost => "code_host",
            Self::Registry => "registry",
            Self::ApiDocs => "api_docs",
            Self::SignUp => "sign_up",
            Self::Other => "other",
        }
    }
}

fn host_is(host: &str, names: &[&str]) -> bool {
    names.iter().any(|n| in_scope(host, n))
}

/// Sorts a link by its host and path.
#[must_use]
#[allow(clippy::too_many_lines)] // one table of known hosts, read top to bottom
pub fn classify(u: &Url) -> LinkClass {
    let host = u.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = u.path().to_ascii_lowercase();
    let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
    if (host == "play.google.com" && path.starts_with("/store/apps"))
        || host_is(
            &host,
            &[
                "apps.apple.com",
                "itunes.apple.com",
                "apps.microsoft.com",
                "chromewebstore.google.com",
                "addons.mozilla.org",
                "appgallery.huawei.com",
                "f-droid.org",
            ],
        )
        || (host == "chrome.google.com" && path.starts_with("/webstore"))
        || (in_scope(&host, "microsoft.com") && path.contains("/store/"))
    {
        return LinkClass::AppStore;
    }
    if looks_like_spec(&path) {
        return LinkClass::ApiDocs;
    }
    if host_is(
        &host,
        &[
            "npmjs.com",
            "npmjs.org",
            "pypi.org",
            "crates.io",
            "search.maven.org",
            "central.sonatype.com",
            "mvnrepository.com",
            "repo1.maven.org",
            "nuget.org",
            "hub.docker.com",
            "rubygems.org",
            "packagist.org",
            "pkg.go.dev",
            "pub.dev",
            "hex.pm",
            "anaconda.org",
            "cocoapods.org",
        ],
    ) {
        return LinkClass::Registry;
    }
    if host_is(
        &host,
        &[
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "codeberg.org",
            "sourceforge.net",
        ],
    ) {
        return LinkClass::CodeHost;
    }
    let api_host = ["docs.", "developer.", "developers.", "api.", "apidocs."]
        .iter()
        .any(|p| host.starts_with(p))
        || host_is(
            &host,
            &[
                "readme.io",
                "redoc.ly",
                "redocly.app",
                "stoplight.io",
                "swaggerhub.com",
                "documenter.getpostman.com",
                "bump.sh",
            ],
        );
    let api_path = [
        "swagger",
        "redoc",
        "api-reference",
        "api-docs",
        "apidocs",
        "openapi",
    ]
    .iter()
    .any(|p| path.contains(p))
        || first == "api";
    if api_host || api_path {
        return LinkClass::ApiDocs;
    }
    let sign_host = [
        "dash.",
        "dashboard.",
        "console.",
        "app.",
        "portal.",
        "my.",
        "account.",
    ]
    .iter()
    .any(|p| host.starts_with(p));
    let sign_path = path.split('/').any(|s| {
        matches!(
            s,
            "signup"
                | "sign-up"
                | "register"
                | "registration"
                | "login"
                | "signin"
                | "sign-in"
                | "dashboard"
                | "console"
                | "join"
        )
    });
    if sign_host || sign_path {
        return LinkClass::SignUp;
    }
    LinkClass::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn the_scope_is_the_registrable_domain() {
        assert_eq!(registrable("docs.velebit.ai"), "velebit.ai");
        assert_eq!(registrable("www.example.co.uk"), "example.co.uk");
        assert_eq!(registrable("user.github.io"), "user.github.io");
        assert_eq!(registrable("localhost"), "localhost");
        assert_eq!(registrable("docs.localhost"), "docs.localhost");
        assert_eq!(registrable("127.0.0.1"), "127.0.0.1");
        assert!(in_scope("docs.velebit.ai", "velebit.ai"));
        assert!(in_scope("VELEBIT.AI.", "velebit.ai"));
        assert!(!in_scope("notvelebit.ai", "velebit.ai"));
        assert!(!in_scope("velebit.ai.evil.test", "velebit.ai"));
    }

    #[test]
    fn keys_fold_what_does_not_change_the_page() {
        let a = key(&u("HTTPS://Docs.Example.com:443/api/?utm_source=x&b=2#top"));
        assert_eq!(a, "https://docs.example.com/api?b=2");
        assert_eq!(key(&u("https://example.com/")), "https://example.com/");
        assert_eq!(
            key(&u("https://example.com/a?gclid=1")),
            "https://example.com/a"
        );
        assert_eq!(
            clean(&u("https://example.com/a/?utm_medium=m#x")).as_str(),
            "https://example.com/a/"
        );
        assert!(is_media(&u("https://example.com/i/logo.PNG")));
        assert!(!is_media(&u("https://example.com/whitepaper.pdf")));
        assert!(!is_media(&u("https://example.com/docs")));
    }

    #[test]
    fn links_are_sorted_into_classes() {
        let cases = [
            (
                "https://play.google.com/store/apps/details?id=com.velebit.babbly",
                LinkClass::AppStore,
            ),
            ("https://apps.apple.com/us/app/x/id123", LinkClass::AppStore),
            ("https://github.com/velebit-ai/", LinkClass::CodeHost),
            ("https://gitlab.com/acme/tool", LinkClass::CodeHost),
            ("https://pypi.org/project/acme/", LinkClass::Registry),
            ("https://www.npmjs.com/package/acme", LinkClass::Registry),
            ("https://crates.io/crates/acme", LinkClass::Registry),
            (
                "https://search.maven.org/artifact/hr.acme/acme",
                LinkClass::Registry,
            ),
            ("https://docs.velebit.ai/api/", LinkClass::ApiDocs),
            ("https://acme.test/assets/openapi.yaml", LinkClass::ApiDocs),
            (
                "https://raw.githubusercontent.com/a/b/main/swagger.json",
                LinkClass::ApiDocs,
            ),
            ("https://dash.velebit.ai/register", LinkClass::SignUp),
            ("https://acme.test/signup", LinkClass::SignUp),
            (
                "https://www.linkedin.com/company/velebitai/",
                LinkClass::Other,
            ),
        ];
        for (link, class) in cases {
            assert_eq!(classify(&u(link)), class, "{link}");
        }
    }
}
