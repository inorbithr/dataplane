//! Listing reads: one anonymous request for each app store page, GitHub organisation,
//! package and API document the crawl found, reduced to a few public fields.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use url::Url;

use super::super::html::{self, looks_like_spec};
use super::scope::{LinkClass, classify};

/// What a listing read is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    /// A Google Play or App Store page, read as HTML.
    Store(Url),
    /// A GitHub organisation (or user): its public repositories.
    GitHubOrg(String),
    /// An npm package.
    Npm(String),
    /// A `PyPI` project.
    PyPi(String),
    /// A crates.io crate.
    Crate(String),
    /// An `OpenAPI`, Swagger or `AsyncAPI` document.
    Spec(Url),
}

impl Target {
    /// Its kind in output.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Store(_) => "app_store",
            Self::GitHubOrg(_) => "github_org",
            Self::Npm(_) => "npm",
            Self::PyPi(_) => "pypi",
            Self::Crate(_) => "crate",
            Self::Spec(_) => "openapi",
        }
    }

    /// The URL it is read from.
    #[must_use]
    pub fn url(&self) -> Option<Url> {
        let s = match self {
            Self::Store(u) | Self::Spec(u) => return Some(u.clone()),
            Self::GitHubOrg(o) => format!("https://api.github.com/orgs/{o}/repos?per_page=100"),
            Self::Npm(p) => format!("https://registry.npmjs.org/{p}/latest"),
            Self::PyPi(p) => format!("https://pypi.org/pypi/{p}/json"),
            Self::Crate(c) => format!("https://crates.io/api/v1/crates/{c}"),
        };
        Url::parse(&s).ok()
    }
}

/// GitHub paths that are not an account.
const GITHUB_RESERVED: &[&str] = &[
    "about",
    "apps",
    "blog",
    "collections",
    "contact",
    "customer-stories",
    "enterprise",
    "events",
    "explore",
    "features",
    "issues",
    "login",
    "marketplace",
    "new",
    "notifications",
    "orgs",
    "pricing",
    "pulls",
    "search",
    "security",
    "settings",
    "signup",
    "site",
    "sponsors",
    "team",
    "topics",
    "trending",
];

fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 214
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b'/'))
}

/// The listing a link names, if it names one.
#[must_use]
pub fn target_of(u: &Url) -> Option<Target> {
    let host = u.host_str()?.to_ascii_lowercase();
    let segs: Vec<&str> = u.path_segments()?.filter(|s| !s.is_empty()).collect();
    if looks_like_spec(&u.path().to_ascii_lowercase()) {
        let mut u = u.clone();
        u.set_fragment(None);
        return Some(Target::Spec(u));
    }
    match classify(u) {
        LinkClass::AppStore => {
            if host == "play.google.com" {
                let id = u.query_pairs().find(|(k, _)| k == "id")?.1.into_owned();
                if !name_ok(&id) {
                    return None;
                }
                let mut s = Url::parse("https://play.google.com/store/apps/details").ok()?;
                s.query_pairs_mut().append_pair("id", &id);
                return Some(Target::Store(s));
            }
            if host == "apps.apple.com" && segs.iter().any(|s| s.starts_with("id")) {
                let mut s = u.clone();
                s.set_query(None);
                s.set_fragment(None);
                return Some(Target::Store(s));
            }
            None
        }
        LinkClass::CodeHost if host == "github.com" || host == "www.github.com" => {
            let org = (*segs.first()?).to_owned();
            (!GITHUB_RESERVED.contains(&org.to_ascii_lowercase().as_str()) && name_ok(&org))
                .then_some(Target::GitHubOrg(org))
        }
        LinkClass::Registry => {
            let pkg = |at: usize| -> Option<String> {
                let rest = segs.get(at..)?;
                let name = if rest.first()?.starts_with('@') {
                    format!("{}/{}", rest.first()?, rest.get(1)?)
                } else {
                    (*rest.first()?).to_owned()
                };
                name_ok(&name).then_some(name)
            };
            if host.ends_with("npmjs.com") && segs.first() == Some(&"package") {
                return pkg(1).map(Target::Npm);
            }
            if host == "pypi.org" && segs.first() == Some(&"project") {
                return pkg(1).filter(|p| !p.contains('/')).map(Target::PyPi);
            }
            if host == "crates.io" && segs.first() == Some(&"crates") {
                return pkg(1).filter(|p| !p.contains('/')).map(Target::Crate);
            }
            None
        }
        _ => None,
    }
}

/// Public fields of a store page: its title, then `SoftwareApplication` JSON-LD (name,
/// category, developer, dates) and Google Play's "Updated on" line.
#[must_use]
pub fn store_fields(page: &str, url: &Url) -> BTreeMap<String, Value> {
    let mut f = BTreeMap::new();
    let o = html::outline(page, url);
    if !o.title.is_empty() {
        f.insert("title".into(), json!(o.title));
    }
    for block in page.split("application/ld+json").skip(1) {
        let Some(start) = block.find('>') else {
            continue;
        };
        let Some(end) = block[start..].find("</script") else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(block[start + 1..start + end].trim()) else {
            continue;
        };
        let ty = v.get("@type").and_then(Value::as_str).unwrap_or_default();
        if !ty.ends_with("Application") {
            continue;
        }
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        if let Some(n) = s("name") {
            f.insert("name".into(), json!(n));
        }
        if let Some(c) = s("applicationCategory") {
            f.insert("category".into(), json!(c));
        }
        let dev = ["author", "publisher"].iter().find_map(|k| {
            v.get(*k)
                .and_then(|a| a.get("name").or(Some(a)))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        if let Some(d) = dev {
            f.insert("developer".into(), json!(d));
        }
        if let Some(d) = s("dateModified").or_else(|| s("datePublished")) {
            f.insert("updated".into(), json!(d));
        }
        break;
    }
    if !f.contains_key("updated")
        && let Some(rest) = page.split("Updated on").nth(1)
    {
        let text = rest
            .split('<')
            .filter_map(|p| p.split_once('>').map(|(_, t)| t.trim()))
            .find(|t| !t.is_empty() && t.len() < 40);
        if let Some(t) = text {
            f.insert("updated".into(), json!(t));
        }
    }
    f
}

/// Public fields of a GitHub repository list: how many, and their names.
#[must_use]
pub fn github_fields(v: &Value) -> BTreeMap<String, Value> {
    let repos = v.as_array().map(Vec::as_slice).unwrap_or_default();
    let names: Vec<&str> = repos
        .iter()
        .filter_map(|r| r.get("name").and_then(Value::as_str))
        .collect();
    let mut f = BTreeMap::new();
    f.insert("repositories".into(), json!(repos.len()));
    f.insert("names".into(), json!(names));
    f
}

/// Name and version of a registry answer.
#[must_use]
pub fn registry_fields(kind: &Target, v: &Value) -> BTreeMap<String, Value> {
    let (name, version) = match kind {
        Target::Npm(_) => (v.pointer("/name"), v.pointer("/version")),
        Target::PyPi(_) => (v.pointer("/info/name"), v.pointer("/info/version")),
        Target::Crate(_) => (v.pointer("/crate/name"), v.pointer("/crate/max_version")),
        _ => (None, None),
    };
    let mut f = BTreeMap::new();
    if let Some(n) = name {
        f.insert("name".into(), n.clone());
    }
    if let Some(n) = version {
        f.insert("version".into(), n.clone());
    }
    f
}

const METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Title, version, server count and operation count of an `OpenAPI` (or Swagger, or
/// `AsyncAPI`) document in JSON or YAML.
///
/// # Errors
/// It is neither, or names no specification version.
pub fn spec_fields(body: &[u8]) -> Result<BTreeMap<String, Value>, String> {
    let v: Value = serde_json::from_slice(body)
        .or_else(|_| serde_yaml_ng::from_slice(body))
        .map_err(|_| "not JSON or YAML".to_owned())?;
    let format = ["openapi", "swagger", "asyncapi"]
        .iter()
        .find_map(|k| {
            v.get(*k).map(|ver| {
                let ver = ver.as_str().map_or_else(|| ver.to_string(), str::to_owned);
                format!("{k} {ver}")
            })
        })
        .ok_or_else(|| "no openapi, swagger or asyncapi version".to_owned())?;
    let mut f = BTreeMap::new();
    f.insert("format".into(), json!(format));
    if let Some(t) = v.pointer("/info/title") {
        f.insert("title".into(), t.clone());
    }
    if let Some(t) = v.pointer("/info/version") {
        f.insert("version".into(), t.clone());
    }
    let servers = match v.get("servers") {
        Some(Value::Array(a)) => a.len(),
        Some(Value::Object(m)) => m.len(),
        _ => usize::from(v.get("host").is_some()),
    };
    f.insert("servers".into(), json!(servers));
    let ops: usize = v
        .get("paths")
        .and_then(Value::as_object)
        .map_or(0, |paths| {
            paths
                .values()
                .filter_map(Value::as_object)
                .map(|item| {
                    item.keys()
                        .filter(|k| METHODS.contains(&k.as_str()))
                        .count()
                })
                .sum()
        });
    f.insert("operations".into(), json!(ops));
    if let Some(ch) = v.get("channels").and_then(Value::as_object) {
        f.insert("channels".into(), json!(ch.len()));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn links_name_their_listings() {
        assert_eq!(
            target_of(&u(
                "https://play.google.com/store/apps/details?id=com.velebit.babbly&hl=en"
            )),
            Some(Target::Store(u(
                "https://play.google.com/store/apps/details?id=com.velebit.babbly"
            )))
        );
        assert_eq!(
            target_of(&u("https://github.com/velebit-ai/")),
            Some(Target::GitHubOrg("velebit-ai".into()))
        );
        assert_eq!(
            target_of(&u("https://github.com/velebit-ai/repo/issues")),
            Some(Target::GitHubOrg("velebit-ai".into()))
        );
        assert_eq!(target_of(&u("https://github.com/features")), None);
        assert_eq!(
            target_of(&u("https://www.npmjs.com/package/@acme/sdk")),
            Some(Target::Npm("@acme/sdk".into()))
        );
        assert_eq!(
            target_of(&u("https://pypi.org/project/acme/")),
            Some(Target::PyPi("acme".into()))
        );
        assert_eq!(
            target_of(&u(
                "https://docs.velebit.ai/assets/openapi-specs/visual-search.yaml"
            )),
            Some(Target::Spec(u(
                "https://docs.velebit.ai/assets/openapi-specs/visual-search.yaml"
            )))
        );
        assert_eq!(target_of(&u("https://www.linkedin.com/company/x")), None);
    }

    #[test]
    fn a_spec_is_reduced_to_counts() {
        let yaml = b"openapi: 3.0.1\ninfo:\n  title: Visual search\n  version: '1.2'\nservers:\n  - url: https://api.example.test\npaths:\n  /a:\n    get: {}\n    post: {}\n    parameters: []\n  /b:\n    delete: {}\n";
        let f = spec_fields(yaml).unwrap();
        assert_eq!(f["format"], json!("openapi 3.0.1"));
        assert_eq!(f["title"], json!("Visual search"));
        assert_eq!(f["version"], json!("1.2"));
        assert_eq!(f["servers"], json!(1));
        assert_eq!(f["operations"], json!(3));
        let swagger = br#"{"swagger":"2.0","info":{"title":"T","version":"1"},"host":"x","paths":{"/a":{"get":{}}}}"#;
        let f = spec_fields(swagger).unwrap();
        assert_eq!(f["format"], json!("swagger 2.0"));
        assert_eq!(f["servers"], json!(1));
        assert!(spec_fields(b"<html></html>").is_err());
    }

    #[test]
    fn a_store_page_gives_its_public_fields() {
        let page = r#"<html><head><title>Babbly - Apps on Google Play</title>
<script type="application/ld+json">{"@type":"SoftwareApplication","name":"Babbly","applicationCategory":"EDUCATION","author":{"@type":"Person","name":"Velebit AI"}}</script>
</head><body><div>Updated on</div><div>Mar 3, 2024</div></body></html>"#;
        let f = store_fields(page, &u("https://play.google.com/store/apps/details?id=x"));
        assert_eq!(f["name"], json!("Babbly"));
        assert_eq!(f["category"], json!("EDUCATION"));
        assert_eq!(f["developer"], json!("Velebit AI"));
        assert_eq!(f["updated"], json!("Mar 3, 2024"));
        let g = github_fields(&json!([{"name":"a"},{"name":"b"}]));
        assert_eq!(g["repositories"], json!(2));
    }
}
