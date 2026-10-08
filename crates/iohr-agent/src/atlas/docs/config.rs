//! `[docs]` in `agent.toml`: the documentation sources this agent reads. Credentials are
//! secret references (`env:`, `file:`, `k8s:`, `vault:`), never values, and the policy's
//! `[secrets] allow` must list each one; the provider's host must pass the policy's
//! `[networks]` like any check target.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use super::Provider;
use crate::secrets::SecretRef;

/// Most items one source fetches in one run, unless its `max_items` says otherwise.
pub const DEFAULT_MAX_ITEMS: u32 = 5_000;

/// The documentation sources.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocsConfig {
    /// Where the normalized copies live, one directory per source (default:
    /// `<state_dir>/docs`). Readable by the agent's user only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_dir: Option<PathBuf>,
    /// The sources, read by `iohr-agent atlas docs sync`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<DocsSourceConfig>,
}

/// One documentation source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocsSourceConfig {
    /// A name for it: lower-case letters, digits and `-`, at most 40, unique. It names the
    /// entities (`doc/<id>/...`) and the local store, so renaming it starts over.
    pub id: String,
    /// The provider.
    pub provider: Provider,
    /// The credential as a secret reference, never the value: `env:NOTION_TOKEN`,
    /// `file:/run/secrets/notion`, `k8s:<namespace>/<name>#<key>`,
    /// `vault:<mount>/<path>#<key>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// The API's base URL, when it is not the provider's public one (a test server, an
    /// egress gateway). `https`, or `http` to a loopback address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<Url>,
    /// Read comments too, where the provider and the credential allow it.
    #[serde(default = "yes")]
    pub comments: bool,
    /// Requests per minute at most (default: the provider's published limit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_minute: Option<u32>,
    /// Items fetched per run at most (default 5000). A run that reaches it is incomplete,
    /// and the next run continues.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u32>,
}

const fn yes() -> bool {
    true
}

impl DocsConfig {
    /// Whether nothing is configured (left out of the printed file then).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.content_dir.is_none() && self.sources.is_empty()
    }

    /// The content directory: the configured one, else `<state_dir>/docs`.
    #[must_use]
    pub fn content_dir(&self, state_dir: &Path) -> PathBuf {
        self.content_dir
            .clone()
            .unwrap_or_else(|| state_dir.join("docs"))
    }

    /// Every rule broken, as `docs.sources[i].field: message`.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for (i, s) in self.sources.iter().enumerate() {
            let at = format!("docs.sources[{i}]");
            if !valid_id(&s.id) {
                out.push(format!(
                    "{at}.id: {:?} must be 1 to 40 lower-case letters, digits or '-', starting with a letter",
                    s.id
                ));
            } else if !seen.insert(s.id.as_str()) {
                out.push(format!("{at}.id: {:?} is used twice", s.id));
            }
            match &s.token {
                None => out.push(format!(
                    "{at}.token: {} needs a credential reference",
                    s.provider
                )),
                Some(t) => {
                    if t.parse::<SecretRef>().is_err() {
                        out.push(format!(
                            "{at}.token: must be a secret reference (env:, file:, k8s:, vault:), never the value"
                        ));
                    }
                }
            }
            if let Some(u) = &s.base_url
                && let Err(e) = check_base_url(u)
            {
                out.push(format!("{at}.base_url: {e}"));
            }
            if s.requests_per_minute == Some(0) {
                out.push(format!("{at}.requests_per_minute: must be at least 1"));
            }
            if s.max_items == Some(0) {
                out.push(format!("{at}.max_items: must be at least 1"));
            }
        }
        out
    }
}

/// A source id: `[a-z][a-z0-9-]{0,39}`.
#[must_use]
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 40
        && id.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `https`, or `http` to a loopback address; no credentials, query or fragment.
///
/// # Errors
/// What is wrong with it.
pub fn check_base_url(u: &Url) -> Result<(), String> {
    if !u.username().is_empty() || u.password().is_some() {
        return Err("must not carry credentials".into());
    }
    if u.query().is_some() || u.fragment().is_some() {
        return Err("must not carry a query or fragment".into());
    }
    match u.scheme() {
        "https" => Ok(()),
        "http" => match u.host() {
            Some(url::Host::Ipv4(ip)) if ip.is_loopback() => Ok(()),
            Some(url::Host::Ipv6(ip)) if ip.is_loopback() => Ok(()),
            Some(url::Host::Domain("localhost")) => Ok(()),
            _ => Err("http is allowed only to a loopback address".into()),
        },
        other => Err(format!("scheme {other} is not https")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(id: &str, token: Option<&str>) -> DocsSourceConfig {
        DocsSourceConfig {
            id: id.into(),
            provider: Provider::Notion,
            token: token.map(Into::into),
            base_url: None,
            comments: true,
            requests_per_minute: None,
            max_items: None,
        }
    }

    #[test]
    fn a_good_source_has_no_problems() {
        let c = DocsConfig {
            content_dir: None,
            sources: vec![source("eng-notion", Some("env:NOTION_TOKEN"))],
        };
        assert!(c.problems().is_empty(), "{:?}", c.problems());
    }

    #[test]
    fn a_token_value_is_refused_where_a_reference_belongs() {
        let c = DocsConfig {
            content_dir: None,
            sources: vec![source("n", Some("ntn_1234567890abcdef"))],
        };
        let p = c.problems();
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].contains("secret reference"), "{p:?}");
        assert!(
            !p[0].contains("ntn_1234567890abcdef"),
            "a problem never repeats what may be a secret"
        );
    }

    #[test]
    fn ids_are_unique_and_well_formed_and_a_token_is_required() {
        let c = DocsConfig {
            content_dir: None,
            sources: vec![
                source("a", Some("env:A")),
                source("a", Some("env:B")),
                source("Bad Id", Some("env:C")),
                source("b", None),
            ],
        };
        let p = c.problems();
        assert_eq!(p.len(), 3, "{p:?}");
        assert!(p[0].contains("used twice"));
        assert!(p[1].contains("lower-case"));
        assert!(p[2].contains("needs a credential"));
    }

    #[test]
    fn base_urls_are_https_or_loopback_http() {
        for good in [
            "https://api.notion.com",
            "http://127.0.0.1:9",
            "http://localhost:1",
        ] {
            assert!(check_base_url(&good.parse().unwrap()).is_ok(), "{good}");
        }
        for bad in [
            "http://api.notion.com",
            "ftp://x",
            "https://u:p@api.notion.com",
            "https://api.notion.com/?k=v",
        ] {
            assert!(check_base_url(&bad.parse().unwrap()).is_err(), "{bad}");
        }
    }
}
