//! Enrollment: a one-time token from the console becomes an identity of the agent's own.
//! The key pair is made here; only the public key leaves the machine.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::keys::{self, AgentKey, KeyAlg};

/// The enrollment record kept in the state directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrollment {
    /// `agt_<ulid>`.
    pub agent_id: String,
    /// The owning account.
    pub account_id: String,
    /// The OAuth2 client this agent authenticates as.
    pub client_id: String,
    /// Where access tokens come from.
    pub token_endpoint: Url,
    /// Token audience.
    pub audience: String,
    /// Token scope.
    pub scope: String,
    /// The environment the platform bound this agent to.
    pub environment: String,
    /// The domains the platform bound this agent to.
    pub domains: Vec<String>,
    /// The API this enrollment belongs to.
    pub api: Url,
    /// When, RFC 3339.
    pub enrolled_at: String,
}

/// The request body of `POST /v1/agents/enroll`.
#[derive(Debug, Serialize)]
struct EnrollRequest<'a> {
    token: &'a str,
    public_jwk: Value,
    name: &'a str,
    version: &'a str,
    os: &'a str,
    arch: &'a str,
    policy_hash: &'a str,
}

#[derive(Debug, Deserialize)]
struct EnrollResponse {
    agent_id: String,
    account_id: String,
    client_id: String,
    token_endpoint: Url,
    audience: String,
    scope: String,
    environment: String,
    #[serde(default)]
    domains: Vec<String>,
}

/// The enrollment file inside a state directory.
#[must_use]
pub fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join("enrollment.json")
}

impl Enrollment {
    /// Reads the enrollment record, if there is one.
    ///
    /// # Errors
    /// When the file exists but cannot be read or parsed.
    pub fn load(state_dir: &Path) -> Result<Option<Self>> {
        let path = state_file(state_dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| Error::Config(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io(path, e)),
        }
    }

    fn save(&self, state_dir: &Path) -> Result<()> {
        let path = state_file(state_dir);
        let json = serde_json::to_vec_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        keys::write_private(&path, &json, true)
    }
}

/// What enrollment needs.
#[derive(Debug)]
pub struct EnrollParams<'a> {
    /// API base.
    pub api: &'a Url,
    /// The one-time token (`ioe_…`).
    pub token: &'a str,
    /// Agent name.
    pub name: &'a str,
    /// The environment the local configuration and policy name.
    pub environment: &'a str,
    /// The policy hash.
    pub policy_hash: &'a str,
    /// Key kind.
    pub key_alg: KeyAlg,
    /// Where the key goes.
    pub key_path: &'a Path,
    /// Where the record goes.
    pub state_dir: &'a Path,
    /// Replace an existing key and record.
    pub replace: bool,
    /// HTTP client.
    pub http: &'a reqwest::Client,
}

/// Checks a token's shape without echoing it.
///
/// # Errors
/// When it is not an `ioe_` token.
pub fn check_token_shape(token: &str) -> Result<()> {
    let body = token.strip_prefix("ioe_").unwrap_or("");
    if body.len() < 16
        || body.len() > 128
        || !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'=')
    {
        return Err(Error::Enroll(
            "that is not an enrollment token (they start with ioe_); create one in the console under Reliability > Agents or with iohr agent init".into(),
        ));
    }
    Ok(())
}

/// Makes a key, presents the token, and stores the key and the enrollment record.
///
/// # Errors
/// When a key already exists (and `replace` is not set), the platform refuses, or the
/// platform's answer does not match the local configuration.
pub async fn enroll(p: EnrollParams<'_>) -> Result<Enrollment> {
    check_token_shape(p.token)?;
    if !p.replace && (p.key_path.exists() || state_file(p.state_dir).exists()) {
        return Err(Error::Enroll(format!(
            "already enrolled ({} exists); pass --force to enroll again with a new key",
            p.key_path.display()
        )));
    }
    let key = AgentKey::generate(p.key_alg)?;
    // Write the key first under a temporary name: if the platform accepts the public key,
    // the private one must already be safe on disk.
    let tmp = p.key_path.with_extension("key.new");
    let _ = std::fs::remove_file(&tmp);
    key.save(&tmp, false)?;
    let body = EnrollRequest {
        token: p.token,
        public_jwk: key.public_jwk(),
        name: p.name,
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        policy_hash: p.policy_hash,
    };
    let url = p
        .api
        .join("v1/agents/enroll")
        .map_err(|e| Error::Enroll(e.to_string()))?;
    let result = async {
        let resp = p.http.post(url).json(&body).send().await.map_err(|e| {
            Error::Enroll(format!("could not reach {}: {}", p.api, without_url(&e)))
        })?;
        if !resp.status().is_success() {
            return Err(Error::Enroll(problem(resp).await));
        }
        resp.json::<EnrollResponse>()
            .await
            .map_err(|e| Error::Enroll(format!("unexpected answer: {}", without_url(&e))))
    }
    .await;
    let r = match result {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    if r.environment != p.environment {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Enroll(format!(
            "the token is for environment {:?} but this agent's configuration and policy say {:?}",
            r.environment, p.environment
        )));
    }
    std::fs::rename(&tmp, p.key_path).map_err(|e| Error::io(p.key_path, e))?;
    let record = Enrollment {
        agent_id: r.agent_id,
        account_id: r.account_id,
        client_id: r.client_id,
        token_endpoint: r.token_endpoint,
        audience: r.audience,
        scope: r.scope,
        environment: r.environment,
        domains: r.domains,
        api: p.api.clone(),
        enrolled_at: now_rfc3339(),
    };
    record.save(p.state_dir)?;
    Ok(record)
}

/// Turns an error answer into a message: status plus the problem's `title`/`detail`.
pub(crate) async fn problem(resp: reqwest::Response) -> String {
    let status = resp.status();
    let text = Zeroizing::new(resp.text().await.unwrap_or_default());
    let detail = serde_json::from_str::<Value>(&text).ok().and_then(|v| {
        let t = v
            .get("detail")
            .or_else(|| v.get("title"))
            .or_else(|| v.get("error_description"));
        t.and_then(Value::as_str)
            .map(|s| s.chars().take(200).collect::<String>())
    });
    match detail {
        Some(d) => format!("the platform answered {}: {d}", status.as_u16()),
        None => format!("the platform answered {}", status.as_u16()),
    }
}

/// reqwest errors print the URL; ours never carry tokens in URLs, but keep messages short.
pub(crate) fn without_url(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    if let Some(u) = e.url() {
        s = s.replace(&format!(" for url ({u})"), "");
    }
    s
}

/// The current time, RFC 3339.
#[must_use]
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape() {
        assert!(check_token_shape("ioe_ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").is_ok());
        assert!(check_token_shape("iohr_ABCDEFGHIJKLMNOPQRSTUVWXYZ").is_err());
        assert!(check_token_shape("ioe_short").is_err());
        let e = check_token_shape("ioe_has spaces and more text").unwrap_err();
        assert!(!e.to_string().contains("spaces"), "never echo the token");
    }
}
