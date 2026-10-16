//! Signing in to the local console (RFC 0100.2): people with roles, not one shared token.
//!
//! - **`machine`**: the token in `<state_dir>/admin.token` (0600), as before. Whoever can
//!   read that file is the machine's break-glass **owner**, always recorded as `machine`.
//!   `iohr agent page --open` and the CLI use it.
//! - **`oidc`**: the company's own identity provider, authorization code with PKCE, the
//!   agent as a confidential client (`[console.oidc]` in the policy, the secret a reference).
//!   The ID token comes straight from the issuer's token endpoint over TLS, so its issuer is
//!   validated by TLS (OpenID Connect Core 3.1.3.7, step 6); `iss`, `aud`, `exp` and the
//!   nonce are checked, and the person's groups map to a role by the policy's table. No
//!   group, no role, no session. InOrbit is not involved: it works air-gapped.
//!
//! A session is an opaque id in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` over TLS),
//! with an idle timeout of 30 minutes and an absolute one of 12 hours; it names the person
//! and their role, and every write checks the role and a CSRF token bound to the session.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::policy::{OidcPolicy, Role};

/// How long a session lives without a request.
pub(super) const IDLE: Duration = Duration::from_mins(30);
/// How long a session lives at most.
pub(super) const ABSOLUTE: Duration = Duration::from_hours(12);
/// How long a sign-in at the identity provider may take.
const PENDING_TTL: Duration = Duration::from_mins(10);
/// Sign-ins in flight kept at once.
pub(super) const MAX_PENDING: usize = 32;

/// Who is signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Person {
    /// `machine`, or the identity provider's subject.
    pub who: String,
    /// The name to show.
    pub name: String,
    /// Their role here.
    pub role: Role,
    /// `machine` or `oidc`.
    pub mode: &'static str,
}

impl Person {
    /// The machine's token: the break-glass owner.
    pub(super) fn machine() -> Self {
        Self {
            who: "machine".into(),
            name: "This machine".into(),
            role: Role::Owner,
            mode: "machine",
        }
    }
}

/// A browser session.
#[derive(Debug, Clone)]
pub(super) struct Session {
    pub id: String,
    pub person: Person,
    pub created: Instant,
    pub last: Instant,
}

impl Session {
    pub(super) fn alive(&self) -> bool {
        self.created.elapsed() < ABSOLUTE && self.last.elapsed() < IDLE
    }
}

/// A sign-in at the identity provider, between the redirect and the callback.
#[derive(Debug, Clone)]
pub(super) struct Pending {
    pub state: String,
    pub verifier: String,
    pub nonce: String,
    pub next: String,
    pub created: Instant,
}

impl Pending {
    pub(super) fn alive(&self) -> bool {
        self.created.elapsed() < PENDING_TTL
    }
}

/// 32 random bytes, base64url.
pub(super) fn random() -> String {
    let mut raw = [0u8; 32];
    let _ = getrandom::fill(&mut raw);
    B64.encode(raw)
}

/// The issuer's discovery document, the parts used.
#[derive(Debug, Deserialize)]
pub(super) struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: url::Url,
    pub token_endpoint: url::Url,
}

fn local(u: &url::Url) -> bool {
    u.host_str()
        .is_some_and(|h| h == "127.0.0.1" || h == "localhost" || h == "[::1]")
}

/// Reads the issuer's discovery document; every endpoint must be https (or loopback, for a
/// test issuer on this machine).
///
/// # Errors
/// The document cannot be read, names another issuer, or an endpoint is not https.
pub(super) async fn discover(http: &reqwest::Client, o: &OidcPolicy) -> Result<Discovery, String> {
    let mut url = o.issuer.clone();
    let path = format!(
        "{}/.well-known/openid-configuration",
        url.path().trim_end_matches('/')
    );
    url.set_path(&path);
    let d: Discovery = http
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("the identity provider did not answer: {e}"))?
        .error_for_status()
        .map_err(|e| format!("the identity provider's discovery document: {e}"))?
        .json()
        .await
        .map_err(|e| format!("the identity provider's discovery document: {e}"))?;
    if d.issuer.trim_end_matches('/') != o.issuer.as_str().trim_end_matches('/') {
        return Err("the discovery document names another issuer".into());
    }
    for u in [&d.authorization_endpoint, &d.token_endpoint] {
        if u.scheme() != "https" && !local(u) {
            return Err("the identity provider's endpoints must be https".into());
        }
    }
    Ok(d)
}

/// Where to send the browser: the authorization request with PKCE, a state and a nonce.
pub(super) fn authorize_url(
    d: &Discovery,
    o: &OidcPolicy,
    redirect_uri: &str,
    p: &Pending,
) -> url::Url {
    let challenge = B64.encode(Sha256::digest(p.verifier.as_bytes()));
    let mut u = d.authorization_endpoint.clone();
    u.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &o.client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", "openid profile email")
        .append_pair("state", &p.state)
        .append_pair("nonce", &p.nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    u
}

#[derive(Debug, Deserialize)]
struct TokenAnswer {
    id_token: String,
}

/// Exchanges the code for an ID token at the token endpoint and makes the person from it.
///
/// # Errors
/// The exchange fails, the token does not hold, or the person's groups name no role.
pub(super) async fn finish(
    http: &reqwest::Client,
    d: &Discovery,
    o: &OidcPolicy,
    client_secret: &str,
    redirect_uri: &str,
    p: &Pending,
    code: &str,
) -> Result<Person, String> {
    let answer: TokenAnswer = http
        .post(d.token_endpoint.clone())
        .timeout(Duration::from_secs(10))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", &p.verifier),
            ("client_id", &o.client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await
        .map_err(|e| format!("the identity provider did not answer: {e}"))?
        .error_for_status()
        .map_err(|_| "the identity provider refused the sign-in".to_owned())?
        .json()
        .await
        .map_err(|_| "the identity provider's answer had no ID token".to_owned())?;
    person_from_id_token(&answer.id_token, &d.issuer, o, &p.nonce)
}

/// The person an ID token names, after its claims are checked.
pub(super) fn person_from_id_token(
    id_token: &str,
    issuer: &str,
    o: &OidcPolicy,
    nonce: &str,
) -> Result<Person, String> {
    let payload = id_token
        .split('.')
        .nth(1)
        .ok_or("the ID token is not a JWT")?;
    let bytes = B64
        .decode(payload.trim_end_matches('='))
        .map_err(|_| "the ID token is not a JWT")?;
    let c: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "the ID token is not a JWT")?;
    if c["iss"].as_str().map(|s| s.trim_end_matches('/')) != Some(issuer.trim_end_matches('/')) {
        return Err("the ID token names another issuer".into());
    }
    let aud_ok = match &c["aud"] {
        serde_json::Value::String(a) => a == &o.client_id,
        serde_json::Value::Array(a) => a.iter().any(|x| x.as_str() == Some(&o.client_id)),
        _ => false,
    };
    if !aud_ok {
        return Err("the ID token is for another client".into());
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if c["exp"].as_i64().is_none_or(|e| e <= now) {
        return Err("the ID token has expired".into());
    }
    if c["nonce"].as_str() != Some(nonce) {
        return Err("the ID token's nonce does not match this sign-in".into());
    }
    let sub = c["sub"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("the ID token names nobody")?;
    let groups: Vec<&str> = c[o.groups_claim.as_str()]
        .as_array()
        .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
        .unwrap_or_default();
    let role = o
        .roles
        .iter()
        .filter(|(_, gs)| gs.iter().any(|g| groups.contains(&g.as_str())))
        .map(|(r, _)| *r)
        .max()
        .ok_or("your groups give you no role on this agent; ask the machine's owner")?;
    let name = c["name"]
        .as_str()
        .or_else(|| c["email"].as_str())
        .or_else(|| c["preferred_username"].as_str())
        .unwrap_or(sub);
    Ok(Person {
        who: sub.chars().take(128).collect(),
        name: crate::redact::redact(&name.chars().take(128).collect::<String>()),
        role,
        mode: "oidc",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> OidcPolicy {
        let mut roles = std::collections::BTreeMap::new();
        roles.insert(Role::Admin, vec!["sre-leads".to_owned()]);
        roles.insert(Role::Viewer, vec!["auditors".to_owned()]);
        OidcPolicy {
            issuer: "https://login.example.com".parse().unwrap(),
            name: None,
            client_id: "iohr-agent-console".into(),
            client_secret: "env:X".into(),
            groups_claim: "groups".into(),
            roles,
        }
    }

    fn token(claims: &serde_json::Value) -> String {
        format!("eyJhbGciOiJub25lIn0.{}.sig", B64.encode(claims.to_string()))
    }

    fn good() -> serde_json::Value {
        serde_json::json!({
            "iss": "https://login.example.com",
            "aud": "iohr-agent-console",
            "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 300,
            "nonce": "n1",
            "sub": "u-42",
            "name": "Ana Example",
            "groups": ["engineering", "sre-leads"],
        })
    }

    #[test]
    fn groups_map_to_the_highest_role() {
        let p = person_from_id_token(
            &token(&good()),
            "https://login.example.com",
            &policy(),
            "n1",
        )
        .unwrap();
        assert_eq!(p.role, Role::Admin);
        assert_eq!(p.who, "u-42");
        assert_eq!(p.mode, "oidc");
    }

    #[test]
    fn a_token_that_does_not_hold_is_refused() {
        let o = policy();
        let iss = "https://login.example.com";
        let mut c = good();
        c["aud"] = "someone-else".into();
        assert!(person_from_id_token(&token(&c), iss, &o, "n1").is_err());
        let mut c = good();
        c["exp"] = 1.into();
        assert!(person_from_id_token(&token(&c), iss, &o, "n1").is_err());
        assert!(person_from_id_token(&token(&good()), iss, &o, "other-nonce").is_err());
        let mut c = good();
        c["iss"] = "https://evil.example".into();
        assert!(person_from_id_token(&token(&c), iss, &o, "n1").is_err());
        let mut c = good();
        c["groups"] = serde_json::json!(["engineering"]);
        let e = person_from_id_token(&token(&c), iss, &o, "n1").unwrap_err();
        assert!(e.contains("no role"), "{e}");
    }

    #[test]
    fn the_challenge_is_s256_of_the_verifier() {
        let d = Discovery {
            issuer: "https://login.example.com".into(),
            authorization_endpoint: "https://login.example.com/authorize".parse().unwrap(),
            token_endpoint: "https://login.example.com/token".parse().unwrap(),
        };
        let p = Pending {
            state: "s".into(),
            verifier: "v".into(),
            nonce: "n".into(),
            next: "/console/".into(),
            created: Instant::now(),
        };
        let u = authorize_url(
            &d,
            &policy(),
            "http://127.0.0.1:7790/auth/oidc/callback",
            &p,
        );
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"], B64.encode(Sha256::digest(b"v")));
        assert_eq!(q["state"], "s");
    }
}
