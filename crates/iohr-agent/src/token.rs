//! Access tokens by `OAuth2` `client_credentials`, authenticated with a `private_key_jwt`
//! client assertion (RFC 7523) signed by the agent's key. Tokens last 15 minutes and are
//! held only in memory.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::enroll::{Enrollment, problem, without_url};
use crate::error::{Error, Result};
use crate::keys::AgentKey;

/// How long a client assertion is valid (the contract allows at most five minutes).
const ASSERTION_TTL_SECS: i64 = 120;
/// Renew this long before expiry.
const RENEW_MARGIN: Duration = Duration::from_secs(60);

/// Hands out a valid access token, fetching a new one when needed.
#[derive(Debug)]
pub struct TokenSource {
    http: reqwest::Client,
    enrollment: Arc<Enrollment>,
    key: Arc<AgentKey>,
    cached: Mutex<Option<(Zeroizing<String>, Instant)>>,
    ledger: Option<Arc<crate::ledger::Ledger>>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl TokenSource {
    /// A source for this enrollment and key.
    #[must_use]
    pub fn new(http: reqwest::Client, enrollment: Arc<Enrollment>, key: Arc<AgentKey>) -> Self {
        Self {
            http,
            enrollment,
            key,
            cached: Mutex::new(None),
            ledger: None,
        }
    }

    /// Records each token request in the egress ledger before it is sent.
    #[must_use]
    pub fn with_ledger(mut self, ledger: Option<Arc<crate::ledger::Ledger>>) -> Self {
        self.ledger = ledger;
        self
    }

    /// The client assertion: `iss` = `sub` = client id, `aud` = token endpoint, short-lived,
    /// with a random `jti`.
    ///
    /// # Errors
    /// When the random source fails.
    pub fn assertion(&self) -> Result<String> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut jti = [0u8; 16];
        getrandom::fill(&mut jti).map_err(|e| Error::Token(format!("random: {e}")))?;
        let jti = hex(&jti);
        let claims = json!({
            "iss": self.enrollment.client_id,
            "sub": self.enrollment.client_id,
            "aud": self.enrollment.token_endpoint.as_str(),
            "jti": jti,
            "iat": now,
            "exp": now + ASSERTION_TTL_SECS,
        });
        Ok(self.key.sign_jwt(&claims))
    }

    /// A token valid for at least another minute.
    ///
    /// # Errors
    /// When the identity provider refuses the assertion or cannot be reached.
    pub async fn access_token(&self) -> Result<Zeroizing<String>> {
        let mut cached = self.cached.lock().await;
        if let Some((token, expires)) = cached.as_ref()
            && Instant::now() + RENEW_MARGIN < *expires
        {
            return Ok(token.clone());
        }
        let assertion = Zeroizing::new(self.assertion()?);
        let form = [
            ("grant_type", "client_credentials"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion.as_str()),
            ("client_id", self.enrollment.client_id.as_str()),
            ("scope", self.enrollment.scope.as_str()),
            ("audience", self.enrollment.audience.as_str()),
        ];
        let body = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(form)
                .finish(),
        );
        if let Some(l) = &self.ledger {
            let mut dest = self.enrollment.token_endpoint.clone();
            dest.set_query(None);
            l.record(crate::ledger::Record {
                kind: "token_request",
                payload: body.as_bytes(),
                rule: "contract.token",
                destination: dest.as_str(),
                job_id: None,
            })?;
        }
        let resp = self
            .http
            .post(self.enrollment.token_endpoint.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body.as_str().to_owned())
            .send()
            .await
            .map_err(|e| {
                Error::Token(format!(
                    "could not reach the token endpoint: {}",
                    without_url(&e)
                ))
            })?;
        if !resp.status().is_success() {
            return Err(Error::Token(problem(resp).await));
        }
        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|e| Error::Token(format!("unexpected answer: {}", without_url(&e))))?;
        let ttl = Duration::from_secs(body.expires_in.unwrap_or(900).clamp(60, 3600));
        let token = Zeroizing::new(body.access_token);
        *cached = Some((token.clone(), Instant::now() + ttl));
        Ok(token)
    }

    /// Forgets the cached token (after the platform rejected it).
    pub async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
