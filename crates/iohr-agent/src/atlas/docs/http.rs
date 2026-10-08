//! The one HTTP client every documentation connector uses: the provider's host must pass
//! the local policy and is pinned to the address the policy admitted (no second lookup),
//! requests are spaced to the provider's rate limit, "too many requests" and server errors
//! are retried with capped, jittered exponential backoff (a `Retry-After` is honoured),
//! answers are capped in size, redirects are not followed, and no request leaves the base
//! URL's origin. Errors name the method, the path and the status, never a header, a query
//! or a body.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, RETRY_AFTER};
use reqwest::{Method, StatusCode};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio::time::Instant;
use url::Url;
use zeroize::Zeroizing;

use super::DocsError;
use crate::policy::{Policy, TargetError};
use crate::tls::TlsContext;

/// How a client paces and retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Requests per minute at most.
    pub per_minute: u32,
    /// Retries of one request after a 429, a 5xx or a network failure.
    pub max_retries: u32,
    /// The first backoff; doubled on every retry.
    pub backoff_base: Duration,
    /// The longest backoff, and the longest `Retry-After` honoured (a longer one gives up).
    pub backoff_max: Duration,
    /// One request's timeout.
    pub timeout: Duration,
    /// The largest answer accepted, in bytes.
    pub max_body: usize,
}

impl Limits {
    /// Defaults for a provider whose published limit is `per_minute`.
    #[must_use]
    pub const fn for_rate(per_minute: u32) -> Self {
        Self {
            per_minute,
            max_retries: 5,
            backoff_base: Duration::from_millis(500),
            backoff_max: Duration::from_secs(60),
            timeout: Duration::from_secs(30),
            max_body: 16 * 1024 * 1024,
        }
    }
}

/// What a client did, in counts.
#[derive(Debug, Default)]
pub struct Stats {
    requests: AtomicU64,
    retries: AtomicU64,
    rate_limited: AtomicU64,
}

impl Stats {
    /// Requests sent, retries included.
    #[must_use]
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
    /// Retries.
    #[must_use]
    pub fn retries(&self) -> u64 {
        self.retries.load(Ordering::Relaxed)
    }
    /// Answers that were 429.
    #[must_use]
    pub fn rate_limited(&self) -> u64 {
        self.rate_limited.load(Ordering::Relaxed)
    }
}

/// A read-only JSON client for one provider origin.
#[derive(Debug)]
pub struct ApiClient {
    http: reqwest::Client,
    base: Url,
    headers: HeaderMap,
    limits: Limits,
    next_slot: Mutex<Option<Instant>>,
    stats: Stats,
}

/// A credential header: its value is marked sensitive (left out of `Debug`) and the
/// zeroizing copy it was built from is dropped by the caller.
///
/// # Errors
/// The value cannot be a header value (a newline in a token file, say).
pub fn secret_header(
    name: &'static str,
    value: &Zeroizing<String>,
) -> Result<(HeaderName, HeaderValue), DocsError> {
    let mut v = HeaderValue::from_str(value.as_str())
        .map_err(|_| DocsError::Refused(format!("the {name} value is not a valid header value")))?;
    v.set_sensitive(true);
    Ok((HeaderName::from_static(name), v))
}

impl ApiClient {
    /// A client for `base`, after the policy admitted its host. `headers` go on every
    /// request (the credential, an API version).
    ///
    /// # Errors
    /// The policy refuses the host ([`DocsError::Refused`]), its name does not resolve, or
    /// TLS cannot be set up.
    pub async fn new(
        base: Url,
        policy: &Policy,
        tls: &TlsContext,
        headers: Vec<(HeaderName, HeaderValue)>,
        limits: Limits,
    ) -> Result<Self, DocsError> {
        super::config::check_base_url(&base).map_err(DocsError::Refused)?;
        let host = base
            .host_str()
            .ok_or_else(|| DocsError::Refused("the base URL has no host".into()))?
            .to_owned();
        let port = base.port_or_known_default().unwrap_or(443);
        let addr = policy
            .resolve_target(&host, port, Duration::from_secs(5))
            .await
            .map_err(|e| match e {
                TargetError::Refused(r) => DocsError::Refused(format!("{host}:{port}: {r}")),
                TargetError::Dns(r) => DocsError::Unavailable(format!("{host}:{port}: {r}")),
            })?;
        crate::tls::install_crypto_provider();
        let mut builder = tls
            .reqwest_builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(limits.timeout);
        let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
        if unbracketed.parse::<std::net::IpAddr>().is_err() {
            builder = builder.resolve(&host, addr);
        }
        let http = builder
            .build()
            .map_err(|e| DocsError::Refused(format!("cannot build an HTTP client: {e}")))?;
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.insert(k, v);
        }
        Ok(Self {
            http,
            base,
            headers: map,
            limits,
            next_slot: Mutex::new(None),
            stats: Stats::default(),
        })
    }

    /// The counts so far.
    #[must_use]
    pub const fn stats(&self) -> &Stats {
        &self.stats
    }

    /// The base URL.
    #[must_use]
    pub const fn base(&self) -> &Url {
        &self.base
    }

    /// `path` (with its query) against the base, refused when it leaves the base's origin.
    ///
    /// # Errors
    /// The path does not parse, or names another origin.
    pub fn url(&self, path: &str) -> Result<Url, DocsError> {
        let u = self
            .base
            .join(path)
            .map_err(|_| DocsError::Refused("a path that does not parse".into()))?;
        if u.origin() != self.base.origin() {
            return Err(DocsError::Refused(
                "a request outside the source's origin".into(),
            ));
        }
        Ok(u)
    }

    /// `GET path`, answered with JSON.
    ///
    /// # Errors
    /// See [`DocsError`].
    pub async fn get(&self, path: &str) -> Result<Value, DocsError> {
        self.send(Method::GET, path, None).await
    }

    /// `POST path` with a JSON body, for providers that read with POST (Notion's search
    /// and queries). Never used to change anything.
    ///
    /// # Errors
    /// See [`DocsError`].
    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, DocsError> {
        self.send(Method::POST, path, Some(body)).await
    }

    async fn pace(&self) {
        let interval = Duration::from_secs(60) / self.limits.per_minute.max(1);
        let mut next = self.next_slot.lock().await;
        let now = Instant::now();
        let at = match *next {
            Some(t) if t > now => t,
            _ => now,
        };
        *next = Some(at + interval);
        drop(next);
        tokio::time::sleep_until(at).await;
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let exp = self
            .limits
            .backoff_base
            .saturating_mul(2u32.saturating_pow(attempt))
            .min(self.limits.backoff_max);
        // Full jitter over the upper half: retries from many agents do not line up.
        let mut b = [0u8; 2];
        let frac = if getrandom::fill(&mut b).is_ok() {
            f64::from(u16::from_le_bytes(b)) / f64::from(u16::MAX)
        } else {
            1.0
        };
        exp.mul_f64(0.5 + frac / 2.0)
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, DocsError> {
        let url = self.url(path)?;
        let what = format!("{method} {}", url.path());
        let mut attempt = 0u32;
        loop {
            self.pace().await;
            self.stats.requests.fetch_add(1, Ordering::Relaxed);
            let mut req = self
                .http
                .request(method.clone(), url.clone())
                .headers(self.headers.clone())
                .header(reqwest::header::ACCEPT, "application/json");
            if let Some(b) = body {
                req = req.json(b);
            }
            let wait = match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return self.read_json(resp, &what).await;
                    }
                    match status {
                        StatusCode::TOO_MANY_REQUESTS => {
                            self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
                            let asked = retry_after(resp.headers());
                            if attempt >= self.limits.max_retries
                                || asked.is_some_and(|d| d > self.limits.backoff_max)
                            {
                                return Err(DocsError::RateLimited {
                                    what,
                                    retry_after: asked,
                                });
                            }
                            asked.unwrap_or_else(|| self.backoff(attempt))
                        }
                        StatusCode::INTERNAL_SERVER_ERROR
                        | StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT => {
                            if attempt >= self.limits.max_retries {
                                return Err(DocsError::Unavailable(format!("{what}: {status}")));
                            }
                            retry_after(resp.headers())
                                .filter(|d| *d <= self.limits.backoff_max)
                                .unwrap_or_else(|| self.backoff(attempt))
                        }
                        StatusCode::UNAUTHORIZED => {
                            return Err(DocsError::Unauthorized(format!("{what}: {status}")));
                        }
                        StatusCode::FORBIDDEN => {
                            return Err(DocsError::Forbidden(format!("{what}: {status}")));
                        }
                        StatusCode::NOT_FOUND | StatusCode::GONE => {
                            return Err(DocsError::NotFound(format!("{what}: {status}")));
                        }
                        _ => return Err(DocsError::Malformed(format!("{what}: {status}"))),
                    }
                }
                Err(e) => {
                    if attempt >= self.limits.max_retries {
                        let why = if e.is_timeout() {
                            "timed out"
                        } else if e.is_connect() {
                            "cannot connect"
                        } else {
                            "request failed"
                        };
                        return Err(DocsError::Unavailable(format!("{what}: {why}")));
                    }
                    self.backoff(attempt)
                }
            };
            attempt += 1;
            self.stats.retries.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(request = %what, attempt, wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX), "docs: retrying");
            tokio::time::sleep(wait).await;
        }
    }

    async fn read_json(&self, mut resp: reqwest::Response, what: &str) -> Result<Value, DocsError> {
        if resp
            .content_length()
            .is_some_and(|n| n > self.limits.max_body as u64)
        {
            return Err(DocsError::TooLarge(what.to_owned()));
        }
        let mut buf = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|_| DocsError::Unavailable(format!("{what}: the answer broke off")))?
        {
            if buf.len() + chunk.len() > self.limits.max_body {
                return Err(DocsError::TooLarge(what.to_owned()));
            }
            buf.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&buf).map_err(|_| DocsError::Malformed(format!("{what}: not JSON")))
    }
}

/// `Retry-After` in seconds. An HTTP date is not honoured (the backoff applies).
fn retry_after(h: &HeaderMap) -> Option<Duration> {
    h.get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn policy() -> Policy {
        Policy::from_toml("environment = \"staging\"\n[networks]\nallow = [\"127.0.0.1/32\"]\n")
            .unwrap()
    }

    fn fast() -> Limits {
        Limits {
            per_minute: 60_000,
            max_retries: 2,
            backoff_base: Duration::from_millis(1),
            backoff_max: Duration::from_millis(20),
            timeout: Duration::from_secs(5),
            max_body: 1024,
        }
    }

    async fn client(server: &MockServer, limits: Limits) -> ApiClient {
        let token = Zeroizing::new("Bearer sekrit-token".to_owned());
        ApiClient::new(
            server.uri().parse().unwrap(),
            &policy(),
            &TlsContext::new(None).unwrap(),
            vec![secret_header("authorization", &token).unwrap()],
            limits,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_429_is_retried_after_the_time_asked() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
            .up_to_n_times(1)
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .and(header("authorization", "Bearer sekrit-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": 1})))
            .mount(&s)
            .await;
        let c = client(&s, fast()).await;
        assert_eq!(c.get("/x").await.unwrap()["ok"], 1);
        assert_eq!(c.stats().requests(), 2);
        assert_eq!(c.stats().retries(), 1);
        assert_eq!(c.stats().rate_limited(), 1);
    }

    #[tokio::test]
    async fn a_retry_after_longer_than_the_cap_gives_up_at_once() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "3600"))
            .mount(&s)
            .await;
        let c = client(&s, fast()).await;
        let e = c.get("/x").await.unwrap_err();
        assert!(
            matches!(e, DocsError::RateLimited { retry_after: Some(d), .. } if d.as_secs() == 3600),
            "{e:?}"
        );
        assert_eq!(c.stats().requests(), 1);
    }

    #[tokio::test]
    async fn server_errors_are_retried_then_reported() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&s)
            .await;
        let c = client(&s, fast()).await;
        let e = c.get("/x?cursor=abc").await.unwrap_err();
        assert_eq!(
            e,
            DocsError::Unavailable("GET /x: 503 Service Unavailable".into())
        );
        assert_eq!(c.stats().requests(), 3, "one try and two retries");
    }

    #[tokio::test]
    async fn refusals_are_not_retried_and_never_carry_the_credential() {
        let s = MockServer::start().await;
        Mock::given(path("/401"))
            .respond_with(ResponseTemplate::new(401).set_body_string("token sekrit-token is bad"))
            .mount(&s)
            .await;
        Mock::given(path("/403"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&s)
            .await;
        Mock::given(path("/404"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&s)
            .await;
        let c = client(&s, fast()).await;
        let e = c.get("/401").await.unwrap_err();
        assert!(matches!(e, DocsError::Unauthorized(_)), "{e:?}");
        assert!(!format!("{e} {e:?} {c:?}").contains("sekrit"), "{e} {c:?}");
        assert!(c.get("/403").await.unwrap_err().is_gone());
        assert!(c.get("/404").await.unwrap_err().is_gone());
        assert_eq!(c.stats().requests(), 3);
    }

    #[tokio::test]
    async fn answers_over_the_cap_and_other_origins_are_refused() {
        let s = MockServer::start().await;
        Mock::given(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(4096)))
            .mount(&s)
            .await;
        let c = client(&s, fast()).await;
        assert!(matches!(
            c.get("/big").await.unwrap_err(),
            DocsError::TooLarge(_)
        ));
        assert!(matches!(
            c.get("https://example.com/x").await.unwrap_err(),
            DocsError::Refused(_)
        ));
        assert!(matches!(
            c.get("//example.com/x").await.unwrap_err(),
            DocsError::Refused(_)
        ));
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let s = MockServer::start().await;
        Mock::given(path("/r"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", "https://example.com/"),
            )
            .mount(&s)
            .await;
        let c = client(&s, fast()).await;
        assert!(matches!(
            c.get("/r").await.unwrap_err(),
            DocsError::Malformed(_)
        ));
    }

    #[tokio::test]
    async fn the_policy_decides_whether_a_host_is_reached() {
        let deny = Policy::from_toml("environment = \"staging\"\n").unwrap();
        let e = ApiClient::new(
            "http://127.0.0.1:9".parse().unwrap(),
            &deny,
            &TlsContext::new(None).unwrap(),
            vec![],
            fast(),
        )
        .await
        .unwrap_err();
        assert!(matches!(e, DocsError::Refused(_)), "{e:?}");
    }

    #[tokio::test]
    async fn requests_are_spaced_to_the_rate_limit() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&s)
            .await;
        let c = client(
            &s,
            Limits {
                per_minute: 600, // 100 ms apart
                ..fast()
            },
        )
        .await;
        let t = std::time::Instant::now();
        for _ in 0..4 {
            c.get("/x").await.unwrap();
        }
        assert!(
            t.elapsed() >= Duration::from_millis(300),
            "{:?}",
            t.elapsed()
        );
    }
}
