use std::error::Error as _;
use std::time::Instant;

use reqwest::header::{HeaderName, HeaderValue};

use super::{CheckDetail, ErrorClass, Prepared, bounds, elapsed_ms, rfc3339};
use crate::tls::TlsContext;

/// The request headers a check may set besides its credential.
pub(crate) const ALLOWED_HEADERS: [&str; 2] = ["accept", "content-type"];

/// The methods an `http` check may use.
pub(crate) const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

pub(super) async fn check(tls: &TlsContext, p: &Prepared<'_>) -> CheckDetail {
    let started = Instant::now();
    let Some(url) = p.endpoint.url.clone() else {
        return CheckDetail::failed(ErrorClass::Connect, started);
    };
    let wanted = p
        .spec
        .params
        .method
        .as_deref()
        .or(p.spec.method.as_deref())
        .map(str::to_ascii_uppercase);
    let method = match wanted.as_deref() {
        None => reqwest::Method::GET,
        Some(m) if METHODS.contains(&m) => match reqwest::Method::from_bytes(m.as_bytes()) {
            Ok(m) => m,
            Err(_) => return CheckDetail::failed(ErrorClass::Connect, started),
        },
        Some(_) => return CheckDetail::failed(ErrorClass::Connect, started),
    };
    let client = match client(tls, p) {
        Ok(c) => c,
        Err(class) => return CheckDetail::failed(class, started),
    };
    let mut req = client.request(method, url);
    for (name, value) in &p.spec.params.headers {
        if ALLOWED_HEADERS.contains(&name.as_str()) {
            req = req.header(name.as_str(), value.as_str());
        }
    }
    if let Some(body) = &p.spec.params.body {
        let Ok(bytes) = serde_json::to_vec(body) else {
            return CheckDetail::failed(ErrorClass::Connect, started);
        };
        if bytes.len() > bounds::MAX_REQUEST_BYTES {
            return CheckDetail::failed(ErrorClass::Connect, started);
        }
        if !p
            .spec
            .params
            .headers
            .iter()
            .any(|(n, _)| n == "content-type")
        {
            req = req.header("content-type", "application/json");
        }
        req = req.body(bytes);
    }
    req = match with_auth(req, p) {
        Ok(r) => r,
        Err(class) => return CheckDetail::failed(class, started),
    };
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let expires = expiry(&resp);
            // The body is never read: dropping the response closes the connection.
            drop(resp);
            let ok = p
                .spec
                .expect
                .status
                .map_or(status < 400, |want| want == status);
            CheckDetail {
                ok,
                latency_ms: elapsed_ms(started),
                status_code: Some(status),
                error_class: (!ok).then_some(ErrorClass::Status),
                tls_expires_at: expires,
                reading: None,
            }
        }
        Err(e) => CheckDetail::failed(classify(&e), started),
    }
}

/// A client per check: pinned to the address the policy approved, no redirects (a
/// redirect would be a second, unchecked target), no proxy, no connection reuse.
pub(super) fn client(tls: &TlsContext, p: &Prepared<'_>) -> Result<reqwest::Client, ErrorClass> {
    let mut builder = tls
        .reqwest_builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(p.timeout)
        .connect_timeout(p.timeout)
        .pool_max_idle_per_host(0)
        .tls_info(true);
    if p.endpoint.url.as_ref().and_then(|u| u.domain()).is_some() {
        builder = builder.resolve(&p.endpoint.host, p.addr);
    }
    builder.build().map_err(|_| ErrorClass::Tls)
}

/// Adds the check's credential, marked sensitive (never logged, never in a debug print).
pub(super) fn with_auth(
    req: reqwest::RequestBuilder,
    p: &Prepared<'_>,
) -> Result<reqwest::RequestBuilder, ErrorClass> {
    let Some((name, value)) = &p.auth else {
        return Ok(req);
    };
    let (Ok(name), Ok(mut value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value.as_str()),
    ) else {
        return Err(ErrorClass::Connect);
    };
    value.set_sensitive(true);
    Ok(req.header(name, value))
}

/// The leaf certificate's expiry, when the answer came over TLS.
pub(super) fn expiry(resp: &reqwest::Response) -> Option<String> {
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(reqwest::tls::TlsInfo::peer_certificate)
        .and_then(crate::x509::not_after)
        .and_then(rfc3339)
}

/// Reads at most [`bounds::MAX_ANSWER_BYTES`] of an answer; past it, `answer`.
pub(super) async fn read_bounded(mut resp: reqwest::Response) -> Result<Vec<u8>, ErrorClass> {
    let mut buf = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > bounds::MAX_ANSWER_BYTES {
                    return Err(ErrorClass::Answer);
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(buf),
            Err(e) => return Err(classify(&e)),
        }
    }
}

pub(super) fn classify(e: &reqwest::Error) -> ErrorClass {
    if e.is_timeout() {
        return ErrorClass::Timeout;
    }
    let mut source = e.source();
    while let Some(s) = source {
        if s.is::<rustls::Error>() {
            return ErrorClass::Tls;
        }
        if let Some(io) = s.downcast_ref::<std::io::Error>()
            && io
                .get_ref()
                .is_some_and(<dyn std::error::Error + Send + Sync>::is::<rustls::Error>)
        {
            return ErrorClass::Tls;
        }
        source = s.source();
    }
    ErrorClass::Connect
}
