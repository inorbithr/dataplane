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
            let status_ok = p
                .spec
                .expect
                .status
                .map_or(status < 400, |want| want == status);
            // Headers are judged only once the status is the wanted one; a wrong status
            // is the failure to report.
            let broken = if status_ok {
                p.spec.params.assert.broken(resp.headers())
            } else {
                Vec::new()
            };
            // The body is never read: dropping the response closes the connection.
            drop(resp);
            let ok = status_ok && broken.is_empty();
            let error_class = if !status_ok {
                Some(ErrorClass::Status)
            } else if ok {
                None
            } else {
                Some(ErrorClass::Answer)
            };
            CheckDetail {
                ok,
                latency_ms: elapsed_ms(started),
                status_code: Some(status),
                error_class,
                tls_expires_at: expires,
                reading: None,
                invariants: broken,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    const GOOD: &str = "HTTP/1.1 302 Found\r\nlocation: https://auth.example.com/login?next=1\r\nstrict-transport-security: max-age=63072000\r\nx-content-type-options: nosniff";
    const BAD: &str = "HTTP/1.1 302 Found\r\nlocation: https://evil.example.net/\r\nstrict-transport-security: max-age=0\r\nx-content-type-options: nosniff";
    const NONE: &str = "HTTP/1.1 200 OK";
    use crate::checks::{Assert, CheckSpec, InvariantStatus, Location};

    /// A server answering every request with `head` (status line and headers).
    async fn serve(head: &'static str) -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(
                            format!("{head}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                                .as_bytes(),
                        )
                        .await;
                });
            }
        });
        addr
    }

    async fn run(addr: std::net::SocketAddr, status: u16, assert: Assert) -> CheckDetail {
        let mut spec: CheckSpec = serde_json::from_value(serde_json::json!({
            "surface": "http",
            "target": {"url": format!("http://{addr}/room/")},
            "expect": {"status": status},
        }))
        .unwrap();
        spec.params.assert = assert;
        let endpoint = spec.endpoint().unwrap();
        let p = Prepared {
            spec: &spec,
            endpoint: &endpoint,
            addr,
            auth: None,
            timeout: Duration::from_secs(5),
        };
        check(&TlsContext::new(None).unwrap(), &p).await
    }

    fn rules() -> Assert {
        Assert {
            location: Some(Location::Prefix("https://auth.example.com/".into())),
            headers: vec![
                ("strict-transport-security".into(), "max-age=".into()),
                ("x-content-type-options".into(), String::new()),
            ],
        }
    }

    #[tokio::test]
    async fn a_redirect_and_headers_are_judged_and_a_failure_names_only_the_rule() {
        let d = run(serve(GOOD).await, 302, rules()).await;
        assert!(d.ok, "{d:?}");
        assert_eq!(d.status_code, Some(302));
        assert_eq!(d.invariants.len(), 0);

        // Redirected somewhere else, and the HSTS value is not what was asked.
        let mut a = rules();
        a.headers[0].1 = "max-age=6".into();
        let d = run(serve(BAD).await, 302, a).await;
        assert!(!d.ok);
        assert_eq!(d.error_class, Some(ErrorClass::Answer));
        let names: Vec<_> = d
            .invariants
            .iter()
            .map(|i| (i.name.as_str(), i.path.as_deref(), i.expected.as_deref()))
            .collect();
        assert_eq!(
            names,
            [
                ("location", Some("location"), Some("prefix")),
                ("header", Some("strict-transport-security"), Some("prefix")),
            ]
        );
        assert!(
            d.invariants
                .iter()
                .all(|i| i.status == InvariantStatus::Failed)
        );
        let text = serde_json::to_string(&d.invariants).unwrap();
        assert!(
            !text.contains("evil.example.net") && !text.contains("max-age"),
            "{text}"
        );

        // A header that is missing, and a redirect that was not sent at all.
        let d = run(
            serve(NONE).await,
            200,
            Assert {
                location: None,
                headers: rules().headers,
            },
        )
        .await;
        assert_eq!(d.invariants.len(), 2, "{d:?}");
        assert_eq!(d.error_class, Some(ErrorClass::Answer));

        // The wrong status is the failure to report, not the headers.
        let d = run(serve(GOOD).await, 301, rules()).await;
        assert_eq!(d.error_class, Some(ErrorClass::Status));
        assert_eq!(d.invariants.len(), 0);

        // Without rules the check is what it was.
        let d = run(serve(NONE).await, 200, Assert::default()).await;
        assert!(d.ok);
    }
}
