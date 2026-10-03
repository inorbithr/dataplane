use std::error::Error as _;
use std::time::Instant;

use reqwest::header::{HeaderName, HeaderValue};

use super::{CheckDetail, ErrorClass, Prepared, elapsed_ms, rfc3339};
use crate::tls::TlsContext;

pub(super) async fn check(tls: &TlsContext, p: &Prepared<'_>) -> CheckDetail {
    let started = Instant::now();
    let Some(url) = p.endpoint.url.clone() else {
        return CheckDetail::failed(ErrorClass::Connect, started);
    };
    let method = match p
        .spec
        .method
        .as_deref()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        None | Some("GET") => reqwest::Method::GET,
        Some("HEAD") => reqwest::Method::HEAD,
        Some(_) => return CheckDetail::failed(ErrorClass::Connect, started),
    };
    // A client per check: pinned to the address the policy approved, no redirects (a
    // redirect would be a second, unchecked target), no proxy, no connection reuse.
    let mut builder = tls
        .reqwest_builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(p.timeout)
        .connect_timeout(p.timeout)
        .pool_max_idle_per_host(0)
        .tls_info(true);
    if url.domain().is_some() {
        builder = builder.resolve(&p.endpoint.host, p.addr);
    }
    let Ok(client) = builder.build() else {
        return CheckDetail::failed(ErrorClass::Tls, started);
    };
    let mut req = client.request(method, url);
    if let Some((name, value)) = &p.auth {
        let (Ok(name), Ok(mut value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value.as_str()),
        ) else {
            return CheckDetail::failed(ErrorClass::Connect, started);
        };
        value.set_sensitive(true);
        req = req.header(name, value);
    }
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let expires = resp
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(reqwest::tls::TlsInfo::peer_certificate)
                .and_then(crate::x509::not_after)
                .and_then(rfc3339);
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
            }
        }
        Err(e) => CheckDetail::failed(classify(&e), started),
    }
}

fn classify(e: &reqwest::Error) -> ErrorClass {
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
