//! `grpc.health.v1.Health/Check` over HTTP/2, hand-encoded: the request is one string
//! field and the response one enum, which does not justify a protobuf stack.

use std::time::{Duration, Instant};

use bytes::{BufMut as _, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::{CheckDetail, ErrorClass, Prepared, elapsed_ms};
use crate::tls::TlsContext;

/// `ServingStatus.SERVING`.
const SERVING: u64 = 1;
/// The largest response accepted.
const MAX_RESPONSE: usize = 64 * 1024;

pub(super) async fn check(tls: &TlsContext, p: &Prepared<'_>) -> CheckDetail {
    let started = Instant::now();
    let service = p.spec.service.as_deref().unwrap_or("");
    let authority = if p.endpoint.port == if p.endpoint.tls { 443 } else { 80 } {
        p.endpoint.host.clone()
    } else {
        format!("{}:{}", p.endpoint.host, p.endpoint.port)
    };
    let auth = p.auth.as_ref().map(|(n, v)| (n.as_str(), v.as_str()));
    let outcome = if p.endpoint.tls {
        match super::tls::connect(tls, &p.endpoint.host, p.addr, &[b"h2"], p.timeout).await {
            Ok((stream, expires)) => call(stream, "https", &authority, service, auth, p.timeout)
                .await
                .map(|()| expires),
            Err(class) => Err(class),
        }
    } else {
        match tokio::time::timeout(p.timeout, TcpStream::connect(p.addr)).await {
            Ok(Ok(stream)) => call(stream, "http", &authority, service, auth, p.timeout)
                .await
                .map(|()| None),
            Ok(Err(_)) => Err(ErrorClass::Connect),
            Err(_) => Err(ErrorClass::Timeout),
        }
    };
    match outcome {
        Ok(expires) => CheckDetail {
            ok: true,
            latency_ms: elapsed_ms(started),
            tls_expires_at: expires,
            ..CheckDetail::default()
        },
        Err(class) => CheckDetail::failed(class, started),
    }
}

async fn call<S>(
    io: S,
    scheme: &str,
    authority: &str,
    service: &str,
    auth: Option<(&str, &str)>,
    timeout: Duration,
) -> Result<(), ErrorClass>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let fut = async {
        let (client, conn) = h2::client::handshake(io)
            .await
            .map_err(|_| ErrorClass::Connect)?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let result = request(client, scheme, authority, service, auth).await;
        driver.abort();
        result
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| ErrorClass::Timeout)?
}

async fn request(
    client: h2::client::SendRequest<Bytes>,
    scheme: &str,
    authority: &str,
    service: &str,
    auth: Option<(&str, &str)>,
) -> Result<(), ErrorClass> {
    let mut client = client.ready().await.map_err(|_| ErrorClass::Connect)?;
    let mut req = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!(
            "{scheme}://{authority}/grpc.health.v1.Health/Check"
        ))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header(
            "user-agent",
            concat!("iohr-agent/", env!("CARGO_PKG_VERSION")),
        );
    if let Some((name, value)) = auth {
        let mut v = http::HeaderValue::from_str(value).map_err(|_| ErrorClass::Connect)?;
        v.set_sensitive(true);
        req = req.header(name, v);
    }
    let req = req.body(()).map_err(|_| ErrorClass::Connect)?;
    let (response, mut send) = client
        .send_request(req, false)
        .map_err(|_| ErrorClass::Connect)?;
    send.send_data(encode_request(service), true)
        .map_err(|_| ErrorClass::Connect)?;
    let response = response.await.map_err(|_| ErrorClass::Connect)?;
    if response.status() != http::StatusCode::OK {
        return Err(ErrorClass::Status);
    }
    // A trailers-only response carries grpc-status in the headers.
    if let Some(s) = response.headers().get("grpc-status")
        && s.as_bytes() != b"0"
    {
        return Err(ErrorClass::Status);
    }
    let mut body = response.into_body();
    let mut buf = BytesMut::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|_| ErrorClass::Connect)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        if buf.len() + chunk.len() > MAX_RESPONSE {
            return Err(ErrorClass::Status);
        }
        buf.extend_from_slice(&chunk);
    }
    if let Ok(Some(trailers)) = body.trailers().await
        && trailers
            .get("grpc-status")
            .is_some_and(|s| s.as_bytes() != b"0")
    {
        return Err(ErrorClass::Status);
    }
    match decode_status(&buf) {
        Some(SERVING) => Ok(()),
        _ => Err(ErrorClass::Status),
    }
}

/// A length-prefixed `HealthCheckRequest { string service = 1; }`.
fn encode_request(service: &str) -> Bytes {
    let mut msg = BytesMut::new();
    if !service.is_empty() {
        msg.put_u8(0x0a);
        put_varint(&mut msg, service.len() as u64);
        msg.put_slice(service.as_bytes());
    }
    let mut out = BytesMut::with_capacity(5 + msg.len());
    out.put_u8(0);
    out.put_u32(u32::try_from(msg.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(&msg);
    out.freeze()
}

/// The `status` field of a length-prefixed `HealthCheckResponse`.
fn decode_status(frame: &[u8]) -> Option<u64> {
    let (&flag, rest) = frame.split_first()?;
    if flag != 0 {
        return None;
    }
    let (len, rest) = rest.split_at_checked(4)?;
    let len = usize::try_from(u32::from_be_bytes(len.try_into().ok()?)).ok()?;
    let mut msg = rest.get(..len)?;
    let mut status = 0;
    while let Some((&tag, rest)) = msg.split_first() {
        let (value, rest) = read_varint(rest)?;
        match (tag >> 3, tag & 7) {
            (1, 0) => {
                status = value;
                msg = rest;
            }
            (_, 0) => msg = rest,
            (_, 2) => msg = rest.get(usize::try_from(value).ok()?..)?,
            _ => return None,
        }
    }
    Some(status)
}

fn put_varint(buf: &mut BytesMut, mut v: u64) {
    while v >= 0x80 {
        buf.put_u8(u8::try_from(v & 0x7f).unwrap_or(0) | 0x80);
        v >>= 7;
    }
    buf.put_u8(u8::try_from(v).unwrap_or(0));
}

fn read_varint(mut buf: &[u8]) -> Option<(u64, &[u8])> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let (&b, rest) = buf.split_first()?;
        buf = rest;
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((v, buf));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes() {
        assert_eq!(&encode_request("")[..], &[0, 0, 0, 0, 0]);
        assert_eq!(&encode_request("a")[..], &[0, 0, 0, 0, 3, 0x0a, 1, b'a']);
        assert_eq!(decode_status(&[0, 0, 0, 0, 2, 0x08, 1]), Some(1));
        assert_eq!(decode_status(&[0, 0, 0, 0, 2, 0x08, 2]), Some(2));
        assert_eq!(decode_status(&[0, 0, 0, 0, 0]), Some(0));
        assert_eq!(decode_status(&[1, 0, 0, 0, 0]), None);
        assert_eq!(decode_status(&[0, 0, 0, 0, 9, 0x08]), None);
    }

    /// A minimal health server on h2c, answering `status` for every call.
    async fn serve(status: u8) -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut conn = h2::server::handshake(sock).await.unwrap();
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        assert_eq!(req.uri().path(), "/grpc.health.v1.Health/Check");
                        let resp = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(resp, false).unwrap();
                        send.send_data(Bytes::from(vec![0, 0, 0, 0, 2, 0x08, status]), false)
                            .unwrap();
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        send.send_trailers(trailers).unwrap();
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn serving_and_not_serving() {
        for (status, ok) in [(1u8, true), (2u8, false)] {
            let addr = serve(status).await;
            let r = call(
                TcpStream::connect(addr).await.unwrap(),
                "http",
                "localhost",
                "",
                None,
                Duration::from_secs(5),
            )
            .await;
            assert_eq!(r.is_ok(), ok, "{r:?}");
        }
    }
}
