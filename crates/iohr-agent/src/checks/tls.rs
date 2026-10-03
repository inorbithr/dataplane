use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::{CheckDetail, ErrorClass, elapsed_ms, rfc3339};
use crate::tls::TlsContext;

/// Connects and completes a TLS handshake; on failure, the class of error.
pub(super) async fn connect(
    tls: &TlsContext,
    host: &str,
    addr: SocketAddr,
    alpn: &[&[u8]],
    timeout: Duration,
) -> Result<(TlsStream<TcpStream>, Option<String>), ErrorClass> {
    let name = ServerName::try_from(
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
    )
    .map_err(|_| ErrorClass::Tls)?;
    let tcp = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(ErrorClass::Connect),
        Err(_) => return Err(ErrorClass::Timeout),
    };
    let connector = TlsConnector::from(Arc::new(tls.client_config(alpn)));
    let stream = match tokio::time::timeout(timeout, connector.connect(name, tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(ErrorClass::Tls),
        Err(_) => return Err(ErrorClass::Timeout),
    };
    let expires = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(|leaf| crate::x509::not_after(leaf.as_ref()))
        .and_then(rfc3339);
    Ok((stream, expires))
}

pub(super) async fn check(
    tls: &TlsContext,
    host: &str,
    addr: SocketAddr,
    timeout: Duration,
) -> CheckDetail {
    let started = Instant::now();
    match connect(tls, host, addr, &[], timeout).await {
        Ok((_stream, expires)) => CheckDetail {
            ok: true,
            latency_ms: elapsed_ms(started),
            tls_expires_at: expires,
            ..CheckDetail::default()
        },
        Err(class) => CheckDetail::failed(class, started),
    }
}
