use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::{CheckDetail, ErrorClass, elapsed_ms};

pub(super) async fn check(addr: SocketAddr, timeout: Duration) -> CheckDetail {
    let started = Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => CheckDetail {
            ok: true,
            latency_ms: elapsed_ms(started),
            ..CheckDetail::default()
        },
        Ok(Err(_)) => CheckDetail::failed(ErrorClass::Connect, started),
        Err(_) => CheckDetail::failed(ErrorClass::Timeout, started),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_and_closed_ports() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = l.local_addr().unwrap();
        let d = check(open, Duration::from_secs(2)).await;
        assert!(d.ok, "{d:?}");
        drop(l);
        let d = check(open, Duration::from_secs(2)).await;
        assert_eq!(d.error_class, Some(ErrorClass::Connect));
    }
}
