//! `ws`: one call on a multiplexed WebSocket (the `/v1/ws` frames: `call`, then `data`,
//! `end` or `error` with the call's id). Healthy when a `data` frame answers the call, or,
//! for a refusal check, when an `error` frame carries the code in `expect_error`. At most
//! [`bounds::MAX_FRAMES`] messages of at most [`bounds::MAX_ANSWER_BYTES`] are read; each
//! is parsed in memory and dropped. Only the frame's `type` and `code` are looked at.

use std::time::{Duration, Instant};

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::{CheckDetail, ErrorClass, Prepared, auth_header, bounds, elapsed_ms};
use crate::tls::TlsContext;

/// An open socket to the target.
pub(super) type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// The call's id: the check makes one call per socket.
const CALL_ID: &str = "1";

/// Opens a WebSocket to the check's URL (`http` becomes `ws`, `https` `wss`) at the
/// address the policy pinned, with the credential and the subprotocol, if any. On failure
/// the class and the upgrade's HTTP status.
pub(super) async fn open(
    tls: &TlsContext,
    p: &Prepared<'_>,
    subprotocol: Option<&'static str>,
) -> Result<(Socket, Option<String>), (ErrorClass, Option<u16>)> {
    let fail = |c| (c, None);
    let mut url = p.endpoint.url.clone().ok_or(fail(ErrorClass::Connect))?;
    let scheme = if p.endpoint.tls { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|()| fail(ErrorClass::Connect))?;
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|_| fail(ErrorClass::Connect))?;
    request.headers_mut().insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static(concat!("iohr-agent/", env!("CARGO_PKG_VERSION"))),
    );
    if let Some(proto) = subprotocol {
        request.headers_mut().insert(
            http::header::SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static(proto),
        );
    }
    if let Some((name, value)) = auth_header(p).map_err(fail)? {
        request.headers_mut().insert(name, value);
    }
    let (stream, expires) = if p.endpoint.tls {
        let (s, expires) =
            super::tls::connect(tls, &p.endpoint.host, p.addr, &[b"http/1.1"], p.timeout)
                .await
                .map_err(fail)?;
        (MaybeTlsStream::Rustls(s), expires)
    } else {
        match tokio::time::timeout(p.timeout, TcpStream::connect(p.addr)).await {
            Ok(Ok(s)) => (MaybeTlsStream::Plain(s), None),
            Ok(Err(_)) => return Err(fail(ErrorClass::Connect)),
            Err(_) => return Err(fail(ErrorClass::Timeout)),
        }
    };
    let config = WebSocketConfig::default()
        .max_message_size(Some(bounds::MAX_ANSWER_BYTES))
        .max_frame_size(Some(bounds::MAX_ANSWER_BYTES));
    let handshake = tokio_tungstenite::client_async_with_config(request, stream, Some(config));
    match tokio::time::timeout(p.timeout, handshake).await {
        Err(_) => Err(fail(ErrorClass::Timeout)),
        // The upgrade was answered with a status: the status is the finding, its body is
        // never looked at.
        Ok(Err(WsError::Http(resp))) => Err((ErrorClass::Status, Some(resp.status().as_u16()))),
        Ok(Err(_)) => Err(fail(ErrorClass::Connect)),
        Ok(Ok((socket, resp))) => {
            if let Some(proto) = subprotocol
                && resp
                    .headers()
                    .get(http::header::SEC_WEBSOCKET_PROTOCOL)
                    .is_none_or(|v| v.as_bytes() != proto.as_bytes())
            {
                return Err((ErrorClass::Answer, Some(101)));
            }
            Ok((socket, expires))
        }
    }
}

pub(super) async fn check(tls: &TlsContext, p: &Prepared<'_>) -> CheckDetail {
    let started = Instant::now();
    let (mut socket, expires) = match open(tls, p, None).await {
        Ok(s) => s,
        Err((class, status)) => {
            let mut d = CheckDetail::failed(class, started);
            d.status_code = status;
            return d;
        }
    };
    let outcome = tokio::time::timeout(p.timeout, call(&mut socket, p)).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), socket.close(None)).await;
    let outcome = outcome.unwrap_or(Err(ErrorClass::Timeout));
    CheckDetail {
        ok: outcome.is_ok(),
        latency_ms: elapsed_ms(started),
        status_code: Some(101),
        error_class: outcome.err(),
        tls_expires_at: expires,
        reading: None,
    }
}

async fn call(socket: &mut Socket, p: &Prepared<'_>) -> Result<(), ErrorClass> {
    let Some(method) = p.spec.params.method.as_deref() else {
        return Err(ErrorClass::Connect);
    };
    let mut frame = json!({"type": "call", "id": CALL_ID, "method": method});
    if let Some(body) = &p.spec.params.body {
        frame["body"] = body.clone();
    }
    socket
        .send(Message::text(frame.to_string()))
        .await
        .map_err(|_| ErrorClass::Connect)?;
    for _ in 0..bounds::MAX_FRAMES {
        let msg = match socket.next().await {
            None | Some(Err(WsError::Capacity(_))) => return Err(ErrorClass::Answer),
            Some(Err(_)) => return Err(ErrorClass::Connect),
            Some(Ok(m)) => m,
        };
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => return Err(ErrorClass::Answer),
            // Pings are answered by the library; binary frames are not this protocol's.
            _ => continue,
        };
        if let Some(r) = judge(text.as_str(), p.spec.params.expect_error.as_deref()) {
            return r;
        }
    }
    Err(ErrorClass::Answer)
}

/// What one frame says about the call: `None` when it is not about the call.
fn judge(text: &str, expect_error: Option<&str>) -> Option<Result<(), ErrorClass>> {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Some(Err(ErrorClass::Answer));
    };
    let id = v.get("id").and_then(Value::as_str);
    let kind = v.get("type").and_then(Value::as_str);
    match (kind, id) {
        (Some("data"), Some(CALL_ID)) if expect_error.is_none() => Some(Ok(())),
        // Data for a refusal check, an end before any data, or an error about the frame
        // itself (no id: the call never started).
        (Some("data" | "end"), Some(CALL_ID)) | (Some("error"), None) => {
            Some(Err(ErrorClass::Answer))
        }
        (Some("error"), Some(CALL_ID)) => {
            let code = v.get("code").and_then(Value::as_str);
            Some(match expect_error {
                Some(want) if code == Some(want) => Ok(()),
                _ => Err(ErrorClass::Answer),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_judged_by_type_id_and_code_only() {
        assert_eq!(
            judge(r#"{"type":"data","id":"1","body":{}}"#, None),
            Some(Ok(()))
        );
        assert_eq!(judge(r#"{"type":"data","id":"2","body":{}}"#, None), None);
        assert_eq!(
            judge(r#"{"type":"end","id":"1"}"#, None),
            Some(Err(ErrorClass::Answer))
        );
        assert_eq!(
            judge(
                r#"{"type":"error","id":"1","code":"forbidden","error":"x"}"#,
                None
            ),
            Some(Err(ErrorClass::Answer))
        );
        assert_eq!(
            judge(
                r#"{"type":"error","id":"1","code":"forbidden"}"#,
                Some("forbidden")
            ),
            Some(Ok(()))
        );
        assert_eq!(
            judge(r#"{"type":"data","id":"1","body":{}}"#, Some("forbidden")),
            Some(Err(ErrorClass::Answer))
        );
        assert_eq!(
            judge(r#"{"type":"error","code":"bad_request"}"#, None),
            Some(Err(ErrorClass::Answer))
        );
        assert_eq!(judge("not json", None), Some(Err(ErrorClass::Answer)));
    }
}
