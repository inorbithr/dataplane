//! `mqtt`: MQTT 5 over WebSocket (subprotocol `mqtt`). CONNECT (clean start), SUBSCRIBE
//! to `reply/<client id>/<n>`, PUBLISH the call at `QoS` 1 to the check's `topic` with that
//! Response Topic and a random Correlation Data, then wait for the PUBLISH that answers
//! it. Healthy when the answer has no `error` user property, or, for a refusal check, when
//! that property equals `expect_error`. A refusal in a CONNACK, SUBACK or PUBACK is the
//! class `status`; its reason code is never reported, nor is any reason string or payload.
//!
//! The packets are hand-encoded: six packet types and the properties they carry do not
//! justify an MQTT stack (and the agent keeps no new dependency for them).

use std::time::{Duration, Instant};

use bytes::{Buf as _, BufMut as _, BytesMut};
use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use super::ws::{Socket, open};
use super::{CheckDetail, ErrorClass, Prepared, bounds, elapsed_ms};
use crate::tls::TlsContext;

const CONNECT: u8 = 1;
const CONNACK: u8 = 2;
const PUBLISH: u8 = 3;
const PUBACK: u8 = 4;
const SUBSCRIBE: u8 = 8;
const SUBACK: u8 = 9;
const DISCONNECT: u8 = 14;

/// The keep-alive asked for, seconds; a check is over long before.
const KEEP_ALIVE: u16 = 60;
const SUBSCRIBE_ID: u16 = 1;
const PUBLISH_ID: u16 = 2;

pub(super) async fn check(tls: &TlsContext, p: &Prepared<'_>) -> CheckDetail {
    let started = Instant::now();
    let (mut socket, expires) = match open(tls, p, Some("mqtt")).await {
        Ok(s) => s,
        Err((class, status)) => {
            let mut d = CheckDetail::failed(class, started);
            d.status_code = status;
            return d;
        }
    };
    let outcome = tokio::time::timeout(p.timeout, converse(&mut socket, p)).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        let _ = socket.send(Message::binary(vec![DISCONNECT << 4, 0])).await;
        let _ = socket.close(None).await;
    })
    .await;
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

async fn converse(socket: &mut Socket, p: &Prepared<'_>) -> Result<(), ErrorClass> {
    let Some(topic) = p.spec.params.topic.as_deref() else {
        return Err(ErrorClass::Connect);
    };
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| ErrorClass::Connect)?;
    let hex = nonce.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    let client_id = format!("iohr-agent-{hex}");
    let reply = format!("reply/{client_id}/check");
    let payload = match &p.spec.params.body {
        Some(v) => serde_json::to_vec(v).map_err(|_| ErrorClass::Connect)?,
        None => Vec::new(),
    };
    let mut reader = Reader::default();

    send(socket, &connect(&client_id)).await?;
    let ack = reader.expect(socket, CONNACK).await?;
    // Acknowledge flags, then the reason code.
    if ack.body.get(1).copied().unwrap_or(0xff) >= 0x80 {
        return Err(ErrorClass::Status);
    }
    send(socket, &subscribe(&reply)).await?;
    let ack = reader.expect(socket, SUBACK).await?;
    if suback_refused(&ack.body) {
        return Err(ErrorClass::Status);
    }
    send(socket, &publish(topic, &reply, &nonce, &payload)).await?;
    let expect_error = p.spec.params.expect_error.as_deref();
    for _ in 0..bounds::MAX_FRAMES {
        let packet = reader.next(socket).await?;
        match packet.kind {
            PUBACK => {
                if puback_refused(&packet.body) {
                    return Err(ErrorClass::Status);
                }
            }
            PUBLISH => {
                let answer = parse_publish(packet.flags, &packet.body).ok_or(ErrorClass::Answer)?;
                if let Some(id) = answer.packet_id {
                    send(socket, &puback(id)).await?;
                }
                if answer.topic != reply || answer.correlation.as_deref() != Some(&nonce[..]) {
                    continue;
                }
                return match (answer.error.as_deref(), expect_error) {
                    (None, None) => Ok(()),
                    (Some(code), Some(want)) if code == want => Ok(()),
                    _ => Err(ErrorClass::Answer),
                };
            }
            DISCONNECT => return Err(ErrorClass::Status),
            _ => {}
        }
    }
    Err(ErrorClass::Answer)
}

async fn send(socket: &mut Socket, packet: &[u8]) -> Result<(), ErrorClass> {
    socket
        .send(Message::binary(packet.to_vec()))
        .await
        .map_err(|_| ErrorClass::Connect)
}

/// One packet: its type, its flags and what follows the fixed header.
#[derive(Debug)]
struct Packet {
    kind: u8,
    flags: u8,
    body: Vec<u8>,
}

/// Packets out of WebSocket messages, which may split or join them.
#[derive(Debug, Default)]
struct Reader {
    buf: BytesMut,
    messages: usize,
}

impl Reader {
    async fn next(&mut self, socket: &mut Socket) -> Result<Packet, ErrorClass> {
        loop {
            if let Some(p) = take_packet(&mut self.buf)? {
                return Ok(p);
            }
            if self.messages >= bounds::MAX_FRAMES {
                return Err(ErrorClass::Answer);
            }
            self.messages += 1;
            match socket.next().await {
                // Closed, past the size bound, or a text frame (not MQTT).
                None
                | Some(Ok(Message::Close(_) | Message::Text(_)) | Err(WsError::Capacity(_))) => {
                    return Err(ErrorClass::Answer);
                }
                Some(Err(_)) => return Err(ErrorClass::Connect),
                Some(Ok(Message::Binary(b))) => {
                    if self.buf.len() + b.len() > bounds::MAX_ANSWER_BYTES {
                        return Err(ErrorClass::Answer);
                    }
                    self.buf.extend_from_slice(&b);
                }
                Some(Ok(_)) => {}
            }
        }
    }

    async fn expect(&mut self, socket: &mut Socket, kind: u8) -> Result<Packet, ErrorClass> {
        let p = self.next(socket).await?;
        match p.kind {
            k if k == kind => Ok(p),
            // Refused with a DISCONNECT, or something else first.
            DISCONNECT => Err(ErrorClass::Status),
            _ => Err(ErrorClass::Answer),
        }
    }
}

/// A whole packet off the front of `buf`, or `None` while it is incomplete.
fn take_packet(buf: &mut BytesMut) -> Result<Option<Packet>, ErrorClass> {
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    let mut len = 0usize;
    let mut at = 1;
    loop {
        let Some(&b) = buf.get(at) else {
            return Ok(None);
        };
        len |= usize::from(b & 0x7f) << (7 * (at - 1));
        at += 1;
        if b & 0x80 == 0 {
            break;
        }
        if at > 4 {
            return Err(ErrorClass::Answer);
        }
    }
    if len > bounds::MAX_ANSWER_BYTES {
        return Err(ErrorClass::Answer);
    }
    if buf.len() < at + len {
        return Ok(None);
    }
    buf.advance(at);
    let body = buf.split_to(len).to_vec();
    Ok(Some(Packet {
        kind: first >> 4,
        flags: first & 0x0f,
        body,
    }))
}

fn put_varint(out: &mut BytesMut, mut v: usize) {
    loop {
        let mut b = u8::try_from(v & 0x7f).unwrap_or(0);
        v >>= 7;
        if v > 0 {
            b |= 0x80;
        }
        out.put_u8(b);
        if v == 0 {
            break;
        }
    }
}

fn put_str(out: &mut BytesMut, s: &[u8]) {
    out.put_u16(u16::try_from(s.len()).unwrap_or(u16::MAX));
    out.put_slice(s);
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(body.len() + 5);
    out.put_u8(first);
    put_varint(&mut out, body.len());
    out.put_slice(body);
    out.to_vec()
}

/// CONNECT, MQTT 5, clean start, no will, no user name or password (the identity is the
/// WebSocket upgrade's credential).
fn connect(client_id: &str) -> Vec<u8> {
    let mut b = BytesMut::new();
    put_str(&mut b, b"MQTT");
    b.put_u8(5);
    b.put_u8(0x02);
    b.put_u16(KEEP_ALIVE);
    b.put_u8(0); // no properties
    put_str(&mut b, client_id.as_bytes());
    packet(CONNECT << 4, &b)
}

/// SUBSCRIBE to the reply topic at `QoS` 1.
fn subscribe(topic: &str) -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u16(SUBSCRIBE_ID);
    b.put_u8(0);
    put_str(&mut b, topic.as_bytes());
    b.put_u8(0x01);
    packet((SUBSCRIBE << 4) | 0x02, &b)
}

/// PUBLISH at `QoS` 1 with a Response Topic and Correlation Data.
fn publish(topic: &str, reply: &str, correlation: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut props = BytesMut::new();
    props.put_u8(0x08);
    put_str(&mut props, reply.as_bytes());
    props.put_u8(0x09);
    put_str(&mut props, correlation);
    if !payload.is_empty() {
        props.put_u8(0x01);
        props.put_u8(1);
    }
    let mut b = BytesMut::new();
    put_str(&mut b, topic.as_bytes());
    b.put_u16(PUBLISH_ID);
    put_varint(&mut b, props.len());
    b.put_slice(&props);
    b.put_slice(payload);
    packet((PUBLISH << 4) | 0x02, &b)
}

fn puback(id: u16) -> Vec<u8> {
    let mut b = BytesMut::new();
    b.put_u16(id);
    packet(PUBACK << 4, &b)
}

/// A SUBACK whose only reason code is a refusal (0x80 and up).
fn suback_refused(body: &[u8]) -> bool {
    let mut r = body;
    if r.len() < 2 {
        return true;
    }
    r = &r[2..];
    let Some((len, rest)) = read_varint(r) else {
        return true;
    };
    rest.get(len).is_none_or(|&code| code >= 0x80)
}

/// A PUBACK for our publish with a refusal reason code (absent means success).
fn puback_refused(body: &[u8]) -> bool {
    body.len() >= 3 && u16::from_be_bytes([body[0], body[1]]) == PUBLISH_ID && body[2] >= 0x80
}

fn read_varint(buf: &[u8]) -> Option<(usize, &[u8])> {
    let mut v = 0usize;
    for (i, &b) in buf.iter().enumerate().take(4) {
        v |= usize::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((v, &buf[i + 1..]));
        }
    }
    None
}

/// What the check reads of an incoming PUBLISH: never its payload.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    topic: String,
    packet_id: Option<u16>,
    correlation: Option<Vec<u8>>,
    /// The `error` user property's value: a code, compared, never reported.
    error: Option<String>,
}

fn parse_publish(flags: u8, body: &[u8]) -> Option<Answer> {
    let mut r = body;
    let topic = take_str(&mut r)?;
    let qos = (flags >> 1) & 0x03;
    let packet_id = if qos > 0 {
        let id = r.get(..2)?;
        let id = u16::from_be_bytes([id[0], id[1]]);
        r = &r[2..];
        Some(id)
    } else {
        None
    };
    let (len, rest) = read_varint(r)?;
    let mut props = rest.get(..len)?;
    let mut correlation = None;
    let mut error = None;
    while let Some((&id, rest)) = props.split_first() {
        props = rest;
        match id {
            0x01 | 0x17 | 0x19 | 0x24 | 0x25 | 0x28 | 0x29 | 0x2A => props = props.get(1..)?,
            0x13 | 0x21 | 0x22 | 0x23 => props = props.get(2..)?,
            0x02 | 0x11 | 0x18 | 0x27 => props = props.get(4..)?,
            0x0B => props = read_varint(props)?.1,
            0x09 => correlation = Some(take_bytes(&mut props)?.to_vec()),
            0x03 | 0x08 | 0x12 | 0x15 | 0x16 | 0x1A | 0x1C | 0x1F => {
                take_bytes(&mut props)?;
            }
            0x26 => {
                let k = take_str(&mut props)?;
                let v = take_str(&mut props)?;
                if k == "error" && error.is_none() {
                    error = Some(v);
                }
            }
            _ => return None,
        }
    }
    Some(Answer {
        topic,
        packet_id,
        correlation,
        error,
    })
}

fn take_bytes<'a>(r: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::from(u16::from_be_bytes([*r.first()?, *r.get(1)?]));
    let out = r.get(2..2 + len)?;
    *r = &r[2 + len..];
    Some(out)
}

fn take_str(r: &mut &[u8]) -> Option<String> {
    take_bytes(r).and_then(|b| String::from_utf8(b.to_vec()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_round_trip_through_the_reader() {
        let mut buf = BytesMut::new();
        let p = publish(
            "rpc/ledger/Ping",
            "reply/c/check",
            b"12345678",
            br#"{"a":1}"#,
        );
        // Split across two messages.
        buf.extend_from_slice(&p[..3]);
        assert!(take_packet(&mut buf).unwrap().is_none());
        buf.extend_from_slice(&p[3..]);
        buf.extend_from_slice(&puback(PUBLISH_ID));
        let first = take_packet(&mut buf).unwrap().unwrap();
        assert_eq!((first.kind, first.flags), (PUBLISH, 0x02));
        let a = parse_publish(first.flags, &first.body).unwrap();
        assert_eq!(a.topic, "rpc/ledger/Ping");
        assert_eq!(a.packet_id, Some(PUBLISH_ID));
        assert_eq!(a.correlation.as_deref(), Some(&b"12345678"[..]));
        assert_eq!(a.error, None);
        let second = take_packet(&mut buf).unwrap().unwrap();
        assert_eq!(second.kind, PUBACK);
        assert!(!puback_refused(&second.body));
        assert!(buf.is_empty());
    }

    #[test]
    fn an_error_property_and_refusals_are_read_as_codes() {
        // PUBLISH `QoS` 0 to "r" with a user property error=forbidden and a content type.
        let mut props = BytesMut::new();
        props.put_u8(0x03);
        put_str(&mut props, b"application/json");
        props.put_u8(0x26);
        put_str(&mut props, b"error");
        put_str(&mut props, b"forbidden");
        let mut b = BytesMut::new();
        put_str(&mut b, b"r");
        put_varint(&mut b, props.len());
        b.put_slice(&props);
        b.put_slice(b"{\"error\":\"canary text\"}");
        let a = parse_publish(0, &b).unwrap();
        assert_eq!(a.error.as_deref(), Some("forbidden"));
        assert_eq!(a.packet_id, None);
        assert!(puback_refused(&[0, 2, 0x87, 0]));
        assert!(!puback_refused(&[0, 2]));
        assert!(suback_refused(&[0, 1, 0, 0x8f]));
        assert!(!suback_refused(&[0, 1, 0, 0x01]));
        assert!(parse_publish(0, &[0, 5, b'a']).is_none(), "truncated");
    }

    #[test]
    fn connect_is_mqtt_5_clean_start() {
        let c = connect("iohr-agent-x");
        assert_eq!(c[0], 0x10);
        assert_eq!(&c[2..10], &[0, 4, b'M', b'Q', b'T', b'T', 5, 0x02]);
        let mut big = BytesMut::new();
        put_varint(&mut big, 321);
        assert_eq!(&big[..], &[0xC1, 0x02]);
        assert_eq!(read_varint(&big).unwrap().0, 321);
    }
}
