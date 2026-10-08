//! `sse`: `GET` with `Accept: text/event-stream`, then events counted until the check has
//! the number it wants (default 1) or its time runs out. An event is counted when a blank
//! line ends a block that had a `data` field; comments (`:` keep-alives) are not events.
//! What the events say is never kept: each line is looked at and dropped.

use std::time::Instant;

use super::http::{classify, client, expiry, with_auth};
use super::{CheckDetail, ErrorClass, Prepared, bounds, elapsed_ms, status_ok};
use crate::tls::TlsContext;

pub(super) async fn check(tls: &TlsContext, p: &Prepared<'_>) -> CheckDetail {
    let started = Instant::now();
    let Some(url) = p.endpoint.url.clone() else {
        return CheckDetail::failed(ErrorClass::Connect, started);
    };
    let want = p.spec.params.events.unwrap_or(1).min(bounds::MAX_EVENTS);
    let client = match client(tls, p) {
        Ok(c) => c,
        Err(class) => return CheckDetail::failed(class, started),
    };
    let req = client
        .get(url)
        .header("accept", "text/event-stream")
        .header("cache-control", "no-cache");
    let req = match with_auth(req, p) {
        Ok(r) => r,
        Err(class) => return CheckDetail::failed(class, started),
    };
    let mut resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return CheckDetail::failed(classify(&e), started),
    };
    let status = resp.status().as_u16();
    let expires = expiry(&resp);
    let mut detail = CheckDetail {
        ok: false,
        latency_ms: 0,
        status_code: Some(status),
        error_class: None,
        tls_expires_at: expires,
        reading: None,
    };
    let is_stream = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim_start().starts_with("text/event-stream"));
    let outcome = if !status_ok(&p.spec.expect, status) {
        Err(ErrorClass::Status)
    } else if !is_stream {
        Err(ErrorClass::Answer)
    } else {
        let mut counter = Counter::default();
        let mut read = 0usize;
        loop {
            if counter.events >= want {
                break Ok(());
            }
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    read += chunk.len();
                    if read > bounds::MAX_ANSWER_BYTES {
                        break Err(ErrorClass::Answer);
                    }
                    counter.feed(&chunk);
                }
                // The stream ended before enough events.
                Ok(None) => break Err(ErrorClass::Answer),
                Err(e) => break Err(classify(&e)),
            }
        }
    };
    drop(resp);
    detail.ok = outcome.is_ok();
    detail.error_class = outcome.err();
    detail.latency_ms = elapsed_ms(started);
    detail
}

/// Counts events in a byte stream without keeping them (beyond one partial line).
#[derive(Debug, Default)]
struct Counter {
    events: u32,
    /// The current line, up to its end; bounded by the answer's bound.
    line: Vec<u8>,
    /// The block so far had a `data` field.
    has_data: bool,
}

impl Counter {
    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            match b {
                b'\n' => self.end_line(),
                b'\r' => {}
                _ => self.line.push(b),
            }
        }
    }

    fn end_line(&mut self) {
        if self.line.is_empty() {
            if self.has_data {
                self.events = self.events.saturating_add(1);
            }
            self.has_data = false;
        } else if self.line.starts_with(b"data") {
            let rest = &self.line[4..];
            if rest.is_empty() || rest[0] == b':' {
                self.has_data = true;
            }
        }
        self.line.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_events_not_comments() {
        let mut c = Counter::default();
        c.feed(b": keep-alive\n\nevent: x\ndata: {\"a\":1}\n\ndata");
        assert_eq!(c.events, 1);
        c.feed(b": more\n\n");
        assert_eq!(c.events, 2, "a bare data field is an event");
        c.feed(b"id: 3\r\n\r\n");
        assert_eq!(c.events, 2, "a block without data is no event");
        c.feed(b"data: a\r\ndata: b\r\n\r\n");
        assert_eq!(c.events, 3);
        c.feed(b"dataset: x\n\n");
        assert_eq!(
            c.events, 3,
            "a field that only starts with data is not data"
        );
    }
}
