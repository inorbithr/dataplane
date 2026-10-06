//! Layer 7: request timing (`docs/capture/design-phase2.md`, "Layer 7").
//!
//! A [`Tracker`] follows one TCP flow. With timing on, the kernel copies the first 512
//! payload bytes of every TCP segment; the tracker follows each direction's sequence
//! numbers, and a gap (a copy lost or reordered) ends timing for the flow, so a lost copy
//! can never pair a request with the wrong response.
//!
//! - HTTP/1: a client segment that starts with a method is a request, a server segment
//!   that starts with `HTTP/1.x NNN` a response; responses pair with the oldest waiting
//!   request.
//! - HTTP/2 (h2c, gRPC): frames are followed across segments by their lengths; a client
//!   HEADERS frame on stream N is the request, the first server HEADERS frame on N the
//!   response, and `grpc-status` in a later (or trailers-only) block the gRPC status. No
//!   HPACK dynamic table is kept across blocks: the connection's first block decodes in
//!   full (its table starts empty), a later block only when it decodes on its own.
//!
//! Latency is the time between the kernel timestamps of the request's first copied byte
//! and the response's first copied byte. Every structure is bounded.

use std::collections::{HashMap, VecDeque};

use crate::proto::{hpack, http2::PREFACE};
use crate::route;

/// Requests waiting for a response on one HTTP/1 flow.
const MAX_WAITING: usize = 16;
/// Streams waiting on one HTTP/2 flow.
const MAX_STREAMS: usize = 64;
/// Largest header block kept from HEADERS and CONTINUATION frames.
const MAX_BLOCK: usize = 4096;
/// Most keys (method, route, owner) aggregated.
pub(crate) const MAX_KEYS: usize = 2048;

/// Latency histogram upper bounds, milliseconds; one more bucket above the last.
pub(crate) const BOUNDS_MS: [f64; 14] = [
    0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
];
/// Buckets: one per bound plus the overflow.
pub(crate) const BUCKETS: usize = BOUNDS_MS.len() + 1;

const METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// What a flow produced, for the aggregates (the engine adds the owner).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A request was answered.
    Response {
        method: String,
        route: String,
        /// HTTP status, when the response showed it.
        status: Option<u16>,
        latency_ns: u64,
    },
    /// A gRPC call's status from its trailers.
    Grpc {
        method: String,
        route: String,
        code: u32,
    },
    /// The flow ended (or the stream was reset) before a response.
    Unanswered { method: String, route: String },
    /// Dropped without an answer because the flow lost sync or a bound was hit.
    Abandoned { method: String, route: String },
}

/// One segment as the tracker needs it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Segment<'a> {
    pub(crate) ts_ns: u64,
    pub(crate) from_client: bool,
    pub(crate) seq: u32,
    pub(crate) syn: bool,
    pub(crate) fin: bool,
    /// The copied prefix of the payload.
    pub(crate) payload: &'a [u8],
    /// The payload's full length.
    pub(crate) payload_len: usize,
}

#[derive(Debug, Clone)]
struct Pending {
    ts_ns: u64,
    method: String,
    route: String,
}

#[derive(Debug)]
enum Proto {
    /// Waiting for the client's first payload.
    Unknown,
    Http1(VecDeque<Pending>),
    Http2(Box<H2>),
    /// Not HTTP, out of sync, or upgraded: nothing more to time.
    Off,
}

/// Per-flow timing state.
#[derive(Debug)]
pub(crate) struct Tracker {
    proto: Proto,
    /// Next expected sequence number, `[client, server]`.
    next: [Option<u32>; 2],
    /// Set once the flow lost sync (counted once).
    pub(crate) unsynced: bool,
}

impl Default for Tracker {
    fn default() -> Self {
        Self {
            proto: Proto::Unknown,
            next: [None, None],
            unsynced: false,
        }
    }
}

impl Tracker {
    /// Whether this flow is still being timed.
    pub(crate) fn active(&self) -> bool {
        !matches!(self.proto, Proto::Off)
    }

    /// One segment of the flow; outcomes are appended to `out`.
    pub(crate) fn segment(&mut self, s: &Segment<'_>, out: &mut Vec<Outcome>) {
        if matches!(self.proto, Proto::Off) {
            return;
        }
        let side = usize::from(!s.from_client);
        let len = u32::try_from(s.payload_len).unwrap_or(u32::MAX);
        if s.syn {
            // The SYN takes one sequence number; data starts after it.
            self.next[side] = Some(s.seq.wrapping_add(1).wrapping_add(len));
            return;
        }
        if s.payload_len == 0 {
            return;
        }
        if let Some(expected) = self.next[side] {
            let diff = s.seq.wrapping_sub(expected).cast_signed();
            if diff < 0 {
                // A retransmission of bytes already seen.
                let end = s.seq.wrapping_add(len);
                if end.wrapping_sub(expected).cast_signed() > 0 {
                    self.next[side] = Some(end);
                }
                return;
            }
            if diff > 0 {
                self.lose(out);
                return;
            }
        }
        self.next[side] = Some(s.seq.wrapping_add(len).wrapping_add(u32::from(s.fin)));
        match &mut self.proto {
            Proto::Unknown => {
                if !s.from_client {
                    return;
                }
                if s.payload.starts_with(PREFACE)
                    || (s.payload.len() < PREFACE.len()
                        && PREFACE.starts_with(s.payload)
                        && s.payload.len() == s.payload_len)
                {
                    let mut h2 = Box::<H2>::default();
                    h2.feed(s, out);
                    let lost = h2.lost;
                    self.proto = Proto::Http2(h2);
                    if lost {
                        self.lose(out);
                    }
                } else if request_method(s.payload).is_some() {
                    let mut q = VecDeque::new();
                    h1_segment(&mut q, s, out);
                    self.proto = Proto::Http1(q);
                } else {
                    self.proto = Proto::Off;
                }
            }
            Proto::Http1(q) => {
                if h1_segment(q, s, out) == H1::Upgraded {
                    self.proto = Proto::Off;
                }
            }
            Proto::Http2(h2) => {
                h2.feed(s, out);
                if h2.lost {
                    self.lose(out);
                }
            }
            Proto::Off => {}
        }
    }

    fn lose(&mut self, out: &mut Vec<Outcome>) {
        self.unsynced = true;
        self.drain(out, false);
        self.proto = Proto::Off;
    }

    /// Requests still waiting: `Unanswered` when the flow ended, else `Abandoned`.
    fn drain(&mut self, out: &mut Vec<Outcome>, ended: bool) {
        let mk = |p: Pending| {
            if ended {
                Outcome::Unanswered {
                    method: p.method,
                    route: p.route,
                }
            } else {
                Outcome::Abandoned {
                    method: p.method,
                    route: p.route,
                }
            }
        };
        match &mut self.proto {
            Proto::Http1(q) => out.extend(q.drain(..).map(mk)),
            Proto::Http2(h2) => {
                let mut ids: Vec<u32> = h2.streams.keys().copied().collect();
                ids.sort_unstable();
                for id in ids {
                    if let Some(st) = h2.streams.remove(&id)
                        && !st.responded
                    {
                        out.push(mk(st.pending));
                    }
                }
            }
            Proto::Unknown | Proto::Off => {}
        }
    }

    /// The flow ended (closed, evicted or expired).
    pub(crate) fn finish(&mut self, out: &mut Vec<Outcome>) {
        self.drain(out, true);
        self.proto = Proto::Off;
    }
}

fn request_method(b: &[u8]) -> Option<&'static str> {
    METHODS
        .iter()
        .copied()
        .find(|m| b.len() > m.len() && b.starts_with(m.as_bytes()) && b.get(m.len()) == Some(&b' '))
}

#[derive(Debug, PartialEq, Eq)]
enum H1 {
    Go,
    Upgraded,
}

fn h1_segment(q: &mut VecDeque<Pending>, s: &Segment<'_>, out: &mut Vec<Outcome>) -> H1 {
    if s.from_client {
        let Some(method) = request_method(s.payload) else {
            return H1::Go; // a body segment
        };
        let rest = s.payload.get(method.len() + 1..).unwrap_or_default();
        let route = match rest.iter().position(|b| *b == b' ' || *b == b'\r') {
            Some(end) => route::template(&String::from_utf8_lossy(
                rest.get(..end).unwrap_or_default(),
            )),
            None => "unknown".to_owned(),
        };
        if q.len() >= MAX_WAITING
            && let Some(old) = q.pop_front()
        {
            out.push(Outcome::Abandoned {
                method: old.method,
                route: old.route,
            });
        }
        q.push_back(Pending {
            ts_ns: s.ts_ns,
            method: method.to_owned(),
            route,
        });
        return H1::Go;
    }
    let Some(status) = response_status(s.payload) else {
        return H1::Go; // a body segment
    };
    if (100..200).contains(&status) && status != 101 {
        return H1::Go; // 100 Continue, 103 Early Hints: not the answer
    }
    if let Some(p) = q.pop_front() {
        out.push(Outcome::Response {
            method: p.method,
            route: p.route,
            status: Some(status),
            latency_ns: s.ts_ns.saturating_sub(p.ts_ns),
        });
    }
    if status == 101 { H1::Upgraded } else { H1::Go }
}

fn response_status(b: &[u8]) -> Option<u16> {
    if b.len() < 12 || !b.starts_with(b"HTTP/1.") || b.get(8) != Some(&b' ') {
        return None;
    }
    let code = b.get(9..12)?;
    if !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let status = code
        .iter()
        .fold(0u16, |acc, d| acc * 10 + u16::from(d - b'0'));
    (100..=599).contains(&status).then_some(status)
}

// ---------------------------------------------------------------- HTTP/2

const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_CONTINUATION: u8 = 0x9;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

#[derive(Debug, Clone)]
struct Stream {
    pending: Pending,
    responded: bool,
}

/// Where one direction's frame reader stands.
#[derive(Debug, Clone)]
enum Cursor {
    /// The client preface: bytes still expected.
    Preface(usize),
    /// Collecting a 9-byte frame header.
    Header { have: [u8; 9], n: usize },
    /// Inside a frame's payload.
    Payload {
        kind: u8,
        flags: u8,
        stream: u32,
        remaining: usize,
        /// The bytes kept (HEADERS and CONTINUATION only), `None` when skipped or a part
        /// was not copied.
        keep: Option<Vec<u8>>,
        ts_ns: u64,
    },
}

#[derive(Debug)]
struct Side {
    cursor: Cursor,
    /// A header block waiting for CONTINUATION: stream, `END_STREAM`, bytes, timestamp.
    block: Option<(u32, bool, Option<Vec<u8>>, u64)>,
}

#[derive(Debug)]
struct H2 {
    sides: [Side; 2],
    streams: HashMap<u32, Stream>,
    lost: bool,
}

impl Default for H2 {
    fn default() -> Self {
        Self {
            sides: [
                Side {
                    cursor: Cursor::Preface(PREFACE.len()),
                    block: None,
                },
                Side {
                    cursor: Cursor::Header { have: [0; 9], n: 0 },
                    block: None,
                },
            ],
            streams: HashMap::new(),
            lost: false,
        }
    }
}

/// A complete header block from one side.
struct Block {
    from_client: bool,
    stream: u32,
    end_stream: bool,
    /// `None` when part of it was not copied.
    bytes: Option<Vec<u8>>,
    ts_ns: u64,
}

impl H2 {
    fn feed(&mut self, s: &Segment<'_>, out: &mut Vec<Outcome>) {
        let side = usize::from(!s.from_client);
        let mut blocks = Vec::new();
        let mut resets = Vec::new();
        {
            let sd = &mut self.sides[side];
            let mut data = s.payload;
            let mut hole = s.payload_len.saturating_sub(s.payload.len());
            loop {
                if data.is_empty() && hole == 0 {
                    break;
                }
                match &mut sd.cursor {
                    Cursor::Preface(left) => {
                        let take = (*left).min(data.len());
                        let off = PREFACE.len() - *left;
                        if data.is_empty() || data.get(..take) != PREFACE.get(off..off + take) {
                            self.lost = true;
                            break;
                        }
                        data = data.get(take..).unwrap_or_default();
                        *left -= take;
                        if *left == 0 {
                            sd.cursor = Cursor::Header { have: [0; 9], n: 0 };
                        }
                    }
                    Cursor::Header { have, n } => {
                        if data.is_empty() {
                            // A frame header in bytes that were not copied.
                            self.lost = true;
                            break;
                        }
                        let take = (9 - *n).min(data.len());
                        have[*n..*n + take].copy_from_slice(data.get(..take).unwrap_or_default());
                        *n += take;
                        data = data.get(take..).unwrap_or_default();
                        if *n == 9 {
                            let h = *have;
                            let len = (usize::from(h[0]) << 16)
                                | (usize::from(h[1]) << 8)
                                | usize::from(h[2]);
                            let stream = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
                            let keep = matches!(h[3], FRAME_HEADERS | FRAME_CONTINUATION)
                                .then(|| Vec::with_capacity(len.min(MAX_BLOCK)));
                            sd.cursor = Cursor::Payload {
                                kind: h[3],
                                flags: h[4],
                                stream,
                                remaining: len,
                                keep,
                                ts_ns: s.ts_ns,
                            };
                            if len == 0 {
                                finish_frame(sd, s.from_client, &mut blocks, &mut resets);
                            }
                        }
                    }
                    Cursor::Payload {
                        remaining, keep, ..
                    } => {
                        if data.is_empty() {
                            // Skip by length through bytes that were not copied.
                            let take = (*remaining).min(hole);
                            hole -= take;
                            *remaining -= take;
                            *keep = None;
                        } else {
                            let take = (*remaining).min(data.len());
                            if let Some(k) = keep {
                                let room = MAX_BLOCK.saturating_sub(k.len());
                                k.extend_from_slice(data.get(..take.min(room)).unwrap_or_default());
                            }
                            data = data.get(take..).unwrap_or_default();
                            *remaining -= take;
                        }
                        if *remaining == 0 {
                            finish_frame(sd, s.from_client, &mut blocks, &mut resets);
                        }
                    }
                }
            }
        }
        for id in resets {
            if let Some(st) = self.streams.remove(&id)
                && !st.responded
            {
                out.push(Outcome::Unanswered {
                    method: st.pending.method,
                    route: st.pending.route,
                });
            }
        }
        for b in &blocks {
            self.block(b, out);
        }
    }

    fn block(&mut self, b: &Block, out: &mut Vec<Outcome>) {
        // Every block is decoded on its own, with an empty dynamic table: right for the
        // connection's first block, and for a later one only when it needs no earlier
        // entry (otherwise it does not decode, and its route is `unknown`).
        let fields = b
            .bytes
            .as_deref()
            .and_then(|bytes| hpack::decode(bytes).ok());
        if b.from_client {
            if b.stream.is_multiple_of(2) || self.streams.contains_key(&b.stream) {
                return; // trailers from the client, or not a request
            }
            let (mut method, mut route) = ("?".to_owned(), "unknown".to_owned());
            if let Some(f) = &fields {
                for (name, value) in f {
                    match name.as_str() {
                        ":method"
                            if !value.is_empty()
                                && value.len() <= 16
                                && value.bytes().all(|c| c.is_ascii_uppercase()) =>
                        {
                            method.clone_from(value);
                        }
                        ":path" => route = route::template(value),
                        _ => {}
                    }
                }
            }
            if self.streams.len() >= MAX_STREAMS {
                out.push(Outcome::Abandoned { method, route });
                return;
            }
            self.streams.insert(
                b.stream,
                Stream {
                    pending: Pending {
                        ts_ns: b.ts_ns,
                        method,
                        route,
                    },
                    responded: false,
                },
            );
            return;
        }
        let Some(st) = self.streams.get_mut(&b.stream) else {
            return;
        };
        let mut status = None;
        let mut grpc_status = None;
        if let Some(f) = &fields {
            for (name, value) in f {
                match name.as_str() {
                    ":status" => status = value.parse::<u16>().ok(),
                    "grpc-status" => grpc_status = value.parse::<u32>().ok().filter(|c| *c <= 16),
                    _ => {}
                }
            }
        }
        let informational = status.is_some_and(|c| (100..200).contains(&c));
        if !st.responded && !informational {
            st.responded = true;
            out.push(Outcome::Response {
                method: st.pending.method.clone(),
                route: st.pending.route.clone(),
                status,
                latency_ns: b.ts_ns.saturating_sub(st.pending.ts_ns),
            });
        }
        if let Some(code) = grpc_status {
            out.push(Outcome::Grpc {
                method: st.pending.method.clone(),
                route: st.pending.route.clone(),
                code,
            });
        }
        if b.end_stream {
            self.streams.remove(&b.stream);
        }
    }
}

/// A frame's payload is complete: emit a header block or a reset, then read the next
/// header.
fn finish_frame(sd: &mut Side, from_client: bool, blocks: &mut Vec<Block>, resets: &mut Vec<u32>) {
    let cursor = std::mem::replace(&mut sd.cursor, Cursor::Header { have: [0; 9], n: 0 });
    let Cursor::Payload {
        kind,
        flags,
        stream,
        keep,
        ts_ns,
        ..
    } = cursor
    else {
        return;
    };
    match kind {
        FRAME_HEADERS => {
            let frag = keep.and_then(|k| fragment(&k, flags).map(<[u8]>::to_vec));
            let end_stream = flags & FLAG_END_STREAM != 0;
            if flags & FLAG_END_HEADERS != 0 {
                blocks.push(Block {
                    from_client,
                    stream,
                    end_stream,
                    bytes: frag,
                    ts_ns,
                });
            } else {
                sd.block = Some((stream, end_stream, frag, ts_ns));
            }
        }
        FRAME_CONTINUATION => {
            if let Some((id, end_stream, mut bytes, ts)) = sd.block.take() {
                if id != stream {
                    return;
                }
                match (&mut bytes, keep) {
                    (Some(b), Some(k)) => {
                        let room = MAX_BLOCK.saturating_sub(b.len());
                        b.extend_from_slice(k.get(..room.min(k.len())).unwrap_or_default());
                    }
                    _ => bytes = None,
                }
                if flags & FLAG_END_HEADERS != 0 {
                    blocks.push(Block {
                        from_client,
                        stream: id,
                        end_stream,
                        bytes,
                        ts_ns: ts,
                    });
                } else {
                    sd.block = Some((id, end_stream, bytes, ts));
                }
            }
        }
        FRAME_RST_STREAM => resets.push(stream),
        _ => {}
    }
}

/// The header block fragment of a HEADERS frame, without padding and priority fields.
fn fragment(payload: &[u8], flags: u8) -> Option<&[u8]> {
    let mut start = 0;
    let mut end = payload.len();
    if flags & FLAG_PADDED != 0 {
        let pad = usize::from(*payload.first()?);
        start = 1;
        end = end.checked_sub(pad)?;
    }
    if flags & FLAG_PRIORITY != 0 {
        start += 5;
    }
    payload.get(start..end)
}

// ---------------------------------------------------------------- aggregates

/// Numbers for one (method, route, owner).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Stats {
    pub(crate) requests: u64,
    pub(crate) responses: u64,
    pub(crate) unanswered: u64,
    pub(crate) abandoned: u64,
    /// `1xx` to `5xx`, then responses whose status was not visible.
    pub(crate) status: [u64; 6],
    /// gRPC codes 0 to 16.
    pub(crate) grpc: [u64; 17],
    pub(crate) buckets: [u64; BUCKETS],
    pub(crate) latency_sum_us: u64,
}

impl Stats {
    fn add(&mut self, o: &Outcome) {
        match o {
            Outcome::Response {
                status, latency_ns, ..
            } => {
                self.requests += 1;
                self.responses += 1;
                let class = status.map_or(5, |s| usize::from(s / 100).clamp(1, 5) - 1);
                self.status[class] += 1;
                self.buckets[bucket(*latency_ns)] += 1;
                self.latency_sum_us = self.latency_sum_us.saturating_add(latency_ns / 1000);
            }
            Outcome::Grpc { code, .. } => {
                if let Some(slot) = self.grpc.get_mut(*code as usize) {
                    *slot += 1;
                }
            }
            Outcome::Unanswered { .. } => {
                self.requests += 1;
                self.unanswered += 1;
            }
            Outcome::Abandoned { .. } => {
                self.requests += 1;
                self.abandoned += 1;
            }
        }
    }

    /// The numbers as JSON (no names).
    pub(crate) fn to_json(&self) -> serde_json::Value {
        let grpc: serde_json::Map<String, serde_json::Value> = self
            .grpc
            .iter()
            .enumerate()
            .filter(|(_, n)| **n > 0)
            .map(|(c, n)| (c.to_string(), (*n).into()))
            .collect();
        #[allow(clippy::cast_precision_loss)]
        let sum_ms = self.latency_sum_us as f64 / 1000.0;
        serde_json::json!({
            "requests": self.requests,
            "responses": self.responses,
            "unanswered": self.unanswered,
            "abandoned": self.abandoned,
            "status_classes": {
                "1xx": self.status[0], "2xx": self.status[1], "3xx": self.status[2],
                "4xx": self.status[3], "5xx": self.status[4], "unknown": self.status[5],
            },
            "grpc_status": grpc,
            "latency_ms": {"le": BOUNDS_MS, "counts": self.buckets, "sum": sum_ms},
        })
    }
}

/// The bucket of a latency.
pub(crate) fn bucket(latency_ns: u64) -> usize {
    #[allow(clippy::cast_precision_loss)]
    let ms = latency_ns as f64 / 1e6;
    BOUNDS_MS
        .iter()
        .position(|b| ms <= *b)
        .unwrap_or(BOUNDS_MS.len())
}

/// Key: (owner, method, route template).
pub(crate) type Key = (String, String, String);

/// The aggregates over every flow, bounded by [`MAX_KEYS`].
#[derive(Debug, Default)]
pub(crate) struct Table {
    pub(crate) keys: HashMap<Key, Stats>,
    pub(crate) total: Stats,
    pub(crate) keys_dropped: u64,
    pub(crate) untracked: u64,
    pub(crate) unsynced: u64,
}

impl Table {
    pub(crate) fn add(&mut self, owner: &str, o: &Outcome) {
        self.total.add(o);
        let (Outcome::Response { method, route, .. }
        | Outcome::Grpc { method, route, .. }
        | Outcome::Unanswered { method, route }
        | Outcome::Abandoned { method, route }) = o;
        let key = (owner.to_owned(), method.clone(), route.clone());
        if let Some(s) = self.keys.get_mut(&key) {
            s.add(o);
        } else if self.keys.len() < MAX_KEYS {
            self.keys.entry(key).or_default().add(o);
        } else {
            if !matches!(o, Outcome::Grpc { .. }) {
                self.untracked += 1;
            }
            self.keys_dropped += 1;
        }
    }

    /// The stats for one owner and `METHOD template` route.
    pub(crate) fn lookup(&self, owner: &str, route: &str) -> Option<&Stats> {
        let (method, template) = route.split_once(' ')?;
        self.keys
            .get(&(owner.to_owned(), method.to_owned(), template.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(ts_ms: u64, from_client: bool, seq: u32, payload: &[u8]) -> Segment<'_> {
        Segment {
            ts_ns: ts_ms * 1_000_000,
            from_client,
            seq,
            syn: false,
            fin: false,
            payload,
            payload_len: payload.len(),
        }
    }

    fn feed(t: &mut Tracker, segs: &[Segment<'_>]) -> Vec<Outcome> {
        let mut out = Vec::new();
        for s in segs {
            t.segment(s, &mut out);
        }
        out
    }

    #[test]
    fn http1_keep_alive_pairs_in_order() {
        let mut t = Tracker::default();
        let r1 = b"GET /items/42?x=1 HTTP/1.1\r\nHost: a\r\n\r\n";
        let r2 = b"POST /orders HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let nf = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let mut syn = seg(0, true, 1000, b"");
        syn.syn = true;
        let mut syn_ack = seg(0, false, 5000, b"");
        syn_ack.syn = true;
        let c1 = 1001;
        let c2 = c1 + u32::try_from(r1.len()).unwrap();
        let s1 = 5001;
        let s2 = s1 + u32::try_from(ok.len()).unwrap();
        let out = feed(
            &mut t,
            &[
                syn,
                syn_ack,
                seg(10, true, c1, r1),
                seg(45, false, s1, ok),
                seg(50, true, c2, r2),
                seg(200, false, s2, nf),
            ],
        );
        assert_eq!(
            out,
            vec![
                Outcome::Response {
                    method: "GET".into(),
                    route: "/items/{id}".into(),
                    status: Some(200),
                    latency_ns: 35_000_000
                },
                Outcome::Response {
                    method: "POST".into(),
                    route: "/orders".into(),
                    status: Some(404),
                    latency_ns: 150_000_000
                },
            ]
        );
        let mut table = Table::default();
        for o in &out {
            table.add("cgroup:/web", o);
        }
        let s = table.lookup("cgroup:/web", "GET /items/{id}").unwrap();
        assert_eq!((s.requests, s.responses, s.status[1]), (1, 1, 1));
        assert_eq!(s.buckets[bucket(35_000_000)], 1);
        assert_eq!(bucket(35_000_000), 6, "25 < 35 <= 50 ms");
        assert!(table.lookup("cgroup:/web", "GET /nope").is_none());
        assert!(table.lookup("other", "GET /items/{id}").is_none());
    }

    #[test]
    fn a_gap_stops_timing_and_never_mispairs() {
        let mut t = Tracker::default();
        let r = b"GET /a HTTP/1.1\r\n\r\n";
        let ok = b"HTTP/1.1 200 OK\r\n\r\n";
        let rl = u32::try_from(r.len()).unwrap();
        let out = feed(
            &mut t,
            &[
                seg(0, true, 1, r),
                // The response to the first request was lost: the server's next segment
                // starts later than expected after its first.
                seg(1, false, 100, ok),
                seg(2, true, 1 + rl, r),
                seg(3, false, 100 + 500, ok),
            ],
        );
        assert_eq!(
            out,
            vec![
                Outcome::Response {
                    method: "GET".into(),
                    route: "/a".into(),
                    status: Some(200),
                    latency_ns: 1_000_000
                },
                Outcome::Abandoned {
                    method: "GET".into(),
                    route: "/a".into()
                },
            ]
        );
        assert!(t.unsynced && !t.active());
    }

    #[test]
    fn retransmissions_are_ignored_and_100_continue_skipped() {
        let mut t = Tracker::default();
        let r = b"PUT /f HTTP/1.1\r\nExpect: 100-continue\r\n\r\n";
        let cont = b"HTTP/1.1 100 Continue\r\n\r\n";
        let ok = b"HTTP/1.1 201 Created\r\n\r\n";
        let cl = u32::try_from(cont.len()).unwrap();
        let out = feed(
            &mut t,
            &[
                seg(0, true, 1, r),
                seg(0, true, 1, r),
                seg(5, false, 1, cont),
                seg(9, false, 1 + cl, ok),
            ],
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(matches!(
            &out[0],
            Outcome::Response {
                status: Some(201),
                latency_ns: 9_000_000,
                ..
            }
        ));
    }

    #[test]
    fn unanswered_at_the_end_and_not_http() {
        let mut t = Tracker::default();
        let mut out = feed(&mut t, &[seg(0, true, 1, b"DELETE /x/1 HTTP/1.1\r\n\r\n")]);
        t.finish(&mut out);
        assert_eq!(
            out,
            vec![Outcome::Unanswered {
                method: "DELETE".into(),
                route: "/x/{id}".into()
            }]
        );
        let mut tls = Tracker::default();
        assert_eq!(
            feed(&mut tls, &[seg(0, true, 1, b"\x16\x03\x01\x02\x00")]),
            vec![]
        );
        assert!(!tls.active());
    }

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let len = u32::try_from(payload.len()).unwrap();
        let mut f = len.to_be_bytes()[1..].to_vec();
        f.push(kind);
        f.push(flags);
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// A literal header field without indexing, new name (RFC 7541 6.2.2).
    fn lit(name: &str, value: &str) -> Vec<u8> {
        let mut b = vec![0x00, u8::try_from(name.len()).unwrap()];
        b.extend_from_slice(name.as_bytes());
        b.push(u8::try_from(value.len()).unwrap());
        b.extend_from_slice(value.as_bytes());
        b
    }

    #[test]
    fn grpc_over_h2c_with_trailers_and_split_frames() {
        let mut t = Tracker::default();
        // Request: preface, SETTINGS, HEADERS (POST, :path, content-type), DATA.
        let mut req_block = vec![0x83]; // :method POST
        req_block.extend(lit(":path", "/e2e.Echo/Say"));
        req_block.extend(lit("content-type", "application/grpc"));
        let mut c = PREFACE.to_vec();
        c.extend(frame(4, 0, 0, b""));
        c.extend(frame(1, FLAG_END_HEADERS, 1, &req_block));
        c.extend(frame(0, FLAG_END_STREAM, 1, b"\0\0\0\0\0"));
        // Response: SETTINGS, HEADERS :status 200, DATA, trailers grpc-status 5.
        let mut s = frame(4, 0, 0, b"");
        s.extend(frame(1, FLAG_END_HEADERS, 1, &[0x88]));
        s.extend(frame(0, 0, 1, b"\0\0\0\0\0"));
        let trailers = lit("grpc-status", "5");
        s.extend(frame(1, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &trailers));
        // The server's bytes arrive in two segments, cut inside a frame header.
        let (s1, s2) = s.split_at(12);
        let s1l = u32::try_from(s1.len()).unwrap();
        let out = feed(
            &mut t,
            &[
                seg(100, true, 1, &c),
                seg(135, false, 1, s1),
                seg(140, false, 1 + s1l, s2),
            ],
        );
        assert_eq!(
            out,
            vec![
                Outcome::Response {
                    method: "POST".into(),
                    route: "/e2e.Echo/Say".into(),
                    status: Some(200),
                    latency_ns: 40_000_000
                },
                Outcome::Grpc {
                    method: "POST".into(),
                    route: "/e2e.Echo/Say".into(),
                    code: 5
                },
            ]
        );
    }

    #[test]
    fn h2_skips_uncopied_bytes_by_length() {
        let mut t = Tracker::default();
        let mut c = PREFACE.to_vec();
        let mut block = vec![0x82]; // GET
        block.extend(lit(":path", "/big/1"));
        c.extend(frame(1, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block));
        // Server: a 2000-byte DATA frame on another stream first; only 512 bytes copied.
        let mut s = frame(0, 0, 3, &[0u8; 2000]);
        let tail = frame(1, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &[0x8e]); // :status 500
        let s_len = s.len();
        let copied = s[..512].to_vec();
        s.truncate(512);
        let mut first = seg(1, false, 1, &copied);
        first.payload_len = s_len;
        let next = u32::try_from(s_len).unwrap() + 1;
        let out = feed(
            &mut t,
            &[seg(0, true, 1, &c), first, seg(7, false, next, &tail)],
        );
        assert_eq!(
            out,
            vec![Outcome::Response {
                method: "GET".into(),
                route: "/big/{id}".into(),
                status: Some(500),
                latency_ns: 7_000_000
            }]
        );
        // A frame header inside bytes that were not copied: timing stops for the flow.
        let mut t = Tracker::default();
        let mut c2 = PREFACE.to_vec();
        c2.extend(frame(1, FLAG_END_HEADERS, 1, &block));
        let mut cut = seg(0, true, 1, &c2);
        cut.payload_len = c2.len() + 100;
        let mut out = Vec::new();
        t.segment(&cut, &mut out);
        assert!(!t.active() && t.unsynced, "{out:?}");
    }

    #[test]
    fn later_blocks_that_need_the_dynamic_table_are_unknown() {
        let mut t = Tracker::default();
        let mut c = PREFACE.to_vec();
        // First block inserts :path with incremental indexing (0x44 = literal, indexed
        // name 4 (:path)); the second refers to it (0xbe = dynamic index 62).
        let mut b1 = vec![0x82, 0x44, 6];
        b1.extend_from_slice(b"/a/b/c");
        c.extend(frame(1, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &b1));
        c.extend(frame(
            1,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            3,
            &[0x82, 0xbe],
        ));
        let mut s = frame(1, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &[0x88]);
        s.extend(frame(1, FLAG_END_HEADERS | FLAG_END_STREAM, 3, &[0x88]));
        let out = feed(&mut t, &[seg(0, true, 1, &c), seg(2, false, 1, &s)]);
        let routes: Vec<&str> = out
            .iter()
            .map(|o| match o {
                Outcome::Response { route, .. } => route.as_str(),
                _ => "",
            })
            .collect();
        assert_eq!(routes, ["/a/b/c", "unknown"]);
    }

    #[test]
    fn random_bytes_never_panic_and_stay_bounded() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..200u32 {
            let mut t = Tracker::default();
            let mut out = Vec::new();
            let mut seqs = [1u32, 1u32];
            let mut start = PREFACE.to_vec();
            if round % 2 == 0 {
                start = b"GET / HTTP/1.1\r\n\r\n".to_vec();
            }
            t.segment(&seg(0, true, 1, &start), &mut out);
            seqs[0] += u32::try_from(start.len()).unwrap();
            for i in 0..50u64 {
                let len = usize::try_from(next() % 700).unwrap();
                let bytes: Vec<u8> = (0..len)
                    .map(|_| u8::try_from(next() % 256).unwrap())
                    .collect();
                let client = next() % 2 == 0;
                let side = usize::from(!client);
                let mut s = seg(i, client, seqs[side], &bytes);
                s.payload_len = len + usize::try_from(next() % 3).unwrap();
                seqs[side] = seqs[side].wrapping_add(u32::try_from(s.payload_len).unwrap());
                t.segment(&s, &mut out);
            }
            t.finish(&mut out);
            assert!(out.len() <= 50 * MAX_STREAMS + 64);
        }
    }
}
