//! The bounded flow table (layer 2, user side). A flow is one TCP connection or one UDP
//! 4-tuple, keyed by this host's end and the remote end. It holds the first contiguous
//! bytes each side sent (bounded) until its protocol is recognised, then only a few
//! numbers. A full table evicts its oldest flow and counts the eviction; idle flows expire.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Most client bytes kept per undecided flow.
pub(crate) const CLIENT_BYTES: usize = 2048;
/// Most server bytes kept per undecided flow.
pub(crate) const SERVER_BYTES: usize = 64;

/// A flow's key: protocol, this host's end, the remote end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub(crate) proto: u8,
    pub(crate) local: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) remote: IpAddr,
    pub(crate) remote_port: u16,
}

/// Where recognition stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// Still looking at the first bytes.
    Undecided,
    /// Recognised; waiting for the first response (HTTP/1 status).
    AwaitResponse,
    /// Recognised, or given up on: nothing more to read.
    Done,
}

/// One side's first bytes.
#[derive(Debug, Default)]
pub(crate) struct Side {
    pub(crate) bytes: Vec<u8>,
    /// A copy was cut (only a prefix of a packet's payload is copied), so later bytes are
    /// not contiguous with these and are not appended.
    pub(crate) gap: bool,
}

impl Side {
    /// Appends `payload` while contiguous and under `cap`. `complete` says whether the
    /// copy held the packet's whole payload.
    pub(crate) fn push(&mut self, payload: &[u8], complete: bool, cap: usize) {
        if self.gap {
            return;
        }
        let room = cap.saturating_sub(self.bytes.len());
        let take = payload.len().min(room);
        self.bytes
            .extend_from_slice(payload.get(..take).unwrap_or_default());
        if !complete || take < payload.len() {
            self.gap = true;
        }
    }

    /// Whether more bytes can still arrive.
    pub(crate) fn can_grow(&self, cap: usize) -> bool {
        !self.gap && self.bytes.len() < cap
    }

    pub(crate) fn clear(&mut self) {
        self.bytes = Vec::new();
    }
}

/// One flow.
#[derive(Debug)]
pub(crate) struct Flow {
    pub(crate) last_seen: Instant,
    /// `Some(true)` when this host is the client (it sent the SYN or the first payload).
    pub(crate) local_is_client: Option<bool>,
    pub(crate) state: State,
    pub(crate) client: Side,
    pub(crate) server: Side,
    /// A truncated TLS hello waiting for more bytes.
    pub(crate) pending_tls: bool,
    /// Matched to an owner (layer 4) already.
    pub(crate) owner_checked: bool,
}

impl Flow {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            local_is_client: None,
            state: State::Undecided,
            client: Side::default(),
            server: Side::default(),
            pending_tls: false,
            owner_checked: false,
        }
    }
}

/// The table, bounded by `max`.
#[derive(Debug)]
pub(crate) struct Table {
    max: usize,
    flows: HashMap<Key, Flow>,
    /// Insertion order, for eviction; keys of removed flows are skipped (and compacted).
    order: VecDeque<Key>,
    pub(crate) evicted: u64,
    pub(crate) expired: u64,
}

impl Table {
    pub(crate) fn new(max: usize) -> Self {
        let max = max.max(1);
        Self {
            max,
            flows: HashMap::with_capacity(max.min(4096)),
            order: VecDeque::with_capacity(max.min(4096)),
            evicted: 0,
            expired: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.flows.len()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.max
    }

    /// Makes sure a flow for `key` exists (evicting the oldest when full) and marks it
    /// seen now. Returns whether it is new and the flow evicted to make room.
    pub(crate) fn get_or_insert(&mut self, key: Key, now: Instant) -> (bool, Option<(Key, Flow)>) {
        let mut evicted = None;
        let new = !self.flows.contains_key(&key);
        if new {
            if self.flows.len() >= self.max {
                while let Some(old) = self.order.pop_front() {
                    if let Some(f) = self.flows.remove(&old) {
                        self.evicted += 1;
                        evicted = Some((old, f));
                        break;
                    }
                }
            }
            if self.order.len() > self.max * 2 {
                let live = &self.flows;
                self.order.retain(|k| live.contains_key(k));
            }
            self.order.push_back(key);
        }
        let flow = self.flows.entry(key).or_insert_with(|| Flow::new(now));
        flow.last_seen = now;
        (new, evicted)
    }

    pub(crate) fn get_mut(&mut self, key: &Key) -> Option<&mut Flow> {
        self.flows.get_mut(key)
    }

    pub(crate) fn remove(&mut self, key: &Key) -> Option<Flow> {
        self.flows.remove(key)
    }

    /// Removes flows idle longer than `idle` and returns them.
    pub(crate) fn expire(&mut self, now: Instant, idle: Duration) -> Vec<(Key, Flow)> {
        let old: Vec<Key> = self
            .flows
            .iter()
            .filter(|(_, f)| now.duration_since(f.last_seen) > idle)
            .map(|(k, _)| *k)
            .collect();
        let mut out = Vec::with_capacity(old.len());
        for k in old {
            if let Some(f) = self.flows.remove(&k) {
                self.expired += 1;
                out.push((k, f));
            }
        }
        let live = &self.flows;
        self.order.retain(|k| live.contains_key(k));
        out
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (&Key, &mut Flow)> {
        self.flows.iter_mut()
    }

    /// Bytes held in flow buffers (for the memory report).
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.flows
            .values()
            .map(|f| f.client.bytes.capacity() + f.server.bytes.capacity())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> Key {
        Key {
            proto: 6,
            local: IpAddr::from([10, 0, 0, 1]),
            local_port: 80,
            remote: IpAddr::from([10, 0, 0, 2]),
            remote_port: port,
        }
    }

    #[test]
    fn never_grows_past_its_bound() {
        let mut t = Table::new(100);
        let now = Instant::now();
        for p in 0..10_000u16 {
            t.get_or_insert(key(p), now);
            if let Some(f) = t.get_mut(&key(p)) {
                f.client.push(&[0u8; 600], true, CLIENT_BYTES);
            }
        }
        assert_eq!(t.len(), 100);
        assert_eq!(t.evicted, 9_900);
        assert!(t.order.len() <= 201);
        assert!(t.buffered_bytes() <= 100 * (CLIENT_BYTES + SERVER_BYTES) * 2);
    }

    #[test]
    fn evicts_oldest_first_and_expires_idle() {
        let mut t = Table::new(2);
        let t0 = Instant::now();
        t.get_or_insert(key(1), t0);
        t.get_or_insert(key(2), t0);
        let (_, evicted) = t.get_or_insert(key(3), t0);
        assert_eq!(evicted.map(|(k, _)| k.remote_port), Some(1));
        let later = t0 + Duration::from_secs(120);
        t.get_or_insert(key(3), later);
        let gone = t.expire(later, Duration::from_secs(60));
        assert_eq!(gone.len(), 1);
        assert_eq!(t.len(), 1);
        assert_eq!(t.expired, 1);
    }

    #[test]
    fn side_stops_at_gaps_and_cap() {
        let mut s = Side::default();
        s.push(b"abc", true, 5);
        s.push(b"def", true, 5);
        assert_eq!(s.bytes, b"abcde");
        assert!(!s.can_grow(5));
        let mut s = Side::default();
        s.push(b"abc", false, 100);
        s.push(b"def", true, 100);
        assert_eq!(s.bytes, b"abc");
        assert!(s.gap);
    }
}
