//! The aggregates: what the kernel counted (layer 1), what the copied bytes showed
//! (layer 2), who owns the sockets (layer 4) and how TCP is doing (layer 5). Everything is
//! bounded: the flow table, every top-K table, the owners and per-port rows. Nothing is
//! stored or sent; [`Engine::counts`] and [`Engine::tables`] are what the sockets answer.
//!
//! An [`Engine`] can only be built with a [`crate::privileges::Dropped`] proof, so no byte
//! from the kernel is parsed before the capabilities are gone.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iohr_capture_common::{CLASS_NAMES, FLAG_NAMES, STATS_USED};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::flows::{self, CLIENT_BYTES, Flow, Key, SERVER_BYTES, State};
#[cfg(test)]
use crate::owners::CgroupIndex;
use crate::owners::{self, Owner};
use crate::packet::{self, IPPROTO_TCP, IPPROTO_UDP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::privileges::Dropped;
use crate::proto::{Detect, Event, dns, http1, http2, postgres, redis, tls};
use crate::sockdiag::{self, Socket};
use crate::timing::{self, Outcome};
use crate::topk::TopK;

/// Protocol version of the socket answers to `counts` and `tables` asked in version 1
/// (`docs/capture/design-phase1.md`).
pub(crate) const WIRE_VERSION: u32 = 1;
/// The newest version of the aggregates socket (`docs/capture/design-phase2.md`).
pub(crate) const WIRE_VERSION_2: u32 = 2;
/// Owner key of flows no owner was found for (layer 7 and the lookup).
pub(crate) const UNOWNED: &str = "unowned";
/// Rows of each top-K table kept in memory.
const TOPK_CAPACITY: usize = 64;
/// Rows of each table shown.
const TOP_SHOWN: usize = 20;
/// Most owners kept.
const MAX_OWNERS: usize = 512;
/// Closed flows remembered, to ignore their last packets.
const RECENTLY_CLOSED: usize = 4096;
/// Most per-port TCP rows kept.
const MAX_TCP_PORTS: usize = 256;
/// Timing rows shown in `tables`.
const TIMING_SHOWN: usize = 50;

/// The layers this companion runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct Layers {
    pub(crate) headers: bool,
    pub(crate) protocols: bool,
    pub(crate) owners: bool,
    pub(crate) tcp: bool,
    /// Layer 7: request timing (needs `protocols`).
    pub(crate) timing: bool,
}

impl Layers {
    pub(crate) fn names(self) -> Vec<&'static str> {
        [
            (self.headers, "headers"),
            (self.protocols, "protocols"),
            (self.owners, "owners"),
            (self.tcp, "tcp"),
            (self.timing, "timing"),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, n)| n)
        .collect()
    }

    /// Parses `headers,protocols,owners,tcp,timing`.
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        let mut l = Self {
            headers: false,
            protocols: false,
            owners: false,
            tcp: false,
            timing: false,
        };
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part {
                "headers" => l.headers = true,
                "protocols" => l.protocols = true,
                "owners" => l.owners = true,
                "tcp" => l.tcp = true,
                "timing" => l.timing = true,
                other => {
                    return Err(format!(
                        "unknown layer {other:?} (headers, protocols, owners, tcp, timing; packets have their own switch, --packets)"
                    ));
                }
            }
        }
        if l.timing && !l.protocols {
            return Err("the timing layer needs the protocols layer".into());
        }
        Ok(l)
    }
}

/// Settings of the user-space side.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) interface: String,
    pub(crate) layers: Layers,
    pub(crate) max_flows: usize,
    pub(crate) idle: Duration,
    /// Capabilities the privileged process kept (it never parses).
    pub(crate) companion_kept: Vec<String>,
    /// Layer 3 is on (`--packets`) and its control socket is bound.
    pub(crate) packets: bool,
}

/// One row of the kernel's per-port map, summed over CPUs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PortRow {
    pub(crate) port: u16,
    pub(crate) proto: u8,
    pub(crate) direction: u8,
    pub(crate) packets: u64,
    pub(crate) bytes: u64,
    pub(crate) syn: u64,
    pub(crate) rst: u64,
}

/// One reading of the kernel's maps (layer 1), summed over CPUs. The privileged process
/// reads it and hands it to the parser process (`worker`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct KernelReading {
    /// `[direction] -> (packets, bytes)`.
    pub(crate) totals: [(u64, u64); 2],
    /// `[direction][class] -> (packets, bytes)`.
    pub(crate) classes: [[(u64, u64); 9]; 2],
    /// `[direction][flag]`.
    pub(crate) flags: [[u64; 4]; 2],
    /// Copied, with payload, rate limited, ring buffer full, short; then layer 3: packets
    /// copied, bytes copied, rate limited, ring buffer full.
    pub(crate) stats: [u64; STATS_USED],
    pub(crate) ports: Vec<PortRow>,
}

#[derive(Debug)]
struct Protocols {
    http1_requests: u64,
    http1_responses: u64,
    http1_methods: BTreeMap<&'static str, u64>,
    http1_versions: BTreeMap<&'static str, u64>,
    http1_status: BTreeMap<String, u64>,
    http1_hosts: TopK,
    http1_paths: TopK,
    tls_hellos: u64,
    tls_with_sni: u64,
    tls_truncated: u64,
    tls13: u64,
    tls_sni: TopK,
    tls_alpn: TopK,
    dns_queries: u64,
    dns_responses: u64,
    dns_names: TopK,
    dns_qtypes: TopK,
    dns_rcodes: BTreeMap<u8, u64>,
    h2_connections: u64,
    h2_streams: u64,
    h2_paths: TopK,
    h2_authorities: TopK,
    grpc_calls: u64,
    grpc_methods: TopK,
    redis_commands: TopK,
    postgres: BTreeMap<&'static str, u64>,
}

impl Protocols {
    fn new() -> Self {
        let t = || TopK::new(TOPK_CAPACITY);
        Self {
            http1_requests: 0,
            http1_responses: 0,
            http1_methods: BTreeMap::new(),
            http1_versions: BTreeMap::new(),
            http1_status: BTreeMap::new(),
            http1_hosts: t(),
            http1_paths: t(),
            tls_hellos: 0,
            tls_with_sni: 0,
            tls_truncated: 0,
            tls13: 0,
            tls_sni: t(),
            tls_alpn: TopK::new(16),
            dns_queries: 0,
            dns_responses: 0,
            dns_names: t(),
            dns_qtypes: TopK::new(16),
            dns_rcodes: BTreeMap::new(),
            h2_connections: 0,
            h2_streams: 0,
            h2_paths: t(),
            h2_authorities: t(),
            grpc_calls: 0,
            grpc_methods: t(),
            redis_commands: TopK::new(32),
            postgres: BTreeMap::new(),
        }
    }

    fn replaced(&self) -> u64 {
        [
            &self.http1_hosts,
            &self.http1_paths,
            &self.tls_sni,
            &self.dns_names,
            &self.h2_paths,
            &self.h2_authorities,
            &self.grpc_methods,
        ]
        .iter()
        .map(|t| t.replaced())
        .sum()
    }

    fn keys(&self) -> usize {
        [
            &self.http1_hosts,
            &self.http1_paths,
            &self.tls_sni,
            &self.tls_alpn,
            &self.dns_names,
            &self.dns_qtypes,
            &self.h2_paths,
            &self.h2_authorities,
            &self.grpc_methods,
            &self.redis_commands,
        ]
        .iter()
        .map(|t| t.len())
        .sum()
    }

    fn apply(&mut self, e: Event) {
        match e {
            Event::Http1Request(r) => {
                self.http1_requests += 1;
                *self.http1_methods.entry(r.method).or_default() += 1;
                *self.http1_versions.entry(r.version).or_default() += 1;
                if let Some(h) = &r.host {
                    self.http1_hosts.add(h);
                }
                self.http1_paths.add(&format!("{} {}", r.method, r.path));
            }
            Event::Http1Response { status } => {
                self.http1_responses += 1;
                *self
                    .http1_status
                    .entry(format!("{}xx", status / 100))
                    .or_default() += 1;
            }
            Event::TlsClientHello(h) => {
                self.tls_hellos += 1;
                if h.truncated {
                    self.tls_truncated += 1;
                }
                if h.tls13 {
                    self.tls13 += 1;
                }
                if let Some(s) = &h.sni {
                    self.tls_with_sni += 1;
                    self.tls_sni.add(s);
                }
                if let Some(a) = &h.alpn {
                    self.tls_alpn.add(a);
                }
            }
            Event::DnsQuery(q) => {
                self.dns_queries += 1;
                self.dns_names.add(&q.name);
                self.dns_qtypes.add(&q.qtype);
            }
            Event::DnsResponse { rcode } => {
                self.dns_responses += 1;
                *self.dns_rcodes.entry(rcode).or_default() += 1;
            }
            Event::Http2(c) => {
                self.h2_connections += 1;
                self.h2_streams += u64::from(c.streams);
                if let Some(p) = &c.path {
                    let m = c.method.as_deref().unwrap_or("?");
                    self.h2_paths.add(&format!("{m} {p}"));
                } else if c.streams > 0 {
                    self.h2_paths.add("unknown");
                }
                if let Some(a) = &c.authority {
                    self.h2_authorities.add(a);
                }
                if c.grpc {
                    self.grpc_calls += 1;
                    self.grpc_methods
                        .add(c.grpc_method.as_deref().unwrap_or("unknown"));
                }
            }
            Event::Redis { command } => self.redis_commands.add(&command),
            Event::Postgres(m) => *self.postgres.entry(m.as_str()).or_default() += 1,
        }
    }
}

#[derive(Debug, Default, Clone)]
struct OwnerRow {
    kind: &'static str,
    name: String,
    process: Option<String>,
    user: Option<String>,
    sockets: u64,
    established: u64,
    listening: Vec<u16>,
    flows: u64,
}

/// TCP health per owner (for the lookup): retransmits and resets since start, the RTT of
/// its established sockets at the last sample.
#[derive(Debug, Default, Clone)]
struct OwnerTcp {
    retransmits: u64,
    resets: u64,
    rtt_buckets: [u64; 5],
}

/// Layer 3 numbers the parser keeps outside the engine (the packet buffer and the pcap
/// files), refreshed every poll.
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub(crate) struct PacketsInfo {
    pub(crate) buffered_packets: u64,
    pub(crate) buffered_bytes: u64,
    pub(crate) buffer_evicted: u64,
    pub(crate) received: u64,
    pub(crate) pcaps_written: u64,
    pub(crate) pcaps_deleted: u64,
    pub(crate) pcap_files: u64,
    pub(crate) pcap_bytes: u64,
}

#[derive(Debug, Default, Clone)]
struct TcpPort {
    role: &'static str,
    established: u64,
    rtt_sum_us: u64,
    rtt_n: u64,
    rtt_max_us: u32,
    retransmits: u64,
    accept_queue: u32,
    backlog: u32,
    queue_full_seen: u64,
}

/// The engine.
#[derive(Debug)]
pub(crate) struct Engine {
    settings: Settings,
    started_ms: u128,
    started: Instant,
    updated_ms: u128,
    flows: flows::Table,
    kernel: KernelReading,
    records_read: u64,
    records_malformed: u64,
    flows_seen: u64,
    flows_opened: u64,
    flows_closed: u64,
    recognised: u64,
    unrecognised: u64,
    proto: Protocols,
    remotes: TopK,
    // layer 4
    owners: HashMap<String, OwnerRow>,
    conn_owner: HashMap<(u8, IpAddr, u16, IpAddr, u16), String>,
    listen_owner: HashMap<(u8, u16), String>,
    sockets: u64,
    flows_owned: u64,
    flows_unowned: u64,
    sockdiag_errors: u64,
    // layer 5
    established: u64,
    listening: u64,
    time_wait: u64,
    rtt_buckets: [u64; 5],
    retrans_by_cookie: HashMap<u64, u32>,
    retransmits: u64,
    tcp_ports: HashMap<u16, TcpPort>,
    host_base: HashMap<(String, String), u64>,
    host_now: HashMap<(String, String), u64>,
    parser_capabilities: Vec<&'static str>,
    /// Flows closed by a FIN or RST lately: the other side's FIN or ACK that follows is
    /// not a new flow. Bounded.
    recently_closed: HashSet<Key>,
    closed_order: std::collections::VecDeque<Key>,
    // layer 7
    timing: timing::Table,
    budget: timing::Budget,
    owner_tcp: HashMap<String, OwnerTcp>,
    // layer 3
    pub(crate) packets: PacketsInfo,
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

impl Engine {
    /// Built only after the drop: `_dropped` is the proof.
    pub(crate) fn new(settings: Settings, dropped: &Dropped) -> Self {
        let max = settings.max_flows;
        Self {
            settings,
            started_ms: unix_ms(),
            started: Instant::now(),
            updated_ms: unix_ms(),
            flows: flows::Table::new(max),
            kernel: KernelReading::default(),
            records_read: 0,
            records_malformed: 0,
            flows_seen: 0,
            flows_opened: 0,
            flows_closed: 0,
            recognised: 0,
            unrecognised: 0,
            proto: Protocols::new(),
            remotes: TopK::new(TOPK_CAPACITY),
            owners: HashMap::new(),
            conn_owner: HashMap::new(),
            listen_owner: HashMap::new(),
            sockets: 0,
            flows_owned: 0,
            flows_unowned: 0,
            sockdiag_errors: 0,
            established: 0,
            listening: 0,
            time_wait: 0,
            rtt_buckets: [0; 5],
            retrans_by_cookie: HashMap::new(),
            retransmits: 0,
            tcp_ports: HashMap::new(),
            host_base: HashMap::new(),
            host_now: HashMap::new(),
            parser_capabilities: dropped.kept.clone(),
            recently_closed: HashSet::new(),
            closed_order: std::collections::VecDeque::new(),
            timing: timing::Table::default(),
            budget: timing::Budget::default(),
            owner_tcp: HashMap::new(),
            packets: PacketsInfo::default(),
        }
    }

    /// One ring-buffer record.
    pub(crate) fn ingest(&mut self, record: &[u8]) {
        self.records_read += 1;
        let Ok(p) = packet::parse(record) else {
            self.records_malformed += 1;
            return;
        };
        let ingress = p.direction == 0;
        let key = if ingress {
            Key {
                proto: p.proto,
                local: p.dst,
                local_port: p.dport,
                remote: p.src,
                remote_port: p.sport,
            }
        } else {
            Key {
                proto: p.proto,
                local: p.src,
                local_port: p.sport,
                remote: p.dst,
                remote_port: p.dport,
            }
        };
        let syn =
            p.proto == IPPROTO_TCP && p.tcp_flags & TCP_SYN != 0 && p.tcp_flags & TCP_ACK == 0;
        if self.recently_closed.contains(&key) {
            if syn {
                // The 4-tuple is reused by a new connection.
                self.recently_closed.remove(&key);
            } else if p.payload.is_empty() {
                // The tail of a closed connection (the other FIN, a last RST).
                return;
            }
        }
        let now = Instant::now();
        let (new, evicted) = self.flows.get_or_insert(key, now);
        if let Some((k, f)) = evicted {
            self.finish(&k, f);
        }
        if new {
            self.flows_seen += 1;
            self.remotes.add(&key.remote.to_string());
        }
        let owner = self.owner_of(&key);
        let mut events = Vec::new();
        let mut outcomes = Vec::new();
        let mut closing = false;
        let mut decided = None;
        if let Some(flow) = self.flows.get_mut(&key) {
            if !flow.owner_checked
                && let Some(o) = &owner
            {
                flow.owner_checked = true;
                if let Some(row) = self.owners.get_mut(o) {
                    row.flows += 1;
                }
                self.flows_owned += 1;
            }
            if p.proto == IPPROTO_TCP {
                if p.tcp_flags & TCP_SYN != 0 && p.tcp_flags & TCP_ACK == 0 {
                    flow.local_is_client = Some(!ingress);
                    self.flows_opened += 1;
                }
                closing = p.tcp_flags & (TCP_FIN | TCP_RST) != 0;
            }
            if !p.payload.is_empty() && self.settings.layers.protocols {
                decided = on_payload(flow, &key, &p, ingress, &mut events);
            }
            if self.settings.layers.timing
                && p.proto == IPPROTO_TCP
                && timing_segment(flow, &p, ingress, &mut self.budget, &mut outcomes)
            {
                self.timing.unsynced += 1;
            }
        }
        match decided {
            Some(true) => self.recognised += 1,
            Some(false) => self.unrecognised += 1,
            None => {}
        }
        for e in events {
            self.proto.apply(e);
        }
        if p.proto == IPPROTO_TCP && p.tcp_flags & TCP_RST != 0 {
            self.owner_tcp_row(owner.as_deref().unwrap_or(UNOWNED), |r| r.resets += 1);
        }
        self.record(&key, &outcomes);
        if closing && let Some(f) = self.flows.remove(&key) {
            self.flows_closed += 1;
            if self.closed_order.len() >= RECENTLY_CLOSED
                && let Some(old) = self.closed_order.pop_front()
            {
                self.recently_closed.remove(&old);
            }
            if self.recently_closed.insert(key) {
                self.closed_order.push_back(key);
            }
            self.finish(&key, f);
        }
    }

    /// Layer 7 outcomes of one flow, under its owner.
    fn record(&mut self, key: &Key, outcomes: &[Outcome]) {
        if outcomes.is_empty() {
            return;
        }
        let owner = self.owner_of(key);
        let owner = owner.as_deref().unwrap_or(UNOWNED);
        for o in outcomes {
            self.timing.add(owner, o);
        }
    }

    /// The per-owner TCP row (bounded like the owners).
    fn owner_tcp_row(&mut self, owner: &str, f: impl FnOnce(&mut OwnerTcp)) {
        if let Some(r) = self.owner_tcp.get_mut(owner) {
            f(r);
        } else if self.owner_tcp.len() < MAX_OWNERS {
            f(self.owner_tcp.entry(owner.to_owned()).or_default());
        }
    }

    /// A flow leaves the table: report a pending truncated TLS hello, settle its owner.
    #[allow(clippy::needless_pass_by_value)] // the flow is consumed: it left the table
    fn finish(&mut self, key: &Key, mut flow: Flow) {
        if let Some(t) = flow.timing.as_mut() {
            let mut outcomes = Vec::new();
            t.finish(&mut outcomes);
            self.budget.release(t);
            self.record(key, &outcomes);
        }
        if flow.pending_tls
            && let Detect::Yes(h) = tls::client_hello(&flow.client.bytes)
        {
            self.recognised += 1;
            self.proto.apply(Event::TlsClientHello(h));
        } else if flow.state == State::Undecided && !flow.client.bytes.is_empty() {
            self.unrecognised += 1;
        }
        if !flow.owner_checked {
            if let Some(o) = self.owner_of(key) {
                if let Some(row) = self.owners.get_mut(&o) {
                    row.flows += 1;
                }
                self.flows_owned += 1;
            } else {
                self.flows_unowned += 1;
            }
        }
    }

    fn owner_of(&self, k: &Key) -> Option<String> {
        if !self.settings.layers.owners {
            return None;
        }
        self.conn_owner
            .get(&(k.proto, k.local, k.local_port, k.remote, k.remote_port))
            .or_else(|| self.listen_owner.get(&(k.proto, k.local_port)))
            .cloned()
    }

    /// Expires idle flows; call every poll.
    pub(crate) fn tick(&mut self) {
        let gone = self.flows.expire(Instant::now(), self.settings.idle);
        for (k, f) in gone {
            self.finish(&k, f);
        }
        // Flows still unmatched get another try against the latest sockets.
        let mut matched = Vec::new();
        let keys: Vec<Key> = self
            .flows
            .iter_mut()
            .filter(|(_, f)| !f.owner_checked)
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            if let Some(o) = self.owner_of(&k) {
                matched.push((k, o));
            }
        }
        for (k, o) in matched {
            if let Some(f) = self.flows.get_mut(&k) {
                f.owner_checked = true;
            }
            if let Some(row) = self.owners.get_mut(&o) {
                row.flows += 1;
            }
            self.flows_owned += 1;
        }
    }

    /// The latest kernel map reading.
    pub(crate) fn kernel(&mut self, reading: KernelReading) {
        self.kernel = reading;
        self.updated_ms = unix_ms();
    }

    /// One `sock_diag` dump and the host TCP counters (layers 4 and 5).
    #[allow(clippy::too_many_lines)] // one pass over the dump feeds both layers
    pub(crate) fn sockets(
        &mut self,
        dump: std::io::Result<Vec<Socket>>,
        host: HashMap<(String, String), u64>,
        cgroups: &HashMap<u64, (String, Option<String>)>,
        users: &HashMap<u32, String>,
    ) {
        if self.host_base.is_empty() {
            self.host_base.clone_from(&host);
        }
        self.host_now = host;
        let socks = match dump {
            Ok(s) => s,
            Err(e) => {
                self.sockdiag_errors += 1;
                tracing::warn!(error = %e, "sock_diag dump failed; owners and TCP health skipped this round");
                return;
            }
        };
        let flows_by_owner: HashMap<String, u64> = self
            .owners
            .iter()
            .map(|(k, r)| (k.clone(), r.flows))
            .collect();
        self.owners.clear();
        self.conn_owner.clear();
        self.listen_owner.clear();
        self.sockets = socks.len() as u64;
        self.established = 0;
        self.listening = 0;
        self.time_wait = 0;
        self.rtt_buckets = [0; 5];
        let listening_ports: HashSet<u16> = socks
            .iter()
            .filter(|s| s.proto == IPPROTO_TCP && s.state == sockdiag::TCP_LISTEN)
            .map(|s| s.local_port)
            .collect();
        let mut ports: HashMap<u16, TcpPort> = HashMap::new();
        let mut retrans = HashMap::with_capacity(socks.len());
        for r in self.owner_tcp.values_mut() {
            r.rtt_buckets = [0; 5];
        }
        for s in &socks {
            let tcp = s.proto == IPPROTO_TCP;
            match (tcp, s.state) {
                (true, sockdiag::TCP_ESTABLISHED) => self.established += 1,
                (true, sockdiag::TCP_LISTEN) => self.listening += 1,
                (true, sockdiag::TCP_TIME_WAIT) => self.time_wait += 1,
                _ => {}
            }
            if self.settings.layers.owners && s.state != sockdiag::TCP_TIME_WAIT {
                let owner = match s.cgroup_id.and_then(|id| cgroups.get(&id)) {
                    Some((path, procs)) => (owners::classify(path), procs.clone()),
                    None => (
                        Owner {
                            kind: "user",
                            name: users
                                .get(&s.uid)
                                .cloned()
                                .unwrap_or_else(|| s.uid.to_string()),
                        },
                        None,
                    ),
                };
                let key = owner.0.key();
                if self.owners.len() < MAX_OWNERS || self.owners.contains_key(&key) {
                    let row = self.owners.entry(key.clone()).or_insert_with(|| OwnerRow {
                        kind: owner.0.kind,
                        name: owner.0.name.clone(),
                        process: owner.1.clone(),
                        user: users.get(&s.uid).cloned(),
                        flows: flows_by_owner.get(&key).copied().unwrap_or(0),
                        ..OwnerRow::default()
                    });
                    row.sockets += 1;
                    let listening = (tcp && s.state == sockdiag::TCP_LISTEN)
                        || (!tcp && s.state == sockdiag::UDP_UNCONNECTED);
                    if listening {
                        if row.listening.len() < 16 && !row.listening.contains(&s.local_port) {
                            row.listening.push(s.local_port);
                        }
                        self.listen_owner
                            .insert((s.proto, s.local_port), key.clone());
                    } else {
                        if s.state == sockdiag::TCP_ESTABLISHED {
                            row.established += 1;
                        }
                        self.conn_owner.insert(
                            (s.proto, s.local, s.local_port, s.remote, s.remote_port),
                            key.clone(),
                        );
                    }
                }
            }
            if !self.settings.layers.tcp || !tcp {
                continue;
            }
            let (port, role) =
                if s.state == sockdiag::TCP_LISTEN || listening_ports.contains(&s.local_port) {
                    (s.local_port, "server")
                } else {
                    (s.remote_port, "client")
                };
            if ports.len() >= MAX_TCP_PORTS && !ports.contains_key(&port) {
                continue;
            }
            let row = ports.entry(port).or_insert_with(|| TcpPort {
                role,
                ..TcpPort::default()
            });
            if s.state == sockdiag::TCP_LISTEN {
                row.accept_queue = row.accept_queue.saturating_add(s.rqueue);
                row.backlog = row.backlog.saturating_add(s.wqueue);
                if s.wqueue > 0 && s.rqueue >= s.wqueue {
                    row.queue_full_seen += 1;
                }
            }
            if let Some(info) = s.tcp {
                let before = self.retrans_by_cookie.get(&s.cookie).copied().unwrap_or(0);
                let delta = u64::from(info.total_retrans.saturating_sub(before));
                self.retransmits += delta;
                row.retransmits += delta;
                let owner = self
                    .conn_owner
                    .get(&(s.proto, s.local, s.local_port, s.remote, s.remote_port))
                    .or_else(|| self.listen_owner.get(&(s.proto, s.local_port)))
                    .cloned();
                if let Some(o) = owner {
                    let rtt = (s.state == sockdiag::TCP_ESTABLISHED && info.rtt_us > 0)
                        .then(|| rtt_bucket(info.rtt_us));
                    self.owner_tcp_row(&o, |r| {
                        r.retransmits += delta;
                        if let Some(b) = rtt {
                            r.rtt_buckets[b] += 1;
                        }
                    });
                }
                if retrans.len() < sockdiag::MAX_SOCKETS {
                    retrans.insert(s.cookie, info.total_retrans);
                }
                if s.state == sockdiag::TCP_ESTABLISHED && info.rtt_us > 0 {
                    row.established += 1;
                    row.rtt_sum_us += u64::from(info.rtt_us);
                    row.rtt_n += 1;
                    row.rtt_max_us = row.rtt_max_us.max(info.rtt_us);
                    self.rtt_buckets[rtt_bucket(info.rtt_us)] += 1;
                }
            }
        }
        self.retrans_by_cookie = retrans;
        // Keep what earlier rounds learned per port (retransmits, queue full), refreshed.
        for (port, row) in ports {
            let old = self.tcp_ports.remove(&port).unwrap_or_default();
            self.tcp_ports.insert(
                port,
                TcpPort {
                    retransmits: old.retransmits + row.retransmits,
                    queue_full_seen: old.queue_full_seen + row.queue_full_seen,
                    ..row
                },
            );
        }
        if self.tcp_ports.len() > MAX_TCP_PORTS {
            let mut keep: Vec<(u16, TcpPort)> = self.tcp_ports.drain().collect();
            keep.sort_by_key(|a| std::cmp::Reverse(a.1.established));
            keep.truncate(MAX_TCP_PORTS);
            self.tcp_ports = keep.into_iter().collect();
        }
    }

    fn host_delta(&self, table: &str, name: &str) -> u64 {
        let k = (table.to_owned(), name.to_owned());
        self.host_now
            .get(&k)
            .copied()
            .unwrap_or(0)
            .saturating_sub(self.host_base.get(&k).copied().unwrap_or(0))
    }

    fn rss_kib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.strip_prefix("VmRSS:")?
                        .trim()
                        .trim_end_matches("kB")
                        .trim()
                        .parse()
                        .ok()
                })
            })
            .unwrap_or(0)
    }

    /// The `counts` answer: numbers only, by construction (no name, path, address, port
    /// or owner travels in it).
    #[allow(clippy::too_many_lines)] // one JSON document, field by field
    pub(crate) fn counts(&self) -> Value {
        let k = &self.kernel;
        let dir = |d: usize| json!({"packets": k.totals[d].0, "bytes": k.totals[d].1});
        let mut classes = serde_json::Map::new();
        for (i, name) in CLASS_NAMES.iter().enumerate() {
            classes.insert(
                (*name).into(),
                json!({
                    "ingress": {"packets": k.classes[0][i].0, "bytes": k.classes[0][i].1},
                    "egress": {"packets": k.classes[1][i].0, "bytes": k.classes[1][i].1},
                }),
            );
        }
        let flags = |d: usize| {
            let mut m = serde_json::Map::new();
            for (i, n) in FLAG_NAMES.iter().enumerate() {
                m.insert((*n).into(), json!(k.flags[d][i]));
            }
            Value::Object(m)
        };
        let p = &self.proto;
        let mut layers = self.settings.layers.names();
        if self.settings.packets {
            layers.push("packets");
        }
        let t = &self.timing;
        let mut timing = t.total.to_json();
        timing["unsynced"] = t.unsynced.into();
        timing["keys"] = t.keys.len().into();
        timing["keys_dropped"] = t.keys_dropped.into();
        timing["untracked"] = t.untracked.into();
        timing["budget"] = json!({
            "pending": self.budget.pending,
            "pending_max": timing::MAX_PENDING_TOTAL,
            "kept_bytes": self.budget.kept,
            "kept_bytes_max": timing::MAX_KEPT_TOTAL,
            "refused": self.budget.refused,
            "pending_peak": self.budget.peak.0,
            "kept_bytes_peak": self.budget.peak.1,
        });
        if let Some(m) = timing.as_object_mut() {
            m.remove("grpc_status");
        }
        let pk = &self.packets;
        let packets = json!({
            "enabled": self.settings.packets,
            "copied": k.stats[5],
            "bytes_copied": k.stats[6],
            "rate_limited": k.stats[7],
            "ring_buffer_full": k.stats[8],
            "received": pk.received,
            "buffered_packets": pk.buffered_packets,
            "buffered_bytes": pk.buffered_bytes,
            "buffer_evicted": pk.buffer_evicted,
            "pcaps_written": pk.pcaps_written,
            "pcaps_deleted": pk.pcaps_deleted,
            "pcap_files": pk.pcap_files,
            "pcap_bytes": pk.pcap_bytes,
        });
        json!({
            "version": WIRE_VERSION,
            "companion_version": env!("CARGO_PKG_VERSION"),
            "interface": self.settings.interface,
            "started_unix_ms": self.started_ms,
            "updated_unix_ms": self.updated_ms,
            "uptime_secs": self.started.elapsed().as_secs(),
            "packet_unit": "skb",
            "layers": layers,
            "privileges": {
                "parser_capabilities": self.parser_capabilities,
                "companion_kept": self.settings.companion_kept,
            },
            "headers": {
                "ingress": dir(0),
                "egress": dir(1),
                "classes": classes,
                "tcp_flags": {"ingress": flags(0), "egress": flags(1)},
                "ports_tracked": k.ports.len(),
            },
            "copy": {
                "records_copied": k.stats[0],
                "records_with_payload": k.stats[1],
                "records_read": self.records_read,
                "records_malformed": self.records_malformed,
            },
            "drops": {
                "rate_limited": k.stats[2],
                "ring_buffer_full": k.stats[3],
                "short_packets": k.stats[4],
                "flows_evicted": self.flows.evicted,
            },
            "flows": {
                "seen": self.flows_seen,
                "active": self.flows.len(),
                "capacity": self.flows.capacity(),
                "opened": self.flows_opened,
                "closed": self.flows_closed,
                "expired": self.flows.expired,
                "evicted": self.flows.evicted,
                "recognised": self.recognised,
                "unrecognised": self.unrecognised,
            },
            "protocols": {
                "http1_requests": p.http1_requests,
                "http1_responses": p.http1_responses,
                "tls_client_hellos": p.tls_hellos,
                "tls_with_sni": p.tls_with_sni,
                "tls_truncated": p.tls_truncated,
                "tls13_offered": p.tls13,
                "dns_queries": p.dns_queries,
                "dns_responses": p.dns_responses,
                "http2_connections": p.h2_connections,
                "http2_streams": p.h2_streams,
                "grpc_calls": p.grpc_calls,
                "redis_commands": p.redis_commands.total(),
                "postgres_connections": p.postgres.values().sum::<u64>(),
            },
            "owners": {
                "sockets": self.sockets,
                "owners": self.owners.len(),
                "flows_owned": self.flows_owned,
                "flows_unowned": self.flows_unowned,
                "sock_diag_errors": self.sockdiag_errors,
            },
            "tcp": {
                "established": self.established,
                "listening": self.listening,
                "time_wait": self.time_wait,
                "retransmits_sampled": self.retransmits,
                "rtt_ms": {
                    "lt_1": self.rtt_buckets[0],
                    "lt_10": self.rtt_buckets[1],
                    "lt_100": self.rtt_buckets[2],
                    "lt_1000": self.rtt_buckets[3],
                    "ge_1000": self.rtt_buckets[4],
                },
                "resets_in": k.flags[0][3],
                "resets_out": k.flags[1][3],
                "host": {
                    "listen_overflows": self.host_delta("TcpExt", "ListenOverflows"),
                    "listen_drops": self.host_delta("TcpExt", "ListenDrops"),
                    "timeouts": self.host_delta("TcpExt", "TCPTimeouts"),
                    "retrans_segs": self.host_delta("Tcp", "RetransSegs"),
                    "estab_resets": self.host_delta("Tcp", "EstabResets"),
                    "out_rsts": self.host_delta("Tcp", "OutRsts"),
                    "attempt_fails": self.host_delta("Tcp", "AttemptFails"),
                },
            },
            "timing": timing,
            "packets": packets,
            "memory": {
                "rss_kib": Self::rss_kib(),
                "flow_buffer_bytes": self.flows.buffered_bytes(),
                "topk_keys": self.proto.keys() + self.remotes.len(),
                "topk_replacements": self.proto.replaced() + self.remotes.replaced(),
            },
        })
    }

    /// The `tables` answer: `counts` plus the bounded top-K tables, for a person on the
    /// host. Never asked for by the agent.
    pub(crate) fn tables(&self) -> Value {
        let mut v = self.counts();
        let p = &self.proto;
        let top = |t: &TopK| serde_json::to_value(t.top(TOP_SHOWN)).unwrap_or_default();
        let mut ports: Vec<&PortRow> = self.kernel.ports.iter().collect();
        ports.sort_by_key(|a| std::cmp::Reverse(a.packets));
        let ports: Vec<Value> = ports
            .into_iter()
            .take(64)
            .map(|c| {
                json!({
                    "port": c.port,
                    "proto": if c.proto == IPPROTO_TCP { "tcp" } else if c.proto == IPPROTO_UDP { "udp" } else { "other" },
                    "direction": if c.direction == 0 { "ingress" } else { "egress" },
                    "packets": c.packets, "bytes": c.bytes, "syn": c.syn, "rst": c.rst,
                })
            })
            .collect();
        let mut owners: Vec<(&String, &OwnerRow)> = self.owners.iter().collect();
        owners.sort_by(|a, b| b.1.sockets.cmp(&a.1.sockets).then(a.0.cmp(b.0)));
        let owners: Vec<Value> = owners
            .into_iter()
            .take(50)
            .map(|(k, r)| {
                json!({
                    "owner": k, "kind": r.kind, "name": r.name, "process": r.process,
                    "user": r.user, "sockets": r.sockets, "established": r.established,
                    "listening_ports": r.listening, "flows": r.flows,
                })
            })
            .collect();
        let mut tcp_ports: Vec<(&u16, &TcpPort)> = self.tcp_ports.iter().collect();
        tcp_ports.sort_by(|a, b| b.1.established.cmp(&a.1.established).then(a.0.cmp(b.0)));
        let tcp_ports: Vec<Value> = tcp_ports
            .into_iter()
            .take(50)
            .map(|(port, r)| {
                #[allow(clippy::cast_precision_loss)]
                let avg = if r.rtt_n == 0 {
                    0.0
                } else {
                    r.rtt_sum_us as f64 / r.rtt_n as f64 / 1000.0
                };
                json!({
                    "port": port, "role": r.role, "established": r.established,
                    "rtt_ms_avg": (avg * 1000.0).round() / 1000.0,
                    "rtt_ms_max": f64::from(r.rtt_max_us) / 1000.0,
                    "retransmits": r.retransmits, "accept_queue": r.accept_queue,
                    "backlog": r.backlog, "queue_full_seen": r.queue_full_seen,
                })
            })
            .collect();
        let rcodes: BTreeMap<&str, u64> = p
            .dns_rcodes
            .iter()
            .map(|(c, n)| (rcode_name(*c), *n))
            .collect();
        let mut rows: Vec<(&timing::Key, &timing::Stats)> = self.timing.keys.iter().collect();
        rows.sort_by(|a, b| b.1.requests.cmp(&a.1.requests).then(a.0.cmp(b.0)));
        let timing_rows: Vec<Value> = rows
            .into_iter()
            .take(TIMING_SHOWN)
            .map(|((owner, method, route), st)| {
                let mut r = st.to_json();
                r["owner"] = owner.as_str().into();
                r["route"] = format!("{method} {route}").into();
                r
            })
            .collect();
        v["tables"] = json!({
            "http1": {
                "methods": p.http1_methods, "versions": p.http1_versions,
                "status_classes": p.http1_status,
                "hosts": top(&p.http1_hosts), "paths": top(&p.http1_paths),
            },
            "tls": {"sni": top(&p.tls_sni), "alpn": top(&p.tls_alpn)},
            "dns": {"names": top(&p.dns_names), "qtypes": top(&p.dns_qtypes), "rcodes": rcodes},
            "http2": {
                "paths": top(&p.h2_paths), "authorities": top(&p.h2_authorities),
                "grpc_methods": top(&p.grpc_methods),
            },
            "redis": {"commands": top(&p.redis_commands)},
            "postgres": {"messages": p.postgres},
            "remote_addresses": top(&self.remotes),
            "ports": ports,
            "owners": owners,
            "tcp_ports": tcp_ports,
            "timing": timing_rows,
        });
        v
    }

    /// The `lookup` answer (version 2): numbers for one owner and route, never a name and
    /// never a list. `owner` and `route` are what the caller sent; they are not echoed.
    pub(crate) fn lookup(&self, owner: &str, route: &str) -> Value {
        let stats = self.timing.lookup(owner, route);
        let tcp = self.owner_tcp.get(owner);
        let mut v = stats.cloned().unwrap_or_default().to_json();
        v["version"] = WIRE_VERSION_2.into();
        v["found"] = stats.is_some().into();
        v["updated_unix_ms"] = json!(self.updated_ms);
        v["owner_tcp"] = json!({
            "found": tcp.is_some(),
            "retransmits": tcp.map_or(0, |t| t.retransmits),
            "resets": tcp.map_or(0, |t| t.resets),
            "rtt_ms": rtt_json(&tcp.map_or([0; 5], |t| t.rtt_buckets)),
        });
        v
    }
}

/// The RTT histogram slot: under 1, 10, 100, 1000 ms, and above.
const fn rtt_bucket(us: u32) -> usize {
    match us {
        0..1_000 => 0,
        1_000..10_000 => 1,
        10_000..100_000 => 2,
        100_000..1_000_000 => 3,
        _ => 4,
    }
}

fn rtt_json(b: &[u64; 5]) -> Value {
    json!({"lt_1": b[0], "lt_10": b[1], "lt_100": b[2], "lt_1000": b[3], "ge_1000": b[4]})
}

/// Layer 7: one TCP segment of a flow into its timing tracker. Returns whether the flow
/// lost sync with this segment.
fn timing_segment(
    flow: &mut Flow,
    p: &packet::Packet<'_>,
    ingress: bool,
    budget: &mut timing::Budget,
    out: &mut Vec<Outcome>,
) -> bool {
    let syn = p.tcp_flags & TCP_SYN != 0;
    // The side is known from the SYN (or, without one, from who spoke first).
    let from_client = if syn {
        p.tcp_flags & TCP_ACK == 0
    } else {
        match flow.local_is_client {
            Some(local_client) => local_client != ingress,
            None => return false,
        }
    };
    let t = flow.timing.get_or_insert_with(Box::default);
    if !t.active() {
        return false;
    }
    let room = budget.room();
    t.segment(
        &timing::Segment {
            ts_ns: p.ts_ns,
            from_client,
            seq: p.seq,
            syn,
            fin: p.tcp_flags & TCP_FIN != 0,
            payload: p.payload,
            payload_len: p.payload_len,
            room,
        },
        out,
    );
    budget.charge(t);
    if !room {
        budget.refused += out
            .iter()
            .filter(|o| matches!(o, Outcome::Abandoned { .. }))
            .count() as u64;
    }
    // An inactive tracker is never fed again, so this is true once per flow at most.
    t.unsynced && !t.active()
}

const fn rcode_name(c: u8) -> &'static str {
    match c {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

/// Payload handling for one packet of one flow; pushes events and returns
/// `Some(recognised?)` when this packet decided the flow.
fn on_payload(
    flow: &mut Flow,
    key: &Key,
    p: &packet::Packet<'_>,
    ingress: bool,
    events: &mut Vec<Event>,
) -> Option<bool> {
    let ports = [key.local_port, key.remote_port];
    if key.proto == IPPROTO_UDP {
        // Every datagram is a message of its own.
        if ports.iter().any(|p| matches!(p, 53 | 5353 | 5355)) {
            match dns::message(p.payload, false) {
                Detect::Yes(dns::Message::Query(q)) => events.push(Event::DnsQuery(q)),
                Detect::Yes(dns::Message::Response { rcode }) => {
                    events.push(Event::DnsResponse { rcode });
                }
                _ => {}
            }
        }
        if flow.state == State::Undecided {
            flow.state = State::Done;
            return Some(!events.is_empty());
        }
        return None;
    }
    if flow.state == State::Done {
        return None;
    }
    if flow.local_is_client.is_none() {
        // No SYN seen: the side that speaks first is the client.
        flow.local_is_client = Some(!ingress);
    }
    let from_client = flow.local_is_client == Some(!ingress);
    let complete = p.payload.len() >= p.payload_len;
    if from_client {
        flow.client.push(p.payload, complete, CLIENT_BYTES);
    } else {
        flow.server.push(p.payload, complete, SERVER_BYTES);
    }
    match flow.state {
        State::Undecided if from_client => recognise(flow, ports, events),
        State::AwaitResponse if !from_client => {
            match http1::response(&flow.server.bytes) {
                Detect::Yes(status) => {
                    events.push(Event::Http1Response { status });
                    flow.state = State::Done;
                    flow.server.clear();
                }
                Detect::No => {
                    flow.state = State::Done;
                    flow.server.clear();
                }
                Detect::NeedMore => {
                    if !flow.server.can_grow(SERVER_BYTES) {
                        flow.state = State::Done;
                        flow.server.clear();
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn recognise(flow: &mut Flow, ports: [u16; 2], events: &mut Vec<Event>) -> Option<bool> {
    let b = &flow.client.bytes;
    let grow = flow.client.can_grow(CLIENT_BYTES);
    let mut waiting = false;
    let mut found: Option<(Event, State)> = None;

    match http1::request(b) {
        Detect::Yes(r) => found = Some((Event::Http1Request(r), State::AwaitResponse)),
        Detect::NeedMore => waiting = true,
        Detect::No => {}
    }
    if found.is_none() {
        match http2::client(b) {
            Detect::Yes(c) => found = Some((Event::Http2(c), State::Done)),
            Detect::NeedMore => waiting = true,
            Detect::No => {}
        }
    }
    if found.is_none() {
        match tls::client_hello(b) {
            Detect::Yes(h) if h.truncated && grow => {
                flow.pending_tls = true;
                waiting = true;
            }
            Detect::Yes(h) => found = Some((Event::TlsClientHello(h), State::Done)),
            Detect::NeedMore => waiting = true,
            Detect::No => {}
        }
    }
    if found.is_none() && ports.contains(&53) {
        match dns::message(b, true) {
            Detect::Yes(dns::Message::Query(q)) => found = Some((Event::DnsQuery(q), State::Done)),
            Detect::Yes(dns::Message::Response { rcode }) => {
                found = Some((Event::DnsResponse { rcode }, State::Done));
            }
            Detect::NeedMore => waiting = true,
            Detect::No => {}
        }
    }
    if found.is_none() && (ports.contains(&6379) || b.first() == Some(&b'*')) {
        match redis::command(b) {
            Detect::Yes(command) => found = Some((Event::Redis { command }, State::Done)),
            Detect::NeedMore => waiting = true,
            Detect::No => {}
        }
    }
    if found.is_none() && ports.contains(&5432) {
        match postgres::opening(b) {
            Detect::Yes(m) => found = Some((Event::Postgres(m), State::Done)),
            Detect::NeedMore => waiting = true,
            Detect::No => {}
        }
    }
    if let Some((event, state)) = found {
        events.push(event);
        flow.state = state;
        flow.pending_tls = false;
        flow.client.clear();
        return Some(true);
    }
    if waiting && grow {
        return None;
    }
    if flow.pending_tls {
        // The hello cannot grow any more: count what it showed.
        if let Detect::Yes(h) = tls::client_hello(b) {
            events.push(Event::TlsClientHello(h));
            flow.pending_tls = false;
            flow.state = State::Done;
            flow.client.clear();
            return Some(true);
        }
    }
    flow.state = State::Done;
    flow.client.clear();
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::record_v4;

    fn engine() -> Engine {
        Engine::new(
            Settings {
                interface: "veth0".into(),
                layers: Layers::parse("headers,protocols,owners,tcp").unwrap(),
                max_flows: 64,
                idle: Duration::from_secs(60),
                companion_kept: Vec::new(),
                packets: false,
            },
            &Dropped::for_tests(),
        )
    }

    const CLIENT: ([u8; 4], u16) = ([10, 0, 0, 2], 40000);
    const SERVER: ([u8; 4], u16) = ([10, 0, 0, 1], 8080);

    #[test]
    fn http1_request_and_response_over_one_flow() {
        let mut e = engine();
        e.ingest(&record_v4(0, 6, CLIENT, SERVER, 0x02, b""));
        e.ingest(&record_v4(
            0,
            6,
            CLIENT,
            SERVER,
            0x18,
            include_bytes!("../tests/fixtures/http1.bin"),
        ));
        e.ingest(&record_v4(
            1,
            6,
            SERVER,
            CLIENT,
            0x18,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        ));
        e.ingest(&record_v4(0, 6, CLIENT, SERVER, 0x11, b""));
        let c = e.counts();
        assert_eq!(c["protocols"]["http1_requests"], 1);
        assert_eq!(c["protocols"]["http1_responses"], 1);
        assert_eq!(c["flows"]["opened"], 1);
        assert_eq!(c["flows"]["closed"], 1);
        assert_eq!(c["flows"]["active"], 0);
        e.ingest(&record_v4(1, 6, SERVER, CLIENT, 0x11, b""));
        e.ingest(&record_v4(0, 6, CLIENT, SERVER, 0x10, b""));
        let c = e.counts();
        assert_eq!(c["flows"]["seen"], 1, "the closing tail is not a new flow");
        assert_eq!(c["flows"]["active"], 0);
        let t = e.tables();
        assert_eq!(t["tables"]["http1"]["hosts"][0]["key"], "web.e2e.test");
        assert_eq!(t["tables"]["http1"]["paths"][0]["key"], "GET /items/{id}");
        assert_eq!(t["tables"]["http1"]["status_classes"]["2xx"], 1);
    }

    #[test]
    fn tls_h2_and_dns() {
        let mut e = engine();
        e.ingest(&record_v4(
            0,
            6,
            ([10, 0, 0, 2], 40001),
            ([10, 0, 0, 1], 443),
            0x18,
            include_bytes!("../tests/fixtures/tls.bin"),
        ));
        e.ingest(&record_v4(
            0,
            6,
            ([10, 0, 0, 2], 40002),
            ([10, 0, 0, 1], 50051),
            0x18,
            include_bytes!("../tests/fixtures/h2.bin"),
        ));
        for port in 50000..50005 {
            e.ingest(&record_v4(
                0,
                17,
                ([10, 0, 0, 2], port),
                ([10, 0, 0, 1], 53),
                0,
                include_bytes!("../tests/fixtures/dns.bin"),
            ));
        }
        let c = e.counts();
        assert_eq!(c["protocols"]["tls_client_hellos"], 1);
        assert_eq!(c["protocols"]["tls_with_sni"], 1);
        assert_eq!(c["protocols"]["http2_connections"], 1);
        assert_eq!(c["protocols"]["grpc_calls"], 1);
        assert_eq!(c["protocols"]["dns_queries"], 5);
        let t = e.tables();
        assert_eq!(t["tables"]["tls"]["sni"][0]["key"], "tls-e2e.example");
        assert_eq!(t["tables"]["dns"]["names"][0]["count"], 5);
        assert_eq!(
            t["tables"]["http2"]["grpc_methods"][0]["key"],
            "/e2e.Echo/Say"
        );
    }

    #[test]
    fn counts_carry_no_names_paths_or_addresses() {
        let mut e = engine();
        e.ingest(&record_v4(
            0,
            6,
            CLIENT,
            SERVER,
            0x18,
            include_bytes!("../tests/fixtures/http1.bin"),
        ));
        e.ingest(&record_v4(
            0,
            6,
            ([10, 0, 0, 2], 40001),
            ([10, 0, 0, 1], 443),
            0x18,
            include_bytes!("../tests/fixtures/tls.bin"),
        ));
        e.ingest(&record_v4(
            0,
            17,
            ([10, 0, 0, 2], 50000),
            ([10, 0, 0, 1], 53),
            0,
            include_bytes!("../tests/fixtures/dns.bin"),
        ));
        let text = e.counts().to_string();
        for secret in [
            "web.e2e.test",
            "items",
            "tls-e2e.example",
            "dns-e2e",
            "10.0.0.2",
            "8080",
            "40000",
        ] {
            assert!(!text.contains(secret), "{secret} in counts: {text}");
        }
        assert!(e.tables().to_string().contains("tls-e2e.example"));
    }

    #[test]
    fn a_split_tls_hello_is_reassembled_from_whole_segments() {
        let mut e = engine();
        let hello: &[u8] = include_bytes!("../tests/fixtures/tls.bin");
        let (a, b) = hello.split_at(100);
        e.ingest(&record_v4(0, 6, CLIENT, ([10, 0, 0, 1], 443), 0x18, a));
        assert_eq!(
            e.counts()["protocols"]["tls_client_hellos"],
            0,
            "waits for the rest"
        );
        e.ingest(&record_v4(0, 6, CLIENT, ([10, 0, 0, 1], 443), 0x18, b));
        let t = e.tables();
        assert_eq!(t["protocols"]["tls_client_hellos"], 1);
        assert_eq!(t["tables"]["tls"]["sni"][0]["key"], "tls-e2e.example");
    }

    #[test]
    fn flow_table_and_memory_stay_bounded_under_a_flood() {
        let mut e = engine();
        for i in 0..20_000u32 {
            let port = u16::try_from(1024 + i % 60_000).unwrap();
            let src = [
                10,
                1,
                u8::try_from(i / 256 % 256).unwrap(),
                u8::try_from(i % 256).unwrap(),
            ];
            e.ingest(&record_v4(
                0,
                6,
                (src, port),
                SERVER,
                0x18,
                b"\x00garbage that is no protocol at all",
            ));
        }
        let c = e.counts();
        assert_eq!(c["flows"]["active"], 64);
        assert_eq!(c["flows"]["evicted"], 20_000 - 64);
        assert!(c["memory"]["topk_keys"].as_u64().unwrap() <= 11 * TOPK_CAPACITY as u64);
        assert!(c["memory"]["flow_buffer_bytes"].as_u64().unwrap() <= 64 * 4096);
    }

    #[test]
    fn owners_from_sockets() {
        use crate::sockdiag::tests::message;
        use std::os::unix::fs::MetadataExt as _;
        let mut e = engine();
        let dir = std::env::temp_dir().join(format!("iohr-capture-engine-{}", std::process::id()));
        let cg = dir.join("cg/iohr-e2e-web");
        std::fs::create_dir_all(&cg).unwrap();
        std::fs::write(cg.join("cgroup.procs"), "1\n").unwrap();
        std::fs::create_dir_all(dir.join("proc/1")).unwrap();
        std::fs::write(dir.join("proc/1/comm"), "python3\n").unwrap();
        let ino = std::fs::metadata(&cg).unwrap().ino();
        let mut idx = CgroupIndex::new(&dir.join("cg"), &dir.join("proc"));
        let mut buf = message(sockdiag::TCP_LISTEN, SERVER, ([0, 0, 0, 0], 0), ino, 0, 0);
        buf.extend(message(
            sockdiag::TCP_ESTABLISHED,
            SERVER,
            CLIENT,
            ino,
            2500,
            3,
        ));
        let mut socks = Vec::new();
        let _ = sockdiag::parse(&buf, 6, 1, &mut socks);
        let resolved = owners::resolve(&socks, &mut idx);
        e.sockets(Ok(socks), HashMap::new(), &resolved, &HashMap::new());
        e.ingest(&record_v4(0, 6, ([10, 0, 0, 3], 41000), SERVER, 0x02, b""));
        let t = e.tables();
        assert_eq!(t["owners"]["flows_owned"], 1);
        let o = &t["tables"]["owners"][0];
        assert_eq!(o["owner"], "cgroup:/iohr-e2e-web");
        assert_eq!(o["process"], "python3");
        assert_eq!(o["listening_ports"][0], 8080);
        assert_eq!(t["tcp"]["retransmits_sampled"], 3);
        assert_eq!(t["tcp"]["rtt_ms"]["lt_10"], 1);
        assert_eq!(t["tables"]["tcp_ports"][0]["port"], 8080);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn big_engine(max_flows: usize) -> Engine {
        Engine::new(
            Settings {
                interface: "veth0".into(),
                layers: Layers::parse("headers,protocols,owners,tcp,timing").unwrap(),
                max_flows,
                idle: Duration::from_secs(60),
                companion_kept: Vec::new(),
                packets: false,
            },
            &Dropped::for_tests(),
        )
    }

    fn client(i: u32) -> ([u8; 4], u16) {
        let [_, a, b, c] = i.to_be_bytes();
        ([10, a, b, c], 40_000 + u16::try_from(i % 20_000).unwrap())
    }

    #[test]
    fn timing_memory_stays_in_budget_under_a_spoofed_flood() {
        use crate::packet::tests::record_v4_at;
        // HTTP/1: 40000 flows, each 16 pipelined requests never answered.
        let mut e = big_engine(65_536);
        let req = b"GET /flood/1 HTTP/1.1\r\n\r\n";
        let rl = u32::try_from(req.len()).unwrap();
        for i in 0..40_000u32 {
            let c = client(i);
            e.ingest(&record_v4_at(0, 6, c, SERVER, 0x02, 1000, 1, b""));
            for k in 0..16 {
                e.ingest(&record_v4_at(0, 6, c, SERVER, 0x18, 1001 + k * rl, 2, req));
            }
        }
        let t = &e.counts()["timing"]["budget"];
        assert!(
            t["pending"].as_u64().unwrap() <= timing::MAX_PENDING_TOTAL as u64,
            "{t}"
        );
        assert!(t["refused"].as_u64().unwrap() > 0, "{t}");
        // HTTP/2: 6000 flows, each a header block that never ends (no END_HEADERS).
        let mut e = big_engine(65_536);
        let mut h2 = crate::proto::http2::PREFACE.to_vec();
        let block = vec![0x40u8; 4000];
        h2.extend_from_slice(&[0x00, 0x0f, 0xa0, 0x01, 0x00, 0, 0, 0, 1]);
        h2.extend_from_slice(&block);
        for i in 0..6_000u32 {
            let c = client(i);
            e.ingest(&record_v4_at(0, 6, c, SERVER, 0x02, 5000, 1, b""));
            // Only the first 512 bytes are copied, but the kernel says the payload is longer:
            // the frame's bytes are kept as they arrive, in later segments too.
            let mut seq = 5001;
            for chunk in h2.chunks(400) {
                e.ingest(&record_v4_at(0, 6, c, SERVER, 0x18, seq, 2, chunk));
                seq += u32::try_from(chunk.len()).unwrap();
            }
        }
        let t = &e.counts()["timing"]["budget"];
        assert!(
            t["kept_bytes_peak"].as_u64().unwrap() <= (timing::MAX_KEPT_TOTAL + 2 * 4096) as u64,
            "{t}"
        );
        assert!(e.flows.buffered_bytes() < 64 * 1024 * 1024);
        // Flows leaving the table give their charge back.
        let mut e = big_engine(8);
        for i in 0..100u32 {
            let c = client(i);
            e.ingest(&record_v4_at(0, 6, c, SERVER, 0x02, 1000, 1, b""));
            e.ingest(&record_v4_at(0, 6, c, SERVER, 0x18, 1001, 2, req));
        }
        assert!(e.counts()["timing"]["budget"]["pending"].as_u64().unwrap() <= 8);
    }

    #[test]
    fn routes_and_owners_never_reach_counts_or_lookups() {
        use crate::packet::tests::record_v4_at;
        use crate::sockdiag::tests::message;
        use std::os::unix::fs::MetadataExt as _;
        let mut e = big_engine(64);
        let dir = std::env::temp_dir().join(format!("iohr-capture-canary-{}", std::process::id()));
        let cg = dir.join("cg/canary-owner-cg");
        std::fs::create_dir_all(&cg).unwrap();
        std::fs::write(cg.join("cgroup.procs"), "1\n").unwrap();
        std::fs::create_dir_all(dir.join("proc/1")).unwrap();
        std::fs::write(dir.join("proc/1/comm"), "canary-proc\n").unwrap();
        let ino = std::fs::metadata(&cg).unwrap().ino();
        let mut idx = CgroupIndex::new(&dir.join("cg"), &dir.join("proc"));
        let buf = message(sockdiag::TCP_LISTEN, SERVER, ([0, 0, 0, 0], 0), ino, 0, 0);
        let mut socks = Vec::new();
        let _ = sockdiag::parse(&buf, 6, 1, &mut socks);
        let resolved = owners::resolve(&socks, &mut idx);
        e.sockets(Ok(socks), HashMap::new(), &resolved, &HashMap::new());
        let req = b"GET /canary-route-word/7?canary-query=1 HTTP/1.1\r\nHost: canary-host.example\r\n\r\n";
        let ok = b"HTTP/1.1 200 OK\r\n\r\n";
        e.ingest(&record_v4_at(0, 6, CLIENT, SERVER, 0x02, 99, 1, b""));
        e.ingest(&record_v4_at(1, 6, SERVER, CLIENT, 0x12, 499, 1, b""));
        e.ingest(&record_v4_at(
            0, 6, CLIENT, SERVER, 0x18, 100, 1_000_000, req,
        ));
        e.ingest(&record_v4_at(
            1, 6, SERVER, CLIENT, 0x18, 500, 31_000_000, ok,
        ));
        let found = e.lookup("cgroup:/canary-owner-cg", "GET /canary-route-word/{id}");
        assert_eq!(found["found"], true, "not vacuous: {found}");
        assert_eq!(found["requests"], 1);
        assert_eq!(found["latency_ms"]["counts"][6], 1, "30 ms");
        let engine = std::sync::Mutex::new(e);
        let v1 = crate::server::answer(
            Ok(&json!({"version": 1, "request": "counts"})),
            &engine,
            true,
        );
        let v2 = crate::server::answer(
            Ok(&json!({"version": 2, "request": "counts"})),
            &engine,
            true,
        );
        assert_eq!(v1["timing"]["requests"], 1);
        for text in [v1.to_string(), v2.to_string(), found.to_string()] {
            for canary in [
                "canary-route-word",
                "canary-owner-cg",
                "canary-proc",
                "canary-host",
                "canary-query",
                "10.0.0.2",
            ] {
                assert!(!text.contains(canary), "{canary} in {text}");
            }
        }
        // A person's tables do carry them (the guard is about who asks).
        let t = crate::server::answer(
            Ok(&json!({"version": 2, "request": "tables"})),
            &engine,
            false,
        );
        assert!(t.to_string().contains("canary-route-word"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
