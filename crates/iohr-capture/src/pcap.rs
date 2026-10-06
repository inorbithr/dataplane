//! Layer 3: whole packets in the parser's memory, and pcapng files on request
//! (`docs/capture/design-phase2.md`, "Layer 3").
//!
//! - [`Buffer`]: the packets the kernel copied, bounded by bytes and by age (300 s).
//! - [`Filter`]: a small, safe subset of the tcpdump syntax (protocol, port, host).
//! - [`write_header`] / [`write_packet`]: pcapng (one section, one interface, nanosecond
//!   timestamps, the direction in `epb_flags`).
//! - [`Manager`]: files in one directory, created `O_EXCL` with mode 0600, size- and
//!   time-capped, deleted after the retention. Nothing here sends a file anywhere.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iohr_capture_common::PACKET_HEADER_BYTES;

/// Longest look-back, and longest `next` capture.
pub(crate) const MAX_SECONDS: u64 = 300;
/// Most terms in a filter.
const MAX_TERMS: usize = 8;
/// Longest filter text.
const MAX_FILTER: usize = 256;
/// Bytes counted per buffered packet on top of its data (bookkeeping).
const OVERHEAD: usize = 64;
/// File name prefix and suffix: the sweeper deletes only names like these.
const PREFIX: &str = "iohr-";
const SUFFIX: &str = ".pcapng";

/// One copied packet.
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    /// Kernel monotonic time (`bpf_ktime_get_ns`).
    pub(crate) ts_ns: u64,
    pub(crate) skb_len: u32,
    pub(crate) direction: u8,
    pub(crate) l2_len: u8,
    pub(crate) ethertype: u16,
    pub(crate) data: Arc<[u8]>,
}

impl Packet {
    /// Parses a packets ring-buffer record (`PacketHeader` + bytes).
    pub(crate) fn parse(record: &[u8]) -> Option<Self> {
        let head = record.get(..PACKET_HEADER_BYTES)?;
        let ts_ns = u64::from_le_bytes(head.get(0..8)?.try_into().ok()?);
        let skb_len = u32::from_le_bytes(head.get(8..12)?.try_into().ok()?);
        let cap_len = u32::from_le_bytes(head.get(12..16)?.try_into().ok()?) as usize;
        let ethertype = u16::from_le_bytes(head.get(16..18)?.try_into().ok()?);
        let direction = *head.get(18)?;
        let l2_len = *head.get(19)?;
        let data = record.get(PACKET_HEADER_BYTES..PACKET_HEADER_BYTES + cap_len)?;
        Some(Self {
            ts_ns,
            skb_len,
            direction,
            l2_len,
            ethertype,
            data: Arc::from(data),
        })
    }

    fn cost(&self) -> usize {
        self.data.len() + OVERHEAD
    }

    /// The L3/L4 fields a filter looks at.
    fn fields(&self) -> Fields {
        let mut f = Fields::default();
        let l2 = usize::from(self.l2_len);
        let d = &self.data[..];
        let be16 = |at: usize| Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]));
        let l4 = match self.ethertype {
            0x0800 => {
                let Some(vihl) = d.get(l2) else { return f };
                let ihl = usize::from(vihl & 0x0f) * 4;
                let (Some(proto), Some(s), Some(t)) = (
                    d.get(l2 + 9),
                    d.get(l2 + 12..l2 + 16),
                    d.get(l2 + 16..l2 + 20),
                ) else {
                    return f;
                };
                f.family = 4;
                f.proto = *proto;
                f.src = <[u8; 4]>::try_from(s).ok().map(IpAddr::from);
                f.dst = <[u8; 4]>::try_from(t).ok().map(IpAddr::from);
                let frag = be16(l2 + 6).unwrap_or(0);
                if frag & 0x1fff != 0 {
                    return f;
                }
                l2 + ihl
            }
            0x86dd => {
                let (Some(proto), Some(s), Some(t)) = (
                    d.get(l2 + 6),
                    d.get(l2 + 8..l2 + 24),
                    d.get(l2 + 24..l2 + 40),
                ) else {
                    return f;
                };
                f.family = 6;
                f.proto = *proto;
                f.src = <[u8; 16]>::try_from(s).ok().map(IpAddr::from);
                f.dst = <[u8; 16]>::try_from(t).ok().map(IpAddr::from);
                l2 + 40
            }
            _ => return f,
        };
        if f.proto == 6 || f.proto == 17 {
            f.sport = be16(l4);
            f.dport = be16(l4 + 2);
        }
        f
    }
}

#[derive(Debug, Default)]
struct Fields {
    family: u8,
    proto: u8,
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    sport: Option<u16>,
    dport: Option<u16>,
}

// ---------------------------------------------------------------- filter

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Any,
    Src,
    Dst,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Prim {
    Tcp,
    Udp,
    Icmp,
    Ip4,
    Ip6,
    Port(Dir, u16),
    Host(Dir, IpAddr),
}

/// A conjunction of (possibly negated) primitives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Filter {
    terms: Vec<(bool, Prim)>,
}

impl Filter {
    /// Parses `[not] PRIM (and [not] PRIM)*` where PRIM is `tcp`, `udp`, `icmp`, `ip`,
    /// `ip6`, `[src|dst] port N` or `[src|dst] host ADDR`. Empty matches everything.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        if text.len() > MAX_FILTER {
            return Err(format!("the filter is longer than {MAX_FILTER} bytes"));
        }
        let words: Vec<&str> = text.split_whitespace().collect();
        let mut terms = Vec::new();
        let mut i = 0;
        while i < words.len() {
            if !terms.is_empty() {
                if words[i] != "and" {
                    return Err(format!(
                        "expected `and` before {:?} (only `and` and `not` combine terms)",
                        words[i]
                    ));
                }
                i += 1;
            }
            let negated = words.get(i) == Some(&"not");
            if negated {
                i += 1;
            }
            let mut dir = Dir::Any;
            match words.get(i) {
                Some(&"src") => {
                    dir = Dir::Src;
                    i += 1;
                }
                Some(&"dst") => {
                    dir = Dir::Dst;
                    i += 1;
                }
                _ => {}
            }
            let word = *words.get(i).ok_or("the filter ends early")?;
            i += 1;
            let prim = match (word, dir) {
                ("tcp", Dir::Any) => Prim::Tcp,
                ("udp", Dir::Any) => Prim::Udp,
                ("icmp", Dir::Any) => Prim::Icmp,
                ("ip", Dir::Any) => Prim::Ip4,
                ("ip6", Dir::Any) => Prim::Ip6,
                ("port", _) => {
                    let n = words.get(i).ok_or("`port` needs a number")?;
                    i += 1;
                    Prim::Port(
                        dir,
                        n.parse()
                            .map_err(|_| format!("{n:?} is not a port number"))?,
                    )
                }
                ("host", _) => {
                    let a = words.get(i).ok_or("`host` needs an address")?;
                    i += 1;
                    Prim::Host(
                        dir,
                        a.parse().map_err(|_| {
                            format!("{a:?} is not an IP address (names are not looked up)")
                        })?,
                    )
                }
                (w, _) => {
                    return Err(format!(
                        "{w:?} is not supported (tcp, udp, icmp, ip, ip6, [src|dst] port N, [src|dst] host ADDR, and, not)"
                    ));
                }
            };
            terms.push((negated, prim));
            if terms.len() > MAX_TERMS {
                return Err(format!("at most {MAX_TERMS} terms"));
            }
        }
        Ok(Self { terms })
    }

    /// Whether a packet matches.
    pub(crate) fn matches(&self, p: &Packet) -> bool {
        if self.terms.is_empty() {
            return true;
        }
        let f = p.fields();
        self.terms
            .iter()
            .all(|(negated, prim)| prim_matches(prim, &f) != *negated)
    }
}

fn prim_matches(p: &Prim, f: &Fields) -> bool {
    let pick = |d: Dir, s: Option<u16>, t: Option<u16>, want: u16| match d {
        Dir::Any => s == Some(want) || t == Some(want),
        Dir::Src => s == Some(want),
        Dir::Dst => t == Some(want),
    };
    match p {
        Prim::Tcp => f.proto == 6 && f.family != 0,
        Prim::Udp => f.proto == 17 && f.family != 0,
        Prim::Icmp => (f.family == 4 && f.proto == 1) || (f.family == 6 && f.proto == 58),
        Prim::Ip4 => f.family == 4,
        Prim::Ip6 => f.family == 6,
        Prim::Port(d, n) => pick(*d, f.sport, f.dport, *n),
        Prim::Host(d, a) => match d {
            Dir::Any => f.src == Some(*a) || f.dst == Some(*a),
            Dir::Src => f.src == Some(*a),
            Dir::Dst => f.dst == Some(*a),
        },
    }
}

// ---------------------------------------------------------------- buffer

/// The packets kept in memory, oldest first.
#[derive(Debug)]
pub(crate) struct Buffer {
    q: VecDeque<Packet>,
    bytes: usize,
    cap: usize,
    pub(crate) received: u64,
    pub(crate) evicted: u64,
}

impl Buffer {
    pub(crate) fn new(cap_bytes: usize) -> Self {
        Self {
            q: VecDeque::new(),
            bytes: 0,
            cap: cap_bytes,
            received: 0,
            evicted: 0,
        }
    }

    pub(crate) fn push(&mut self, p: Packet) {
        self.received += 1;
        let newest = p.ts_ns;
        self.bytes += p.cost();
        self.q.push_back(p);
        let oldest_allowed = newest.saturating_sub(MAX_SECONDS * 1_000_000_000);
        while self.bytes > self.cap || self.q.front().is_some_and(|f| f.ts_ns < oldest_allowed) {
            let Some(old) = self.q.pop_front() else { break };
            self.bytes -= old.cost();
            self.evicted += 1;
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.q.len()
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Clones (cheap: shared data) of the packets since `since_ns` that match, up to
    /// `max_bytes` of pcapng; and whether the cap cut it.
    pub(crate) fn select(
        &self,
        since_ns: u64,
        filter: &Filter,
        max_bytes: u64,
    ) -> (Vec<Packet>, bool) {
        let mut out = Vec::new();
        let mut size = HEADER_BYTES;
        for p in self.q.iter().filter(|p| p.ts_ns >= since_ns) {
            if !filter.matches(p) {
                continue;
            }
            let next = size + epb_len(p.data.len());
            if next > max_bytes {
                return (out, true);
            }
            size = next;
            out.push(p.clone());
        }
        (out, false)
    }
}

// ---------------------------------------------------------------- pcapng

/// Bytes [`write_header`] writes (at most; the interface name is bounded).
const HEADER_BYTES: u64 = 256;

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

/// Size of one Enhanced Packet Block.
fn epb_len(data: usize) -> u64 {
    // header 28 + data + pad + epb_flags option (8) + end of options (4) + trailer 4
    (28 + data + pad4(data) + 8 + 4 + 4) as u64
}

fn option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&code.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value.get(..usize::from(len)).unwrap_or_default());
    out.extend(std::iter::repeat_n(0u8, pad4(usize::from(len))));
}

fn block(w: &mut impl Write, kind: u32, body: &[u8]) -> io::Result<()> {
    let total = u32::try_from(12 + body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block too large"))?;
    w.write_all(&kind.to_le_bytes())?;
    w.write_all(&total.to_le_bytes())?;
    w.write_all(body)?;
    w.write_all(&total.to_le_bytes())
}

/// The Section Header and Interface Description blocks. `linktype` 1 (Ethernet) or 101
/// (raw IP); timestamps in nanoseconds.
pub(crate) fn write_header(
    w: &mut impl Write,
    linktype: u16,
    snaplen: u32,
    interface: &str,
) -> io::Result<()> {
    let mut shb = Vec::with_capacity(64);
    shb.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    option(
        &mut shb,
        4,
        format!("iohr-capture {}", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    option(&mut shb, 0, b"");
    block(w, 0x0A0D_0D0A, &shb)?;
    let mut idb = Vec::with_capacity(64);
    idb.extend_from_slice(&linktype.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&snaplen.to_le_bytes());
    let name: String = interface.chars().take(64).collect();
    option(&mut idb, 2, name.as_bytes());
    option(&mut idb, 9, &[9]); // if_tsresol: 10^-9 s
    option(&mut idb, 0, b"");
    block(w, 1, &idb)
}

/// One Enhanced Packet Block; `unix_ns` is the wall-clock time.
pub(crate) fn write_packet(w: &mut impl Write, unix_ns: u64, p: &Packet) -> io::Result<()> {
    let cap = u32::try_from(p.data.len()).unwrap_or(u32::MAX);
    let mut epb = Vec::with_capacity(p.data.len() + 40);
    epb.extend_from_slice(&0u32.to_le_bytes());
    epb.extend_from_slice(&u32::try_from(unix_ns >> 32).unwrap_or(0).to_le_bytes());
    epb.extend_from_slice(
        &u32::try_from(unix_ns & 0xffff_ffff)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    epb.extend_from_slice(&cap.to_le_bytes());
    epb.extend_from_slice(&p.skb_len.max(cap).to_le_bytes());
    epb.extend_from_slice(&p.data);
    epb.extend(std::iter::repeat_n(0u8, pad4(p.data.len())));
    // epb_flags: bits 0-1 direction, 01 inbound, 10 outbound.
    let flags: u32 = if p.direction == 0 { 1 } else { 2 };
    option(&mut epb, 2, &flags.to_le_bytes());
    option(&mut epb, 0, b"");
    block(w, 6, &epb)
}

// ---------------------------------------------------------------- files

/// How the files are made.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) dir: PathBuf,
    /// Largest file a request may ask for.
    pub(crate) max_bytes: u64,
    /// Largest total of our files in `dir`.
    pub(crate) dir_max_bytes: u64,
    pub(crate) retention: Duration,
    pub(crate) linktype: u16,
    pub(crate) snaplen: u32,
    pub(crate) interface: String,
}

/// A request, as the control socket took it.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub(crate) seconds: u64,
    pub(crate) filter: Filter,
    pub(crate) max_bytes: u64,
    pub(crate) next: bool,
}

/// Why a request failed (the control socket's error code and message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refused {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl Refused {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Parses the fields of a `pcap` request.
pub(crate) fn request(v: &serde_json::Value, settings: &Settings) -> Result<Request, Refused> {
    let seconds = v["seconds"].as_u64().unwrap_or(30);
    if !(1..=MAX_SECONDS).contains(&seconds) {
        return Err(Refused::new("bad_request", "seconds must be 1 to 300"));
    }
    let filter = match &v["filter"] {
        serde_json::Value::Null => Filter::default(),
        serde_json::Value::String(s) => {
            Filter::parse(s).map_err(|m| Refused::new("bad_request", m))?
        }
        _ => return Err(Refused::new("bad_request", "filter must be a string")),
    };
    let max_bytes = v["max_bytes"].as_u64().unwrap_or(settings.max_bytes);
    if max_bytes > settings.max_bytes || max_bytes < 4096 {
        return Err(Refused::new(
            "bad_request",
            format!(
                "max_bytes must be 4096 to {} (IOHR_CAPTURE_PCAP_MAX_BYTES)",
                settings.max_bytes
            ),
        ));
    }
    let next = match v["mode"].as_str() {
        None | Some("last") => false,
        Some("next") => true,
        Some(_) => return Err(Refused::new("bad_request", "mode is \"last\" or \"next\"")),
    };
    Ok(Request {
        seconds,
        filter,
        max_bytes,
        next,
    })
}

/// A `last` file ready to be written.
#[derive(Debug)]
pub(crate) struct Prepared {
    path: PathBuf,
    w: io::BufWriter<fs::File>,
    packets: Vec<Packet>,
    truncated: bool,
    offset: i128,
    from_ns: u64,
    to_ns: u64,
    retention: Duration,
}

impl Prepared {
    /// Writes the packets and answers (blocking file I/O).
    pub(crate) fn write(mut self) -> Result<serde_json::Value, Refused> {
        let io = |e: io::Error| Refused::new("io", format!("writing: {}", e.kind()));
        for p in &self.packets {
            write_packet(&mut self.w, to_unix_ns(p.ts_ns, self.offset), p).map_err(io)?;
        }
        self.w.flush().map_err(io)?;
        let size = fs::metadata(&self.path).map_or(0, |m| m.len());
        Ok(serde_json::json!({
            "path": self.path.display().to_string(),
            "packets": self.packets.len(),
            "bytes": size,
            "truncated": self.truncated,
            "from_unix_ms": to_unix_ns(self.from_ns, self.offset) / 1_000_000,
            "to_unix_ms": to_unix_ns(self.to_ns, self.offset) / 1_000_000,
            "expires_unix_ms": unix_ms_now() + u64::try_from(self.retention.as_millis()).unwrap_or(0),
        }))
    }
}

/// Everything layer 3 keeps in the parser: the buffer, the files, the clock offset.
#[derive(Debug)]
pub(crate) struct State {
    pub(crate) buffer: Buffer,
    pub(crate) files: Manager,
    /// Wall-clock minus monotonic nanoseconds (refreshed every poll).
    pub(crate) offset: i128,
}

impl State {
    pub(crate) fn new(buffer_bytes: usize, settings: Settings) -> Self {
        Self {
            buffer: Buffer::new(buffer_bytes),
            files: Manager::new(settings),
            offset: clock_offset_ns(),
        }
    }

    /// A packet from the kernel: into a running `next` file, and into the buffer.
    pub(crate) fn push(&mut self, p: Packet) {
        self.files.on_packet(&p, self.offset);
        self.buffer.push(p);
    }

    /// Every poll: the clock offset, the end of a `next` file, the retention sweep.
    pub(crate) fn tick(&mut self) {
        self.offset = clock_offset_ns();
        self.files.tick();
        self.files.sweep();
    }

    /// The numbers for `counts` (and the control socket's `status`).
    pub(crate) fn info(&self) -> crate::engine::PacketsInfo {
        let (files, bytes) = self.files.usage();
        crate::engine::PacketsInfo {
            buffered_packets: self.buffer.len() as u64,
            buffered_bytes: self.buffer.bytes() as u64,
            buffer_evicted: self.buffer.evicted,
            received: self.buffer.received,
            pcaps_written: self.files.written,
            pcaps_deleted: self.files.deleted,
            pcap_files: files,
            pcap_bytes: bytes,
        }
    }
}

/// A file being written by a `next` request.
#[derive(Debug)]
struct Active {
    path: PathBuf,
    file: io::BufWriter<fs::File>,
    until_ns: u64,
    filter: Filter,
    max_bytes: u64,
    bytes: u64,
    packets: u64,
}

/// The pcap files.
#[derive(Debug)]
pub(crate) struct Manager {
    pub(crate) settings: Settings,
    n: u64,
    active: Option<Active>,
    pub(crate) written: u64,
    pub(crate) deleted: u64,
}

/// Wall-clock nanoseconds minus kernel monotonic nanoseconds, now.
pub(crate) fn clock_offset_ns() -> i128 {
    let mono = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let mono_ns = i128::from(mono.tv_sec) * 1_000_000_000 + i128::from(mono.tv_nsec);
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    i128::try_from(wall).unwrap_or(0) - mono_ns
}

/// Kernel monotonic nanoseconds now (the clock of `bpf_ktime_get_ns`).
pub(crate) fn mono_now_ns() -> u64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(t.tv_sec).unwrap_or(0) * 1_000_000_000 + u64::try_from(t.tv_nsec).unwrap_or(0)
}

fn to_unix_ns(mono_ns: u64, offset: i128) -> u64 {
    u64::try_from(i128::from(mono_ns) + offset).unwrap_or(0)
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

/// `20261006T120000Z` for a time in seconds since the epoch (UTC, proleptic Gregorian).
fn utc_stamp(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn ours(name: &str) -> bool {
    name.starts_with(PREFIX)
        && name.ends_with(SUFFIX)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

impl Manager {
    pub(crate) fn new(settings: Settings) -> Self {
        Self {
            settings,
            n: 0,
            active: None,
            written: 0,
            deleted: 0,
        }
    }

    /// Our files in the directory and their total size.
    pub(crate) fn usage(&self) -> (u64, u64) {
        let Ok(dir) = fs::read_dir(&self.settings.dir) else {
            return (0, 0);
        };
        dir.flatten()
            .filter(|e| e.file_name().to_str().is_some_and(ours))
            .filter_map(|e| e.metadata().ok())
            .fold((0, 0), |(n, b), m| (n + 1, b + m.len()))
    }

    /// Deletes our files older than the retention. Returns how many went.
    pub(crate) fn sweep(&mut self) -> u64 {
        let Ok(dir) = fs::read_dir(&self.settings.dir) else {
            return 0;
        };
        let now = SystemTime::now();
        let active = self.active.as_ref().map(|a| a.path.clone());
        let mut gone = 0;
        for e in dir.flatten() {
            if !e.file_name().to_str().is_some_and(ours) || Some(e.path()) == active {
                continue;
            }
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age >= self.settings.retention);
            if old && fs::remove_file(e.path()).is_ok() {
                gone += 1;
            }
        }
        self.deleted += gone;
        gone
    }

    fn create(&mut self) -> Result<(PathBuf, io::BufWriter<fs::File>), Refused> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.n += 1;
        let path = self
            .settings
            .dir
            .join(format!("{PREFIX}{}-{}{SUFFIX}", utc_stamp(now), self.n));
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
            .open(&path)
            .map_err(|e| Refused::new("io", format!("cannot create the file: {}", e.kind())))?;
        let mut w = io::BufWriter::with_capacity(256 * 1024, file);
        write_header(
            &mut w,
            self.settings.linktype,
            self.settings.snaplen,
            &self.settings.interface,
        )
        .map_err(|e| Refused::new("io", format!("writing: {}", e.kind())))?;
        Ok((path, w))
    }

    fn room(&self, want: u64) -> Result<u64, Refused> {
        let (_, used) = self.usage();
        let left = self.settings.dir_max_bytes.saturating_sub(used);
        if left < 4096 {
            return Err(Refused::new(
                "no_space",
                format!(
                    "the pcap directory holds {used} bytes (cap {}); files expire after {} s",
                    self.settings.dir_max_bytes,
                    self.settings.retention.as_secs()
                ),
            ));
        }
        Ok(want.min(left))
    }

    /// A `last` request, first half (quick, under the lock): the packets of the last
    /// `seconds` from `buffer` (shared, not copied) and a new file. The caller writes it
    /// with [`Prepared::write`] without holding the lock.
    pub(crate) fn prepare_last(
        &mut self,
        req: &Request,
        buffer: &Buffer,
        offset: i128,
    ) -> Result<Prepared, Refused> {
        let max = self.room(req.max_bytes)?;
        let now = mono_now_ns();
        let since = now.saturating_sub(req.seconds * 1_000_000_000);
        let (packets, truncated) = buffer.select(since, &req.filter, max);
        let (path, w) = self.create()?;
        self.written += 1;
        Ok(Prepared {
            path,
            w,
            packets,
            truncated,
            offset,
            from_ns: since,
            to_ns: now,
            retention: self.settings.retention,
        })
    }

    /// Both halves at once (tests).
    #[cfg(test)]
    pub(crate) fn last(
        &mut self,
        req: &Request,
        buffer: &Buffer,
        offset: i128,
    ) -> Result<serde_json::Value, Refused> {
        self.prepare_last(req, buffer, offset)?.write()
    }

    /// A `next` request: a file that collects the packets of the next `seconds`.
    pub(crate) fn next(
        &mut self,
        req: &Request,
        offset: i128,
    ) -> Result<serde_json::Value, Refused> {
        if self.active.is_some() {
            return Err(Refused::new(
                "busy",
                "a `next` capture is already running; ask again when it ends",
            ));
        }
        let max = self.room(req.max_bytes)?;
        let (path, file) = self.create()?;
        let until_ns = mono_now_ns() + req.seconds * 1_000_000_000;
        let answer = serde_json::json!({
            "path": path.display().to_string(),
            "state": "writing",
            "until_unix_ms": to_unix_ns(until_ns, offset) / 1_000_000,
            "expires_unix_ms": to_unix_ns(until_ns, offset) / 1_000_000
                + u64::try_from(self.settings.retention.as_millis()).unwrap_or(0),
        });
        self.active = Some(Active {
            path,
            file,
            until_ns,
            filter: req.filter.clone(),
            max_bytes: max,
            bytes: HEADER_BYTES,
            packets: 0,
        });
        self.written += 1;
        Ok(answer)
    }

    /// A packet arrived: appended to a running `next` capture when it matches.
    pub(crate) fn on_packet(&mut self, p: &Packet, offset: i128) {
        let Some(a) = &mut self.active else { return };
        if p.ts_ns > a.until_ns {
            self.close();
            return;
        }
        if !a.filter.matches(p) {
            return;
        }
        let size = epb_len(p.data.len());
        if a.bytes + size > a.max_bytes {
            self.close();
            return;
        }
        if write_packet(&mut a.file, to_unix_ns(p.ts_ns, offset), p).is_err() {
            self.close();
            return;
        }
        a.bytes += size;
        a.packets += 1;
    }

    /// Ends a `next` capture whose time is up; call every poll.
    pub(crate) fn tick(&mut self) {
        if self
            .active
            .as_ref()
            .is_some_and(|a| mono_now_ns() > a.until_ns)
        {
            self.close();
        }
    }

    fn close(&mut self) {
        if let Some(mut a) = self.active.take() {
            let _ = a.file.flush();
            tracing::info!(
                packets = a.packets,
                bytes = a.bytes,
                "pcap: a `next` capture ended"
            );
        }
    }

    /// Whether a `next` capture is running.
    pub(crate) fn writing(&self) -> bool {
        self.active.is_some()
    }
}

/// Prepares the pcap directory before the capability drop: created if missing, a real
/// directory (not a symbolic link), mode 0700, owned by `owner` when given.
pub(crate) fn prepare_dir(dir: &Path, owner: Option<u32>) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if fs::symlink_metadata(dir).is_err() {
        fs::create_dir_all(dir)?;
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    if let Some(uid) = owner.filter(|u| *u != meta.uid())
        && let Err(e) = std::os::unix::fs::chown(dir, Some(uid), None)
    {
        tracing::warn!(error = %e, dir = %dir.display(), "the pcap directory keeps its owner");
    }
    if meta.mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet(ts_ns: u64, sport: u16, dport: u16, direction: u8) -> Packet {
        let rec = crate::packet::tests::record_v4(
            direction,
            6,
            ([10, 0, 0, 2], sport),
            ([10, 0, 0, 1], dport),
            0x18,
            b"hello",
        );
        let data = &rec[24..];
        Packet {
            ts_ns,
            skb_len: u32::try_from(data.len()).unwrap(),
            direction,
            l2_len: 14,
            ethertype: 0x0800,
            data: Arc::from(data),
        }
    }

    #[test]
    fn filters() {
        let p = tcp_packet(1, 40000, 443, 0);
        let yes = [
            "",
            "tcp",
            "ip",
            "port 443",
            "dst port 443",
            "src port 40000",
            "host 10.0.0.1",
            "src host 10.0.0.2",
            "tcp and port 443 and not udp",
            "not port 80",
        ];
        for f in yes {
            assert!(Filter::parse(f).unwrap().matches(&p), "{f}");
        }
        let no = [
            "udp",
            "ip6",
            "icmp",
            "port 80",
            "src port 443",
            "dst host 10.0.0.2",
            "not tcp",
        ];
        for f in no {
            assert!(!Filter::parse(f).unwrap().matches(&p), "{f}");
        }
        for bad in [
            "tcp or udp",
            "port",
            "port http",
            "host example.com",
            "portrange 1-2",
            "src tcp",
            "tcp port 443",
            "ether host 00:11:22:33:44:55",
            &"tcp and ".repeat(9),
            &"x".repeat(300),
        ] {
            assert!(Filter::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn buffer_bounds_by_bytes_and_age() {
        let mut b = Buffer::new(10 * (OVERHEAD + 59));
        for i in 0..100u64 {
            b.push(tcp_packet(i * 1_000_000, 40000, 443, 0));
        }
        assert_eq!(b.len(), 10);
        assert_eq!(b.evicted, 90);
        assert!(b.bytes() <= 10 * (OVERHEAD + 59));
        let mut b = Buffer::new(1 << 30);
        b.push(tcp_packet(0, 1, 2, 0));
        b.push(tcp_packet(301 * 1_000_000_000, 1, 2, 0));
        assert_eq!(b.len(), 1, "older than 300 s goes");
        let (sel, cut) = b.select(0, &Filter::default(), 1 << 20);
        assert_eq!((sel.len(), cut), (1, false));
        let (sel, cut) = b.select(0, &Filter::default(), HEADER_BYTES + 10);
        assert_eq!((sel.len(), cut), (0, true));
    }

    /// A minimal pcapng reader: the blocks, checked for lengths, byte order and EPBs.
    fn read_blocks(bytes: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 12 <= bytes.len() {
            let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
            assert_eq!(len % 4, 0, "blocks are padded to 4");
            let trailer = u32::from_le_bytes(bytes[at + len - 4..at + len].try_into().unwrap());
            assert_eq!(trailer as usize, len);
            out.push((kind, bytes[at + 8..at + len - 4].to_vec()));
            at += len;
        }
        assert_eq!(at, bytes.len());
        out
    }

    #[test]
    fn pcapng_layout() {
        let mut buf = Vec::new();
        write_header(&mut buf, 1, 65535, "veth-cap").unwrap();
        let p = tcp_packet(5, 40000, 443, 1);
        write_packet(&mut buf, 1_759_740_000_123_456_789, &p).unwrap();
        let blocks = read_blocks(&buf);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].0, 0x0A0D_0D0A);
        assert_eq!(&blocks[0].1[..4], &0x1A2B_3C4Du32.to_le_bytes());
        assert_eq!(blocks[1].0, 1);
        assert_eq!(u16::from_le_bytes([blocks[1].1[0], blocks[1].1[1]]), 1);
        let epb = &blocks[2].1;
        assert_eq!(blocks[2].0, 6);
        let hi = u64::from(u32::from_le_bytes(epb[4..8].try_into().unwrap()));
        let lo = u64::from(u32::from_le_bytes(epb[8..12].try_into().unwrap()));
        assert_eq!(hi << 32 | lo, 1_759_740_000_123_456_789);
        let cap = u32::from_le_bytes(epb[12..16].try_into().unwrap()) as usize;
        assert_eq!(cap, p.data.len());
        assert_eq!(&epb[20..20 + cap], &p.data[..]);
        // epb_flags: outbound.
        let opt = 20 + cap + pad4(cap);
        assert_eq!(&epb[opt..opt + 8], &[2, 0, 4, 0, 2, 0, 0, 0]);
        assert_eq!(epb_len(p.data.len()), blocks[2].1.len() as u64 + 12);
    }

    #[test]
    fn files_are_0600_capped_and_swept() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("iohr-pcap-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        prepare_dir(&dir, None).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let mut m = Manager::new(Settings {
            dir: dir.clone(),
            max_bytes: 1 << 20,
            dir_max_bytes: 1 << 20,
            retention: Duration::from_secs(3600),
            linktype: 1,
            snaplen: 65535,
            interface: "lo".into(),
        });
        let mut b = Buffer::new(1 << 20);
        let now = mono_now_ns();
        for i in 0..20u64 {
            b.push(tcp_packet(
                now - 1_000_000_000 + i,
                40000,
                if i % 2 == 0 { 443 } else { 80 },
                0,
            ));
        }
        let req = request(
            &serde_json::json!({"seconds": 30, "filter": "tcp and port 443"}),
            &m.settings,
        )
        .unwrap();
        let a = m.last(&req, &b, clock_offset_ns()).unwrap();
        assert_eq!(a["packets"], 10);
        assert_eq!(a["truncated"], false);
        let path = PathBuf::from(a["path"].as_str().unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let blocks = read_blocks(&fs::read(&path).unwrap());
        assert_eq!(blocks.len(), 12);
        // `next`: one at a time, closed by tick after its time.
        let n = request(
            &serde_json::json!({"seconds": 1, "mode": "next"}),
            &m.settings,
        )
        .unwrap();
        let a2 = m.next(&n, 0).unwrap();
        assert_eq!(m.next(&n, 0).unwrap_err().code, "busy");
        m.on_packet(&tcp_packet(mono_now_ns(), 1, 2, 0), 0);
        std::thread::sleep(Duration::from_millis(1100));
        m.tick();
        assert!(!m.writing());
        let blocks = read_blocks(&fs::read(a2["path"].as_str().unwrap()).unwrap());
        assert_eq!(blocks.len(), 3);
        // Bad requests.
        for bad in [
            serde_json::json!({"seconds": 0}),
            serde_json::json!({"seconds": 301}),
            serde_json::json!({"max_bytes": 2_000_000}),
            serde_json::json!({"filter": "tcp or udp"}),
            serde_json::json!({"mode": "forever"}),
        ] {
            assert_eq!(
                request(&bad, &m.settings).unwrap_err().code,
                "bad_request",
                "{bad}"
            );
        }
        // The directory's cap.
        m.settings.dir_max_bytes = 10;
        assert_eq!(m.last(&req, &b, 0).unwrap_err().code, "no_space");
        // Retention: nothing young goes, everything old does; foreign files stay.
        fs::write(dir.join("keep-me.txt"), b"x").unwrap();
        assert_eq!(m.sweep(), 0);
        m.settings.retention = Duration::ZERO;
        assert_eq!(m.sweep(), 2);
        assert!(dir.join("keep-me.txt").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stamps() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(1_791_288_000), "20261006T120000Z");
        assert!(ours("iohr-20261006T120000Z-1.pcapng"));
        assert!(!ours("../iohr-x.pcapng") && !ours("iohr-1.pcap") && !ours("other.pcapng"));
    }
}
