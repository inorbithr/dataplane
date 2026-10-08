//! `atlas observe host`: the host readers' results as Atlas evidence. Each reader is an
//! observer (class direct sensor) with its own method; everything it read becomes one
//! artefact (the canonical JSON of the reading, by digest), and every fact cites it.
//! What could not be read is recorded as `host.not_observed` with the reason, and the
//! observer's authority is marked insufficient when the reason is privilege. Derived
//! findings come from a deterministic extractor and cite the readers' artefacts.

use iohr_evidence::evidence::EvidenceRef;
use iohr_evidence::ids::ArtifactObservationId;
use iohr_evidence::method::{CoverageModel, MethodCategory};
use iohr_evidence::observer::ObserverClass;
use iohr_evidence::vocabulary::Value;

use super::common::{Ctx, ObservedNow, method};
use super::record::Sink;
use crate::error::{Error, Result};
use crate::host::derive::{self, Finding};
use crate::host::sampler::Sampler;
use crate::host::{Snapshot, hwmon::Kind};

/// The methods, one per reader.
pub mod methods {
    /// Sensors.
    pub const HWMON: &str = "host.hwmon.sysfs";
    /// PCI topology and links.
    pub const PCIE: &str = "host.pcie.sysfs";
    /// Storage layout.
    pub const STORAGE: &str = "host.storage.sysfs";
    /// I/O counters.
    pub const DISKSTATS: &str = "host.storage.diskstats";
    /// PSI, load, memory.
    pub const PRESSURE: &str = "host.pressure.procfs";
    /// Boot records.
    pub const BOOT: &str = "host.boot.records";
    /// Derived findings.
    pub const DERIVE: &str = "host.derive";
}

fn principal() -> String {
    #[cfg(unix)]
    {
        format!("uid:{}", rustix::process::getuid().as_raw())
    }
    #[cfg(not(unix))]
    {
        "uid:unknown".to_owned()
    }
}

struct Reader {
    ctx: Ctx,
    artifact: ArtifactObservationId,
}

impl Reader {
    #[allow(clippy::too_many_arguments)]
    fn new<T: serde::Serialize>(
        sink: &mut Sink,
        clock: &ObservedNow,
        snap: &Snapshot,
        name: &str,
        method_name: &str,
        category: MethodCategory,
        part: &str,
        reading: &T,
        complete: bool,
        privileged_gap: bool,
    ) -> Result<Self> {
        let mut m = method(method_name, category)?;
        if !complete {
            m.coverage = CoverageModel::BestEffort;
        }
        let mut ctx = Ctx::new(
            sink,
            name,
            ObserverClass::DirectSensor,
            m,
            &principal(),
            &["read"],
            clock,
        )?;
        ctx.authority.sufficient = !privileged_gap;
        let bytes = serde_json::to_vec(reading)
            .map_err(|e| Error::Atlas(format!("cannot encode the {part} reading: {e}")))?;
        let boot = snap.boot.boot_id.as_deref().unwrap_or("unknown");
        let artifact = ctx.artifact(sink, &format!("host:{}/{part}@{boot}", snap.host), &bytes)?;
        Ok(Self { ctx, artifact })
    }

    fn put(&self, sink: &mut Sink, subject: &str, predicate: &str, value: Value) -> Result<()> {
        self.ctx
            .observe(sink, subject, predicate, value, &[self.artifact])
            .map(|_| ())
    }

    fn entity(&self, sink: &mut Sink, subject: &str, predicate: &str, object: &str) -> Result<()> {
        let id = sink.entity(object);
        self.put(sink, subject, predicate, Value::Entity(id))
    }
}

fn int<T: TryInto<i64>>(v: T) -> Value {
    Value::Int(v.try_into().unwrap_or(i64::MAX))
}

/// Entity keys for one host.
struct Keys<'a>(&'a str);

impl Keys<'_> {
    fn host(&self) -> String {
        format!("host/{}", self.0)
    }
    fn sensor(&self, key: &str) -> String {
        format!("hwmon/{}/{key}", self.0)
    }
    fn pci(&self, addr: &str) -> String {
        format!("pci/{}/{addr}", self.0)
    }
    fn nvme(&self, name: &str) -> String {
        format!("nvme/{}/{name}", self.0)
    }
    fn block(&self, name: &str) -> String {
        format!("block/{}/{name}", self.0)
    }
    fn mount(&self, path: &str) -> String {
        format!("mount/{}:{path}", self.0)
    }
    fn net(&self, name: &str) -> String {
        format!("net/{}/{name}", self.0)
    }
    fn boot(&self, id: &str) -> String {
        format!("boot/{}/{id}", self.0)
    }
    /// A finding's subject (`mount:/x`, `pci:addr`, `nvme:n`, `block:b`) as an entity key.
    fn subject(&self, s: &str) -> String {
        match s.split_once(':') {
            Some(("mount", p)) => self.mount(p),
            Some(("pci", a)) => self.pci(a),
            Some(("nvme", n)) => self.nvme(n),
            Some(("block", b)) => self.block(b),
            Some(("hwmon", k)) => self.sensor(k),
            Some(("md", m)) => self.block(m),
            _ => format!("host/{}/{s}", self.0),
        }
    }
}

fn temp_predicate(kind: Kind) -> &'static str {
    match kind {
        Kind::Temp => "host.temp.millicelsius",
        Kind::Fan => "host.fan.rpm",
        Kind::In => "host.voltage.millivolts",
        Kind::Curr => "host.current.milliamps",
        Kind::Power => "host.power.microwatts",
    }
}

/// Writes the evidence for one snapshot (and the window, when sampled) into `sink`;
/// returns the derived findings for a report.
///
/// # Errors
/// A record could not be built.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // one reader after another
pub fn observe(
    snap: &Snapshot,
    window: Option<&Sampler>,
    chipset_warn: i64,
    sink: &mut Sink,
    clock: &ObservedNow,
) -> Result<Vec<Finding>> {
    let k = Keys(&snap.host);
    let host = k.host();
    let mut refs: Vec<EvidenceRef> = Vec::new();

    // hwmon
    let r = Reader::new(
        sink,
        clock,
        snap,
        "host-hwmon-reader",
        methods::HWMON,
        MethodCategory::Metrics,
        "hwmon",
        &snap.hwmon,
        true,
        false,
    )?;
    refs.push(EvidenceRef::Artifact(r.artifact));
    for chip in &snap.hwmon {
        for s in &chip.sensors {
            let key = chip.key(s);
            let e = k.sensor(&key);
            r.entity(sink, &e, "host.sensor.on_host", &host)?;
            r.put(sink, &e, "host.sensor.chip", Value::Text(chip.name.clone()))?;
            if let Some(n) = &chip.nvme {
                r.entity(sink, &e, "host.sensor.of_device", &k.nvme(n))?;
            } else if let Some(p) = &chip.pci {
                r.entity(sink, &e, "host.sensor.of_device", &k.pci(p))?;
            }
            match s.input {
                Some(v) => r.put(sink, &e, temp_predicate(s.kind), Value::Int(v))?,
                None => r.put(
                    sink,
                    &e,
                    "host.not_observed",
                    Value::Text("value: the driver returned an error".into()),
                )?,
            }
            r.put(sink, &e, "host.sensor.plausible", Value::Bool(s.plausible))?;
            for (t, v) in &s.thresholds {
                r.put(
                    sink,
                    &e,
                    &format!("host.sensor.threshold_{t}"),
                    Value::Int(*v),
                )?;
            }
            if let Some(a) = s.alarm {
                r.put(sink, &e, "host.sensor.alarm", Value::Bool(a))?;
            }
            if let Some(w) = window {
                if let Some(rate) = w.rate_per_min(&key, crate::host::check::RATE_OVER) {
                    r.put(sink, &e, "host.sensor.rate_per_min", Value::Int(rate))?;
                }
                if let Some(peak) = w.extreme_since(&key, 0, false) {
                    r.put(sink, &e, "host.sensor.window_max", Value::Int(peak))?;
                }
            }
        }
    }

    // pcie
    let t = &snap.pcie;
    let mut r = Reader::new(
        sink,
        clock,
        snap,
        "host-pcie-reader",
        methods::PCIE,
        MethodCategory::RuntimeState,
        "pcie",
        t,
        t.config_readable,
        !t.config_readable,
    )?;
    if t.config_readable {
        // Config space past 64 bytes was readable: the process held CAP_SYS_ADMIN.
        r.ctx.authority.capabilities.push("cap_sys_admin".into());
        r.ctx.authority.capabilities.sort();
    }
    refs.push(EvidenceRef::Artifact(r.artifact));
    if let Some(p) = &t.aspm_policy {
        r.put(sink, &host, "host.pcie.aspm_policy", Value::Text(p.clone()))?;
    }
    if !t.config_readable {
        r.put(
            sink,
            &host,
            "host.not_observed",
            Value::Text(
                "pcie.aspm per link: config space past 64 bytes needs CAP_SYS_ADMIN".into(),
            ),
        )?;
    }
    for d in t.devices.values() {
        let e = k.pci(&d.addr);
        r.entity(sink, &e, "host.pci.on_host", &host)?;
        if let Some(p) = &d.parent {
            r.entity(sink, &e, "host.pci.parent", &k.pci(p))?;
        }
        r.put(sink, &e, "host.pci.ids", Value::Text(d.ids()))?;
        r.put(
            sink,
            &e,
            "host.pci.class",
            Value::Text(format!("0x{:06x}", d.class)),
        )?;
        if d.vendor_name.is_some() {
            r.put(sink, &e, "host.pci.name", Value::Text(d.name()))?;
        }
        if let Some(drv) = &d.driver {
            r.put(sink, &e, "host.pci.driver", Value::Text(drv.clone()))?;
        }
        if let Some(pt) = &d.port_type {
            r.put(sink, &e, "host.pci.port_type", Value::Text(pt.clone()))?;
        }
        if let Some(c) = &d.chipset_uplink {
            r.put(sink, &e, "host.pci.chipset_uplink", Value::Text(c.clone()))?;
        }
        if let Some(up) = t.uplink_of(&d.addr) {
            r.entity(sink, &e, "host.pci.behind_chipset", &k.pci(&up.addr))?;
        }
        if let Some(l) = &d.link {
            if let Some(v) = l.speed_mts {
                r.put(sink, &e, "host.pcie.link_speed_mts", int(v))?;
            }
            if let Some(v) = l.width {
                r.put(sink, &e, "host.pcie.link_width", int(v))?;
            }
            if let Some(v) = l.max_speed_mts {
                r.put(sink, &e, "host.pcie.link_max_speed_mts", int(v))?;
            }
            if let Some(v) = l.max_width {
                r.put(sink, &e, "host.pcie.link_max_width", int(v))?;
            }
            r.put(
                sink,
                &e,
                "host.pcie.link_downgraded",
                Value::Bool(l.downgraded),
            )?;
            r.put(
                sink,
                &e,
                "host.pcie.link_limited_by_port",
                Value::Bool(l.limited_by_port),
            )?;
        }
        if let Some(a) = &d.aspm.enabled {
            r.put(sink, &e, "host.pcie.aspm_enabled", Value::Text(a.clone()))?;
        }
        if let Some(a) = &d.aspm.supported {
            r.put(sink, &e, "host.pcie.aspm_supported", Value::Text(a.clone()))?;
        }
        for (f, on) in &d.aspm.sysfs {
            r.put(sink, &e, &format!("host.pcie.sysfs_{f}"), Value::Bool(*on))?;
        }
        for (n, speed) in &d.net {
            let ne = k.net(n);
            r.entity(sink, &ne, "host.net.on_device", &e)?;
            match speed {
                Some(s) => r.put(sink, &ne, "host.net.link_speed_mbps", Value::Int(*s))?,
                None => r.put(sink, &ne, "host.net.link_up", Value::Bool(false))?,
            }
        }
    }

    // storage
    let st = &snap.storage;
    let r = Reader::new(
        sink,
        clock,
        snap,
        "host-storage-reader",
        methods::STORAGE,
        MethodCategory::RuntimeState,
        "storage",
        &(&st.controllers, &st.disks, &st.mounts),
        st.smart_not_observed.is_none(),
        st.smart_not_observed.is_some(),
    )?;
    refs.push(EvidenceRef::Artifact(r.artifact));
    for c in &st.controllers {
        let e = k.nvme(&c.name);
        r.entity(sink, &e, "host.nvme.on_host", &host)?;
        if let Some(p) = &c.pci {
            r.entity(sink, &e, "host.nvme.on_pci", &k.pci(p))?;
        }
        if let Some(m) = &c.model {
            r.put(sink, &e, "host.nvme.model", Value::Text(m.clone()))?;
        }
        if let Some(f) = &c.firmware {
            r.put(sink, &e, "host.nvme.firmware", Value::Text(f.clone()))?;
        }
        if let Some(s) = &c.serial {
            r.put(sink, &e, "host.nvme.serial", Value::Text(s.clone()))?;
        }
        if let Some(s) = &c.state {
            r.put(sink, &e, "host.nvme.state", Value::Text(s.clone()))?;
        }
        if let Some(why) = &st.smart_not_observed {
            r.put(
                sink,
                &e,
                "host.not_observed",
                Value::Text(format!("smart: {why}")),
            )?;
        }
    }
    for d in &st.disks {
        let e = k.block(&d.name);
        r.entity(sink, &e, "host.block.on_host", &host)?;
        if let Some(c) = &d.controller {
            r.entity(sink, &e, "host.block.on_controller", &k.nvme(c))?;
        } else if let Some(p) = &d.pci {
            r.entity(sink, &e, "host.block.on_pci", &k.pci(p))?;
        }
        if let Some(s) = d.size_bytes {
            r.put(sink, &e, "host.block.size_bytes", int(s))?;
        }
        for p in &d.partitions {
            r.entity(sink, &k.block(p), "host.block.partition_of", &e)?;
        }
        if let Some(md) = &d.md {
            if let Some(l) = &md.level {
                r.put(sink, &e, "host.md.level", Value::Text(l.clone()))?;
            }
            if let Some(s) = &md.array_state {
                r.put(sink, &e, "host.md.array_state", Value::Text(s.clone()))?;
            }
            if let Some(s) = &md.mdstat {
                r.put(sink, &e, "host.md.members_up", Value::Text(s.clone()))?;
            }
            if let Some(dg) = md.degraded {
                r.put(sink, &e, "host.md.degraded", Value::Int(dg))?;
            }
            for m in &md.members {
                r.entity(sink, &e, "host.md.member", &k.block(m))?;
            }
        }
    }
    for m in &st.mounts {
        let e = k.mount(&m.mountpoint);
        r.entity(sink, &e, "host.mount.on_host", &host)?;
        r.entity(sink, &e, "host.mount.device", &k.block(&m.device))?;
        r.put(sink, &e, "host.mount.fstype", Value::Text(m.fstype.clone()))?;
        for role in &m.roles {
            r.put(
                sink,
                &e,
                "host.mount.role",
                Value::Text(role.as_str().into()),
            )?;
        }
        for d in &m.disks {
            r.entity(sink, &e, "host.mount.on_disk", &k.block(d))?;
        }
    }

    // I/O counters (and rates over the window).
    let r = Reader::new(
        sink,
        clock,
        snap,
        "host-diskstats-reader",
        methods::DISKSTATS,
        MethodCategory::Metrics,
        "diskstats",
        &st.io,
        true,
        false,
    )?;
    let names: std::collections::BTreeSet<&str> =
        st.disks.iter().map(|d| d.name.as_str()).collect();
    for (name, c) in &st.io {
        if !names.contains(name.as_str()) {
            continue;
        }
        let e = k.block(name);
        r.put(sink, &e, "host.io.sectors_read_total", int(c.sectors_read))?;
        r.put(
            sink,
            &e,
            "host.io.sectors_written_total",
            int(c.sectors_written),
        )?;
        r.put(sink, &e, "host.io.busy_ms_total", int(c.io_ms))?;
        if let Some(w) = window
            && let (Some(a), Some(b)) = (w.samples().front(), w.samples().back())
            && b.at_ms > a.at_ms
            && let (Some(x), Some(y)) = (a.io.get(name), b.io.get(name))
        {
            let rate = y.rates_since(x, b.at_ms - a.at_ms);
            r.put(
                sink,
                &e,
                "host.io.read_bytes_per_s",
                int(rate.read_bytes_per_s),
            )?;
            r.put(
                sink,
                &e,
                "host.io.write_bytes_per_s",
                int(rate.write_bytes_per_s),
            )?;
            r.put(sink, &e, "host.io.busy_permille", int(rate.busy_permille))?;
        }
    }

    // pressure
    let p = &snap.pressure;
    let r = Reader::new(
        sink,
        clock,
        snap,
        "host-pressure-reader",
        methods::PRESSURE,
        MethodCategory::Metrics,
        "pressure",
        p,
        p.psi_not_observed.is_none(),
        false,
    )?;
    refs.push(EvidenceRef::Artifact(r.artifact));
    for (name, psi) in &p.psi {
        let pre = format!("host.psi.{}", name.replace('/', "_"));
        r.put(
            sink,
            &host,
            &format!("{pre}_avg10_centipct"),
            Value::Int(psi.avg10),
        )?;
        r.put(
            sink,
            &host,
            &format!("{pre}_avg60_centipct"),
            Value::Int(psi.avg60),
        )?;
        r.put(
            sink,
            &host,
            &format!("{pre}_avg300_centipct"),
            Value::Int(psi.avg300),
        )?;
    }
    if let Some(why) = &p.psi_not_observed {
        r.put(
            sink,
            &host,
            "host.not_observed",
            Value::Text(format!("psi: {why}")),
        )?;
    }
    if let Some([a, b, c]) = p.load {
        r.put(sink, &host, "host.load.avg1_centi", Value::Int(a))?;
        r.put(sink, &host, "host.load.avg5_centi", Value::Int(b))?;
        r.put(sink, &host, "host.load.avg15_centi", Value::Int(c))?;
    }
    for (pred, v) in [
        ("host.mem.total_kib", p.mem_total_kib),
        ("host.mem.available_kib", p.mem_available_kib),
        ("host.swap.total_kib", p.swap_total_kib),
        ("host.swap.free_kib", p.swap_free_kib),
        ("host.oom.kills_since_boot", p.oom_kills),
    ] {
        if let Some(v) = v {
            r.put(sink, &host, pred, Value::Int(v))?;
        }
    }

    // boot
    let b = &snap.boot;
    let r = Reader::new(
        sink,
        clock,
        snap,
        "host-boot-reader",
        methods::BOOT,
        MethodCategory::Logs,
        "boot",
        b,
        b.journal_not_observed.is_none(),
        false,
    )?;
    refs.push(EvidenceRef::Artifact(r.artifact));
    if let Some(id) = &b.boot_id {
        let e = k.boot(&id.replace('-', ""));
        r.entity(sink, &e, "host.boot.of_host", &host)?;
        r.put(sink, &e, "host.boot.ending", Value::Text("running".into()))?;
        if let Some(u) = b.uptime_secs {
            r.put(sink, &e, "host.boot.uptime_secs", Value::Int(u))?;
        }
    }
    for boot in &b.boots {
        let e = k.boot(&boot.boot_id);
        r.entity(sink, &e, "host.boot.of_host", &host)?;
        r.put(
            sink,
            &e,
            "host.boot.ending",
            Value::Text(boot.ending.as_str().into()),
        )?;
        if let Some(f) = boot.first {
            r.put(sink, &e, "host.boot.first_entry_unix", Value::Int(f))?;
        }
        if let Some(l) = boot.last {
            r.put(sink, &e, "host.boot.last_entry_unix", Value::Int(l))?;
        }
    }
    if let Some(why) = &b.journal_not_observed {
        r.put(
            sink,
            &host,
            "host.not_observed",
            Value::Text(format!("journal: {why}")),
        )?;
    }
    if let Some(why) = &b.wtmp_not_observed {
        r.put(
            sink,
            &host,
            "host.not_observed",
            Value::Text(format!("wtmp: {why}")),
        )?;
    }
    let wtmp_boots = b.wtmp.iter().filter(|e| e.boot).count();
    r.put(sink, &host, "host.wtmp.boot_records", int(wtmp_boots))?;
    for w in &b.watchdogs {
        if let Some(s) = w.bootstatus {
            r.put(
                sink,
                &host,
                &format!("host.watchdog.{}_bootstatus", w.name),
                Value::Int(s),
            )?;
        }
    }

    // derived
    let findings = derive::derive(snap, window, chipset_warn);
    let m = method(methods::DERIVE, MethodCategory::RuntimeState)?;
    let ctx = Ctx::new(
        sink,
        "host-derive",
        ObserverClass::DeterministicExtractor,
        m,
        &principal(),
        &["derive"],
        clock,
    )?;
    for f in &findings {
        let e = k.subject(&f.subject);
        let pred = format!("host.derived.{}", f.check);
        ctx.observe_from(
            sink,
            &e,
            &pred,
            Value::Text(f.verdict.as_str().into()),
            &refs,
        )?;
        ctx.observe_from(
            sink,
            &e,
            &format!("{pred}_reason"),
            Value::Text(f.reason.clone()),
            &refs,
        )?;
        if let Some(v) = f.value {
            ctx.observe_from(sink, &e, &format!("{pred}_value"), Value::Int(v), &refs)?;
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas::record::Record;
    use crate::host::{Options, snapshot, sysfs::Root};

    #[test]
    fn the_trx40_reading_becomes_typed_evidence() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/host/trx40");
        let snap = snapshot(&Options {
            root: Root::at(&dir.join("root")),
            journal: false,
            ids: Some(std::fs::read_to_string(dir.join("pci.ids")).unwrap()),
        });
        let mut sink = Sink::default();
        let f = observe(
            &snap,
            None,
            derive::DEFAULT_CHIPSET_WARN,
            &mut sink,
            &ObservedNow::now(),
        )
        .unwrap();
        assert_ne!(f.len(), 0);
        let per = sink.per_method();
        for m in [
            methods::HWMON,
            methods::PCIE,
            methods::STORAGE,
            methods::DISKSTATS,
            methods::PRESSURE,
            methods::BOOT,
            methods::DERIVE,
        ] {
            assert!(per.get(m).copied().unwrap_or(0) > 0, "{m}: {per:?}");
        }
        let keys: Vec<&str> = sink
            .records()
            .iter()
            .filter_map(|r| match r {
                Record::Entity { key, .. } => Some(key.as_str()),
                _ => None,
            })
            .collect();
        assert!(keys.contains(&"hwmon/fixture/asusec/temp/Chipset"));
        assert!(keys.contains(&"pci/fixture/0000:41:00.0"));
        assert!(keys.contains(&"mount/fixture:/mnt/development"));
        // The journal was not allowed: recorded as not observed, never guessed.
        let not_observed = sink
            .records()
            .iter()
            .filter(|r| {
                matches!(r, Record::Observation(o) if o.statement().predicate.name.as_str() == "host.not_observed")
            })
            .count();
        assert!(not_observed > 0);
    }
}
