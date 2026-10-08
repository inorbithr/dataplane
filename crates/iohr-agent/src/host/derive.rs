//! Derived host checks: deterministic conclusions over what the readers saw, each with a
//! verdict of `supported`, `not_supported` or `unknown` and the facts it rests on. They
//! never say more than the readings allow: a correlation is a correlation (not a cause),
//! and an association between a sensor and a component is stated with how it was made.
//!
//! - `behind_hot_component`: a mount whose disks sit behind a component (the chipset
//!   uplink, or the drive itself) whose temperature is at or past its threshold.
//! - `shared_uplink`: two or more roles (root, journal, md member, data) depend on one
//!   chipset uplink.
//! - `idle_cpu_lane_drive`: an NVMe drive on CPU lanes (not behind a chipset) that holds
//!   no mount and no array member: room to move a critical role off the chipset.
//! - `io_temp_correlation`: a disk's I/O rate against the chipset temperature over the
//!   sampled window (Pearson r; at least [`MIN_SAMPLES`] pairs).

#![allow(clippy::cast_precision_loss)] // display and statistics only

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::Snapshot;
use super::hwmon::{Chip, Kind, Sensor};
use super::sampler::Sampler;

/// Pairs needed before a correlation is judged.
pub const MIN_SAMPLES: usize = 12;
/// r at or above this is `supported`.
pub const R_SUPPORTED: f64 = 0.6;
/// |r| below this, with enough samples, is `not_supported`.
pub const R_NONE: f64 = 0.2;
/// The chipset threshold when no hwmon check names one (RFC 0094: warn 100 °C).
pub const DEFAULT_CHIPSET_WARN: i64 = 100_000;

/// A verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The readings support it.
    Supported,
    /// The readings speak against it.
    NotSupported,
    /// The readings do not decide it.
    Unknown,
}

impl Verdict {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::NotSupported => "not_supported",
            Self::Unknown => "unknown",
        }
    }
}

/// One derived finding.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// `behind_hot_component`, `shared_uplink`, `idle_cpu_lane_drive`, `io_temp_correlation`.
    pub check: &'static str,
    /// The entity it is about, as a host-relative key (`mount:/mnt/development`).
    pub subject: String,
    /// The verdict.
    pub verdict: Verdict,
    /// Why, in one sentence a person can check.
    pub reason: String,
    /// The facts it rests on (host-relative keys: `pci:0000:41:00.0`,
    /// `hwmon:asusec/temp/Chipset`, `nvme:nvme8`).
    pub cites: Vec<String>,
    /// A number behind it, where there is one (r × 1000 for a correlation).
    pub value: Option<i64>,
}

/// The chipset temperature sensor: a temperature labelled `Chipset` on a board chip.
/// The association is by label (the board vendor's own name for it), stated as such.
#[must_use]
pub fn chipset_sensor(chips: &[Chip]) -> Option<(&Chip, &Sensor)> {
    chips.iter().find_map(|c| {
        c.sensors
            .iter()
            .find(|s| s.kind == Kind::Temp && s.label.eq_ignore_ascii_case("chipset"))
            .map(|s| (c, s))
    })
}

fn c(v: i64) -> String {
    format!("{:.1} °C", v as f64 / 1000.0)
}

/// Every finding over one snapshot, with the sampler's window when there is one.
/// `chipset_warn` is the threshold for the chipset (a declared hwmon check's, or
/// [`DEFAULT_CHIPSET_WARN`]).
#[must_use]
#[allow(clippy::too_many_lines)] // four checks, one after another
pub fn derive(snap: &Snapshot, window: Option<&Sampler>, chipset_warn: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    let topo = &snap.pcie;
    let chipset = chipset_sensor(&snap.hwmon);
    let uplinks = topo.chipset_uplinks();
    let nvme_temp: BTreeMap<&str, (&Chip, &Sensor)> = snap
        .hwmon
        .iter()
        .filter_map(|c| {
            let s = c
                .sensors
                .iter()
                .find(|s| s.kind == Kind::Temp && s.label == "Composite")?;
            Some((c.nvme.as_deref()?, (c, s)))
        })
        .collect();

    // behind_hot_component, per mount.
    for m in &snap.storage.mounts {
        let subject = format!("mount:{}", m.mountpoint);
        let mut cites = Vec::new();
        let mut hot = Vec::new();
        let mut cool = Vec::new();
        let mut unknown = Vec::new();
        for pci in &m.pci {
            cites.push(format!("pci:{pci}"));
            if let Some(up) = topo.uplink_of(pci) {
                cites.push(format!("pci:{}", up.addr));
                match chipset {
                    Some((chip, s)) if s.plausible => {
                        let v = s.input.unwrap_or_default();
                        cites.push(format!("hwmon:{}", chip.key(s)));
                        let what = format!(
                            "{pci} is behind the chipset uplink {} and {} reads {} (threshold {})",
                            up.addr,
                            chip.key(s),
                            c(v),
                            c(chipset_warn)
                        );
                        if v >= chipset_warn {
                            hot.push(what);
                        } else {
                            cool.push(what);
                        }
                    }
                    _ => unknown.push(format!(
                        "{pci} is behind the chipset uplink {} but no plausible chipset temperature was read",
                        up.addr
                    )),
                }
            }
        }
        for d in &m.disks {
            let ctrl = snap
                .storage
                .disks
                .iter()
                .find(|x| &x.name == d)
                .and_then(|x| x.controller.clone());
            if let Some(ctrl) = ctrl
                && let Some((chip, s)) = nvme_temp.get(ctrl.as_str())
                && let Some(v) = s.input
            {
                cites.push(format!("hwmon:{}", chip.key(s)));
                let limit = s.thresholds.get("max").copied();
                match limit {
                    Some(l) if v >= l => hot.push(format!(
                        "{ctrl} reads {} at or past its own limit {}",
                        c(v),
                        c(l)
                    )),
                    Some(l) => cool.push(format!("{ctrl} reads {} (limit {})", c(v), c(l))),
                    None => {}
                }
            }
        }
        if hot.is_empty() && cool.is_empty() && unknown.is_empty() {
            continue;
        }
        cites.sort();
        cites.dedup();
        let (verdict, reason) = if !hot.is_empty() {
            (Verdict::Supported, hot.join("; "))
        } else if !unknown.is_empty() {
            (Verdict::Unknown, unknown.join("; "))
        } else {
            (Verdict::NotSupported, cool.join("; "))
        };
        out.push(Finding {
            check: "behind_hot_component",
            subject,
            verdict,
            reason: format!("{} ({}): {reason}", m.mountpoint, roles(&m.roles)),
            cites,
            value: None,
        });
    }

    // shared_uplink, per chipset uplink.
    for up in &uplinks {
        let mut deps: BTreeSet<String> = BTreeSet::new();
        let mut cites = vec![format!("pci:{}", up.addr)];
        for m in &snap.storage.mounts {
            if m.pci
                .iter()
                .any(|p| topo.uplink_of(p).is_some_and(|u| u.addr == up.addr))
            {
                deps.insert(format!("{} ({})", m.mountpoint, roles(&m.roles)));
                cites.push(format!("mount:{}", m.mountpoint));
            }
        }
        for d in &snap.storage.disks {
            let Some(md) = &d.md else { continue };
            for member in &md.members {
                let whole = snap
                    .storage
                    .disks
                    .iter()
                    .find(|x| &x.name == member || x.partitions.contains(member));
                if let Some(w) = whole
                    && let Some(p) = &w.pci
                    && topo.uplink_of(p).is_some_and(|u| u.addr == up.addr)
                {
                    deps.insert(format!("{} member {}", d.name, w.name));
                    cites.push(format!("md:{}", d.name));
                }
            }
        }
        let behind_net: Vec<String> = topo
            .behind(&up.addr)
            .into_iter()
            .flat_map(|d| d.net.iter().map(|(n, _)| n.clone()))
            .collect();
        for n in &behind_net {
            deps.insert(format!("network {n}"));
        }
        let verdict = if deps.len() >= 2 {
            Verdict::Supported
        } else {
            Verdict::NotSupported
        };
        cites.sort();
        cites.dedup();
        out.push(Finding {
            check: "shared_uplink",
            subject: format!("pci:{}", up.addr),
            verdict,
            reason: format!(
                "{} ({}) carries {} dependent(s): {}",
                up.addr,
                up.chipset_uplink.as_deref().unwrap_or("chipset uplink"),
                deps.len(),
                deps.into_iter().collect::<Vec<_>>().join(", ")
            ),
            cites,
            value: None,
        });
    }

    // idle_cpu_lane_drive, per NVMe controller.
    if !uplinks.is_empty() {
        for ctrl in &snap.storage.controllers {
            let Some(pci) = &ctrl.pci else { continue };
            if topo.uplink_of(pci).is_some() {
                continue;
            }
            let disks: Vec<&str> = snap
                .storage
                .disks
                .iter()
                .filter(|d| d.controller.as_deref() == Some(ctrl.name.as_str()))
                .map(|d| d.name.as_str())
                .collect();
            let used = disks.iter().any(|d| {
                !snap.storage.mounts_on(d).is_empty() || !snap.storage.arrays_of(d).is_empty()
            });
            if used {
                continue;
            }
            out.push(Finding {
                check: "idle_cpu_lane_drive",
                subject: format!("nvme:{}", ctrl.name),
                verdict: Verdict::Supported,
                reason: format!(
                    "{} ({}) is at {pci} on CPU lanes, not behind a chipset uplink, and holds no mount or array member",
                    ctrl.name,
                    ctrl.model.as_deref().unwrap_or("unknown model")
                ),
                cites: vec![format!("nvme:{}", ctrl.name), format!("pci:{pci}")],
                value: None,
            });
        }
    }

    // io_temp_correlation, per physical disk behind a chipset uplink.
    if let (Some(w), Some((chip, s))) = (window, chipset) {
        let key = chip.key(s);
        let temps: BTreeMap<u64, i64> = w.series(&key).into_iter().collect();
        for d in &snap.storage.disks {
            let Some(p) = &d.pci else { continue };
            if d.md.is_some() || topo.uplink_of(p).is_none() {
                continue;
            }
            let pairs: Vec<(f64, f64)> = w
                .io_series(&d.name)
                .into_iter()
                .filter_map(|(t, r)| {
                    let temp = temps.get(&t)?;
                    #[allow(clippy::cast_precision_loss)]
                    Some((
                        (r.read_bytes_per_s + r.write_bytes_per_s) as f64,
                        *temp as f64,
                    ))
                })
                .collect();
            let cites = vec![format!("block:{}", d.name), format!("hwmon:{key}")];
            let (verdict, reason, value) = match pearson(&pairs) {
                _ if pairs.len() < MIN_SAMPLES => (
                    Verdict::Unknown,
                    format!(
                        "{} I/O against {key}: {} paired samples, {MIN_SAMPLES} needed",
                        d.name,
                        pairs.len()
                    ),
                    None,
                ),
                None => (
                    Verdict::Unknown,
                    format!(
                        "{} I/O against {key}: one of the series did not vary over {} samples",
                        d.name,
                        pairs.len()
                    ),
                    None,
                ),
                Some(r) => {
                    #[allow(clippy::cast_possible_truncation)]
                    let milli = (r * 1000.0).round() as i64;
                    let verdict = if r >= R_SUPPORTED {
                        Verdict::Supported
                    } else if r.abs() < R_NONE {
                        Verdict::NotSupported
                    } else {
                        Verdict::Unknown
                    };
                    (
                        verdict,
                        format!(
                            "{} I/O against {key}: r = {r:.2} over {} samples (correlation, not cause)",
                            d.name,
                            pairs.len()
                        ),
                        Some(milli),
                    )
                }
            };
            out.push(Finding {
                check: "io_temp_correlation",
                subject: format!("block:{}", d.name),
                verdict,
                reason,
                cites,
                value,
            });
        }
    }
    out
}

fn roles(r: &[super::storage::Role]) -> String {
    r.iter().map(|x| x.as_str()).collect::<Vec<_>>().join("+")
}

/// Pearson's r; `None` when either series has no variance.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn pearson(pts: &[(f64, f64)]) -> Option<f64> {
    if pts.len() < 2 {
        return None;
    }
    let n = pts.len() as f64;
    let mx = pts.iter().map(|p| p.0).sum::<f64>() / n;
    let my = pts.iter().map(|p| p.1).sum::<f64>() / n;
    let sxy: f64 = pts.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
    let sxx: f64 = pts.iter().map(|p| (p.0 - mx).powi(2)).sum();
    let syy: f64 = pts.iter().map(|p| (p.1 - my).powi(2)).sum();
    (sxx > 0.0 && syy > 0.0).then(|| sxy / (sxx.sqrt() * syy.sqrt()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::sampler::tests::sample;
    use crate::host::{Options, snapshot};
    use std::time::Duration;

    fn fixture() -> Snapshot {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/host/trx40");
        snapshot(&Options {
            root: crate::host::sysfs::Root::at(&dir.join("root")),
            journal: false,
            ids: Some(std::fs::read_to_string(dir.join("pci.ids")).unwrap()),
        })
    }

    fn find<'a>(f: &'a [Finding], check: &str, subject: &str) -> &'a Finding {
        f.iter()
            .find(|x| x.check == check && x.subject == subject)
            .unwrap_or_else(|| panic!("no {check} for {subject}: {f:#?}"))
    }

    #[test]
    fn the_trx40_findings_are_the_manual_findings() {
        let snap = fixture();
        let f = derive(&snap, None, DEFAULT_CHIPSET_WARN);
        let root = find(&f, "behind_hot_component", "mount:/");
        assert_eq!(root.verdict, Verdict::Supported);
        assert!(root.reason.contains("0000:41:00.0"), "{}", root.reason);
        assert!(root.reason.contains("107.0 °C"), "{}", root.reason);
        assert_eq!(
            find(&f, "behind_hot_component", "mount:/mnt/development").verdict,
            Verdict::Supported
        );
        // md1 has a member behind the chipset.
        assert_eq!(
            find(&f, "behind_hot_component", "mount:/mnt/raid0").verdict,
            Verdict::Supported
        );
        // md0 is all on CPU lanes; its drives are below their own limits.
        assert_eq!(
            find(&f, "behind_hot_component", "mount:/mnt/fast").verdict,
            Verdict::NotSupported
        );
        let shared = find(&f, "shared_uplink", "pci:0000:41:00.0");
        assert_eq!(shared.verdict, Verdict::Supported);
        for dep in [
            "/ (root+journal)",
            "/mnt/development",
            "md1 member nvme6n1",
            "network enp70s0",
        ] {
            assert!(shared.reason.contains(dep), "{dep}: {}", shared.reason);
        }
        let idle = find(&f, "idle_cpu_lane_drive", "nvme:nvme7");
        assert_eq!(idle.verdict, Verdict::Supported);
        assert_eq!(
            f.iter()
                .filter(|x| x.check == "idle_cpu_lane_drive")
                .count(),
            1,
            "only nvme7 is idle on CPU lanes"
        );
        // A raised threshold turns the chipset finding around.
        let f = derive(&snap, None, 110_000);
        assert_eq!(
            find(&f, "behind_hot_component", "mount:/mnt/development").verdict,
            Verdict::NotSupported
        );
    }

    #[test]
    fn correlation_is_unknown_until_there_is_enough_and_honest_after() {
        let snap = fixture();
        let k = "asusec/temp/Chipset";
        let mut w = Sampler::new(
            crate::host::sysfs::Root::at(std::path::Path::new("/nonexistent")),
            Duration::from_secs(3600),
        );
        for i in 0..5u64 {
            w.push(sample(i * 10_000, k, 100_000, "nvme8n1", i * 1000));
        }
        let f = derive(&snap, Some(&w), DEFAULT_CHIPSET_WARN);
        let x = find(&f, "io_temp_correlation", "block:nvme8n1");
        assert_eq!(x.verdict, Verdict::Unknown);
        // Writes that rise with temperature.
        let mut w = Sampler::new(
            crate::host::sysfs::Root::at(std::path::Path::new("/nonexistent")),
            Duration::from_secs(3600),
        );
        let mut written = 0;
        for i in 0..20u64 {
            let burst = if i % 4 < 2 { 50_000 } else { 1_000 };
            written += burst;
            let temp = if i % 4 < 2 { 108_000 } else { 104_000 };
            w.push(sample(i * 10_000, k, temp, "nvme8n1", written));
        }
        let f = derive(&snap, Some(&w), DEFAULT_CHIPSET_WARN);
        let x = find(&f, "io_temp_correlation", "block:nvme8n1");
        assert_eq!(x.verdict, Verdict::Supported, "{}", x.reason);
        assert!(x.value.unwrap() >= 600);
        assert!(x.reason.contains("not cause"));
        assert_eq!(pearson(&[(1.0, 1.0), (1.0, 2.0)]), None);
    }
}
