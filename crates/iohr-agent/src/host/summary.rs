//! The host summary the heartbeat carries to the platform (RFC 0102), when the policy says
//! `[share] host = true`: load, memory, filesystems and their free space, temperatures,
//! RAID arrays and NVMe controllers. Coarse numbers and short labels only: no process,
//! user, file, address or serial number leaves the machine through it. The platform keeps
//! the latest and shows it; alerting comes from declared `hwmon` checks.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::hwmon::{Chip, Kind};
use super::pressure::Pressure;
use super::storage::Storage;
use super::sysfs::Root;

/// The most filesystems, temperatures or controllers one summary carries (the platform's
/// bound).
pub const MAX_ITEMS: usize = 16;
/// The most arrays.
pub const MAX_ARRAYS: usize = 8;
/// The longest label.
const MAX_LABEL: usize = 64;

/// A filesystem's space: total, free to an unprivileged user, and free in all, bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    /// Size.
    pub total: u64,
    /// Free to an unprivileged user (`df`'s "Avail").
    pub available: u64,
    /// Free in all, root's reserve included.
    pub free: u64,
}

/// Reads a mount point's space (`statvfs`), on this host only.
#[must_use]
pub fn space(mountpoint: &str) -> Option<Space> {
    let s = rustix::fs::statvfs(mountpoint).ok()?;
    let unit = s.f_frsize;
    Some(Space {
        total: s.f_blocks.checked_mul(unit)?,
        available: s.f_bavail.checked_mul(unit)?,
        free: s.f_bfree.checked_mul(unit)?,
    })
}

/// The summary of this host now: what [`build`] makes of a fresh read.
#[must_use]
pub fn summary(root: &Root, chips: &[Chip]) -> Value {
    let storage = super::storage::read(root);
    let pressure = super::pressure::read(root);
    let mountinfo = root.read("/proc/self/mountinfo").unwrap_or_default();
    let cpus = root
        .read("/proc/cpuinfo")
        .map(|c| c.lines().filter(|l| l.starts_with("processor")).count())
        .filter(|n| *n > 0);
    let host = root.is_host();
    build(&Parts {
        chips,
        storage: &storage,
        pressure: &pressure,
        mountinfo: &mountinfo,
        cpus,
        space: &|mp| if host { space(mp) } else { None },
    })
}

/// What a summary is made from.
#[allow(missing_debug_implementations)] // holds a function
pub struct Parts<'a> {
    /// Sensors.
    pub chips: &'a [Chip],
    /// Storage.
    pub storage: &'a Storage,
    /// Load and memory.
    pub pressure: &'a Pressure,
    /// `/proc/self/mountinfo`, for each mount's read-only flag.
    pub mountinfo: &'a str,
    /// Logical CPUs.
    pub cpus: Option<usize>,
    /// A mount point's space.
    pub space: &'a dyn Fn(&str) -> Option<Space>,
}

fn label(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL)
        .collect()
}

/// Mount points mounted read-only, the kernel's own after an error (`emergency_ro`) too.
fn read_only_mounts(mountinfo: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in mountinfo.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(sep) = f.iter().position(|x| *x == "-") else {
            continue;
        };
        let opts = f.get(5).copied().unwrap_or_default();
        let sup = f.get(sep + 3).copied().unwrap_or_default();
        let ro = opts.split(',').any(|o| o == "ro")
            || sup.split(',').any(|o| o == "ro" || o == "emergency_ro");
        if ro && let Some(mp) = f.get(4) {
            out.insert(mp.replace("\\040", " "));
        }
    }
    out
}

/// The sensors worth a person's eye first: the chipset, the CPU, the drives.
fn rank(chip: &Chip, label: &str) -> u8 {
    let l = label.to_ascii_lowercase();
    if l.contains("chipset") {
        0
    } else if matches!(chip.name.as_str(), "k10temp" | "coretemp" | "zenpower") {
        1
    } else if chip.nvme.is_some() || chip.name == "nvme" {
        2
    } else {
        3
    }
}

/// `md`'s `array_state` as the platform's state.
fn array_state(state: Option<&str>) -> &'static str {
    match state.unwrap_or_default() {
        "readonly" | "read-auto" => "read_only",
        "inactive" | "broken" | "clear" => "failed",
        _ => "active",
    }
}

/// The summary, as the heartbeat's `host`.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::too_many_lines)] // shown numbers; one section after another
pub fn build(p: &Parts<'_>) -> Value {
    let mut out = serde_json::Map::new();
    if let Some([one, _, _]) = p.pressure.load {
        out.insert("load_1m".into(), json!(one as f64 / 100.0));
    }
    if let Some(n) = p.cpus {
        out.insert("cpus".into(), json!(n));
    }
    if let (Some(total), Some(avail)) = (p.pressure.mem_total_kib, p.pressure.mem_available_kib)
        && total > 0
    {
        let used = (total - avail.clamp(0, total)) * 100 / total;
        out.insert("memory_used_percent".into(), json!(used));
    }

    let ro = read_only_mounts(p.mountinfo);
    let mut seen = BTreeSet::new();
    let mut mounts: Vec<_> = p.storage.mounts.iter().collect();
    mounts.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));
    let mut disks = Vec::new();
    for m in mounts {
        if !seen.insert(m.device.clone()) || disks.len() >= MAX_ITEMS {
            continue;
        }
        let Some(s) = (p.space)(&m.mountpoint) else {
            continue;
        };
        let used = s.total.saturating_sub(s.free);
        let seen_size = used + s.available;
        let used_percent = if seen_size == 0 {
            0
        } else {
            (used * 100).div_ceil(seen_size).min(100)
        };
        disks.push(json!({
            "mount": label(&m.mountpoint),
            "used_percent": used_percent,
            "free_bytes": s.available,
            "read_only": ro.contains(&m.mountpoint),
        }));
    }
    if !disks.is_empty() {
        out.insert("disks".into(), Value::Array(disks));
    }

    let mut temps: Vec<(u8, i64, Value)> = Vec::new();
    for chip in p.chips {
        for s in &chip.sensors {
            let (Kind::Temp, true, Some(v)) = (s.kind, s.plausible, s.input) else {
                continue;
            };
            let name = label(&format!("{}/{}", chip.alias, s.label));
            let mut t = json!({"sensor": name, "celsius": v as f64 / 1000.0});
            if let Some(c) = s.thresholds.get("crit") {
                t["critical_celsius"] = json!(*c as f64 / 1000.0);
            }
            temps.push((rank(chip, &s.label), -v, t));
        }
    }
    temps.sort_by_key(|t| (t.0, t.1));
    if !temps.is_empty() {
        out.insert(
            "temperatures".into(),
            Value::Array(temps.into_iter().take(MAX_ITEMS).map(|t| t.2).collect()),
        );
    }

    let live = |disk: &str| -> bool {
        let Some(d) = p.storage.disks.iter().find(|d| d.name == disk) else {
            return false;
        };
        let Some(c) = &d.controller else {
            return true;
        };
        p.storage
            .controllers
            .iter()
            .find(|x| &x.name == c)
            .and_then(|x| x.state.as_deref())
            .is_none_or(|s| s == "live")
    };
    let mut arrays = Vec::new();
    for d in p.storage.disks.iter().filter(|d| d.md.is_some()) {
        let Some(md) = &d.md else { continue };
        let level = md.level.clone().unwrap_or_default();
        let devices = md.members.len();
        let gone = md.members.iter().filter(|m| !live(m)).count();
        let degraded = usize::try_from(md.degraded.unwrap_or(0)).unwrap_or(0);
        let failed = gone.max(degraded).min(devices);
        let mut state = array_state(md.array_state.as_deref());
        if failed > 0 && state == "active" {
            state = if matches!(level.as_str(), "raid0" | "linear") {
                "failed"
            } else {
                "degraded"
            };
        }
        let on_ro = p
            .storage
            .mounts
            .iter()
            .any(|m| m.device == d.name && ro.contains(&m.mountpoint));
        if on_ro && state == "active" {
            state = "read_only";
        }
        arrays.push(json!({
            "name": label(&d.name), "level": level, "state": state,
            "devices": devices, "failed_devices": failed,
        }));
        if arrays.len() >= MAX_ARRAYS {
            break;
        }
    }
    if !arrays.is_empty() {
        out.insert("arrays".into(), Value::Array(arrays));
    }

    let controllers: Vec<Value> = p
        .storage
        .controllers
        .iter()
        .filter_map(|c| {
            c.state
                .as_ref()
                .map(|s| json!({"name": label(&c.name), "state": s}))
        })
        .take(MAX_ITEMS)
        .collect();
    if !controllers.is_empty() {
        out.insert("controllers".into(), Value::Array(controllers));
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{hwmon, pressure, storage};

    fn trx40() -> Root {
        Root::at(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/host/trx40/root"),
        )
    }

    #[allow(clippy::unnecessary_wraps)] // the shape `Parts::space` takes
    fn plenty(_: &str) -> Option<Space> {
        Some(Space {
            total: 1000,
            available: 390,
            free: 400,
        })
    }

    #[test]
    fn a_healthy_trx40_reads_as_healthy() {
        let root = trx40();
        let (chips, st, pr) = (
            hwmon::read(&root),
            storage::read(&root),
            pressure::read(&root),
        );
        let mi = root.read("/proc/self/mountinfo").unwrap_or_default();
        let v = build(&Parts {
            chips: &chips,
            storage: &st,
            pressure: &pr,
            mountinfo: &mi,
            cpus: Some(48),
            space: &plenty,
        });
        assert_eq!(v["cpus"], 48);
        assert!(v["load_1m"].is_number(), "{v}");
        let temps = v["temperatures"].as_array().unwrap();
        assert!(temps.len() <= MAX_ITEMS);
        assert!(
            temps[0]["sensor"]
                .as_str()
                .unwrap()
                .to_ascii_lowercase()
                .contains("chipset"),
            "the chipset first: {}",
            temps[0]
        );
        let arrays = v["arrays"].as_array().unwrap();
        let md0 = arrays.iter().find(|a| a["name"] == "md0").unwrap();
        assert_eq!(md0["level"], "raid0");
        assert_eq!(md0["state"], "active");
        assert_eq!(
            (md0["devices"].as_u64(), md0["failed_devices"].as_u64()),
            (Some(4), Some(0))
        );
        let disks = v["disks"].as_array().unwrap();
        assert!(disks.iter().all(|d| d["read_only"] == false));
        assert_eq!(
            disks[0]["used_percent"], 61,
            "df's rounding: 600 used of 990 seen"
        );
        assert!(
            v["controllers"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["state"] == "live")
        );
        let text = v.to_string();
        for never in ["serial", "model", "firmware", "pci", "pid", "user"] {
            assert!(!text.contains(never), "{never} never leaves: {text}");
        }
    }

    /// RFC 0102, 2026-10-09 on this very machine: nvme0 dropped off the bus, `md0`
    /// (RAID 0 over nvme0 to nvme3) lost a member and its filesystem went read-only.
    #[test]
    fn the_day_nvme0_dropped_reads_as_a_failed_array() {
        let root = trx40();
        let (chips, mut st, pr) = (
            hwmon::read(&root),
            storage::read(&root),
            pressure::read(&root),
        );
        for c in &mut st.controllers {
            if c.name == "nvme0" {
                c.state = Some("dead".into());
            }
        }
        let mi = root
            .read("/proc/self/mountinfo")
            .unwrap_or_default()
            .replace("/mnt/fast rw,relatime", "/mnt/fast ro,relatime")
            .replace(
                "/dev/md0 rw,stripe=512",
                "/dev/md0 ro,stripe=512,emergency_ro",
            );
        let v = build(&Parts {
            chips: &chips,
            storage: &st,
            pressure: &pr,
            mountinfo: &mi,
            cpus: None,
            space: &plenty,
        });
        let md0 = v["arrays"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["name"] == "md0")
            .unwrap()
            .clone();
        assert_eq!(md0["state"], "failed", "a RAID 0 without a member: {md0}");
        assert_eq!(md0["failed_devices"], 1);
        let md1 = v["arrays"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["name"] == "md1")
            .unwrap()
            .clone();
        assert_eq!(md1["state"], "active", "the mirror is fine");
        let fast = v["disks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["mount"] == "/mnt/fast")
            .unwrap()
            .clone();
        assert_eq!(fast["read_only"], true);
        let nvme0 = v["controllers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "nvme0")
            .unwrap()
            .clone();
        assert_eq!(nvme0["state"], "dead");
        assert!(v.get("cpus").is_none());
    }

    #[test]
    fn without_space_a_mount_is_left_out() {
        let root = trx40();
        let (chips, st, pr) = (
            hwmon::read(&root),
            storage::read(&root),
            pressure::read(&root),
        );
        let v = build(&Parts {
            chips: &chips,
            storage: &st,
            pressure: &pr,
            mountinfo: "",
            cpus: None,
            space: &|_| None,
        });
        assert!(v.get("disks").is_none());
        assert_eq!(
            read_only_mounts("33 2 259:12 / / ro,relatime shared:1 - ext4 /dev/x rw"),
            BTreeSet::from(["/".to_owned()])
        );
    }
}
