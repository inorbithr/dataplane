//! `host.storage`: NVMe controllers → PCI address → block devices → partitions → `md`
//! arrays → mounts, with each mount's role (root, journal, boot, data) and the physical
//! disks and PCI devices under it; I/O counters from `/proc/diskstats`.
//!
//! How it can fail: a mount through device-mapper or a network filesystem has no
//! physical disk here (it is listed with none); md state comes from both
//! `/sys/block/md*/md` and `/proc/mdstat` and is reported from whichever was readable.
//! An NVMe drive's SMART log needs the admin command set (`CAP_SYS_ADMIN` and an ioctl
//! this crate does not issue); without it, SMART is reported as not observed. The
//! drive's composite temperature is in `host.hwmon`.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::hwmon::pci_of;
use super::sysfs::Root;

/// One NVMe controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Controller {
    /// `nvme5`.
    pub name: String,
    /// Its PCI address.
    pub pci: Option<String>,
    /// Model, as the drive reports it.
    pub model: Option<String>,
    /// Firmware revision.
    pub firmware: Option<String>,
    /// Serial number: pins the drive across boots (`nvmeN` numbering can change).
    pub serial: Option<String>,
    /// `live`, `resetting`, `dead`, ...
    pub state: Option<String>,
}

/// A whole block device (disk, md array), with its partitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disk {
    /// `nvme5n1`, `md1`, `sda`.
    pub name: String,
    /// `259:12`.
    pub dev: Option<String>,
    /// Bytes.
    pub size_bytes: Option<u64>,
    /// Spinning.
    pub rotational: Option<bool>,
    /// The NVMe controller, for a namespace.
    pub controller: Option<String>,
    /// The PCI device it hangs off (directly or through a SATA controller).
    pub pci: Option<String>,
    /// Partitions (`nvme5n1p2`).
    pub partitions: Vec<String>,
    /// Devices built on it (an md array on a member).
    pub holders: Vec<String>,
    /// For an md array.
    pub md: Option<MdArray>,
}

/// An md array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MdArray {
    /// `raid1`.
    pub level: Option<String>,
    /// `clean`, `active`, ...
    pub array_state: Option<String>,
    /// Missing members.
    pub degraded: Option<i64>,
    /// Members (block devices: disks or partitions).
    pub members: Vec<String>,
    /// `[UU]` from `/proc/mdstat`.
    pub mdstat: Option<String>,
}

/// What a mount is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// `/`.
    Root,
    /// Holds `/var/log/journal` (the systemd journal).
    Journal,
    /// `/boot` or `/boot/efi`.
    Boot,
    /// Anything else.
    Data,
}

impl Role {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Journal => "journal",
            Self::Boot => "boot",
            Self::Data => "data",
        }
    }
}

/// One mount of a block device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mount {
    /// `/mnt/development`.
    pub mountpoint: String,
    /// The block device mounted (`nvme8n1p1`, `md1`).
    pub device: String,
    /// `ext4`.
    pub fstype: String,
    /// What it is for.
    pub roles: Vec<Role>,
    /// The physical disks under it (through partitions and md members).
    pub disks: Vec<String>,
    /// Their PCI devices.
    pub pci: Vec<String>,
}

/// Counters for one block device, from `/proc/diskstats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct IoCounters {
    /// Reads completed.
    pub reads: u64,
    /// Sectors read (512 bytes).
    pub sectors_read: u64,
    /// Writes completed.
    pub writes: u64,
    /// Sectors written.
    pub sectors_written: u64,
    /// Milliseconds spent doing I/O.
    pub io_ms: u64,
}

/// Rates between two counter readings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct IoRates {
    /// Bytes read per second.
    pub read_bytes_per_s: u64,
    /// Bytes written per second.
    pub write_bytes_per_s: u64,
    /// Operations per second.
    pub iops: u64,
    /// Time busy, per mille.
    pub busy_permille: u64,
}

impl IoCounters {
    /// Rates from `earlier` to `self` over `ms`.
    #[must_use]
    pub fn rates_since(&self, earlier: &Self, ms: u64) -> IoRates {
        let ms = ms.max(1);
        let per_s = |a: u64, b: u64| a.saturating_sub(b).saturating_mul(1000) / ms;
        IoRates {
            read_bytes_per_s: per_s(self.sectors_read, earlier.sectors_read) * 512,
            write_bytes_per_s: per_s(self.sectors_written, earlier.sectors_written) * 512,
            iops: per_s(self.reads + self.writes, earlier.reads + earlier.writes),
            busy_permille: (self.io_ms.saturating_sub(earlier.io_ms) * 1000 / ms).min(1000),
        }
    }
}

/// The storage layout.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Storage {
    /// NVMe controllers.
    pub controllers: Vec<Controller>,
    /// Whole block devices (loop and ram devices left out).
    pub disks: Vec<Disk>,
    /// Mounts of block devices.
    pub mounts: Vec<Mount>,
    /// Counters by device name.
    pub io: BTreeMap<String, IoCounters>,
    /// Why SMART was not observed (always set in this version unless a privileged
    /// reader filled it in).
    pub smart_not_observed: Option<String>,
}

impl Storage {
    /// The mounts whose disks include `disk`.
    #[must_use]
    pub fn mounts_on(&self, disk: &str) -> Vec<&Mount> {
        self.mounts
            .iter()
            .filter(|m| m.disks.iter().any(|d| d == disk))
            .collect()
    }

    /// The md arrays a disk (or one of its partitions) is a member of.
    #[must_use]
    pub fn arrays_of(&self, disk: &str) -> Vec<&Disk> {
        let parts: BTreeSet<String> = self
            .disks
            .iter()
            .find(|d| d.name == disk)
            .map(|d| {
                let mut s: BTreeSet<String> = d.partitions.iter().cloned().collect();
                s.insert(d.name.clone());
                s
            })
            .unwrap_or_default();
        self.disks
            .iter()
            .filter(|d| {
                d.md.as_ref()
                    .is_some_and(|m| m.members.iter().any(|x| parts.contains(x)))
            })
            .collect()
    }
}

fn skip(name: &str) -> bool {
    ["loop", "ram", "zram", "sr", "fd"]
        .iter()
        .any(|p| name.starts_with(p))
}

/// Parses `/proc/diskstats`.
#[must_use]
pub fn parse_diskstats(text: &str) -> BTreeMap<String, IoCounters> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 14 || skip(f[2]) {
            continue;
        }
        let n = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        out.insert(
            f[2].to_owned(),
            IoCounters {
                reads: n(3),
                sectors_read: n(5),
                writes: n(7),
                sectors_written: n(9),
                io_ms: n(12),
            },
        );
    }
    out
}

/// `/proc/mdstat`: array name → its member status (`[UU]`).
#[must_use]
pub fn parse_mdstat(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some((name, _)) = line.split_once(" : ") {
            let name = name.trim();
            current = name.starts_with("md").then(|| name.to_owned());
            continue;
        }
        if let Some(c) = &current
            && let Some(start) = line.rfind('[')
            && line.trim_end().ends_with(']')
        {
            let status = &line[start..].trim_end();
            if status.chars().all(|ch| matches!(ch, '[' | ']' | 'U' | '_')) {
                out.insert(c.clone(), (*status).to_owned());
                current = None;
            }
        }
    }
    out
}

/// Reads the layout. `mountinfo` is `/proc/self/mountinfo`'s text.
#[must_use]
#[allow(clippy::too_many_lines)] // one layer after another
pub fn read(root: &Root) -> Storage {
    let mut st = Storage {
        smart_not_observed: Some(
            "the NVMe SMART log needs the admin command set (CAP_SYS_ADMIN and an ioctl this agent does not issue); the composite temperature is in host.hwmon"
                .to_owned(),
        ),
        ..Storage::default()
    };
    for name in root.list("/sys/class/nvme") {
        let base = format!("/sys/class/nvme/{name}");
        let real = root.resolve(&base).unwrap_or_default();
        st.controllers.push(Controller {
            pci: pci_of(&real),
            model: root.read(&format!("{base}/model")),
            firmware: root.read(&format!("{base}/firmware_rev")),
            serial: root.read(&format!("{base}/serial")),
            state: root.read(&format!("{base}/state")),
            name,
        });
    }
    // dev (major:minor) → block name, and partition → disk.
    let mut by_dev: BTreeMap<String, String> = BTreeMap::new();
    let mut part_of: BTreeMap<String, String> = BTreeMap::new();
    for name in root.list("/sys/class/block") {
        if skip(&name) {
            continue;
        }
        let base = format!("/sys/class/block/{name}");
        if let Some(dev) = root.read(&format!("{base}/dev")) {
            by_dev.insert(dev, name.clone());
        }
        if root.exists(&format!("{base}/partition"))
            && let Some(real) = root.resolve(&base)
            && let Some(parent) = real.rsplit('/').nth(1)
        {
            part_of.insert(name.clone(), parent.to_owned());
        }
    }
    let mdstat = root
        .read("/proc/mdstat")
        .map(|t| parse_mdstat(&t))
        .unwrap_or_default();
    for name in root.list("/sys/block") {
        if skip(&name) {
            continue;
        }
        let base = format!("/sys/block/{name}");
        let real = root.resolve(&base).unwrap_or_default();
        let controller = real
            .split('/')
            .collect::<Vec<_>>()
            .windows(2)
            .find(|w| w[0] == "nvme")
            .map(|w| w[1].to_owned());
        let partitions: Vec<String> = part_of
            .iter()
            .filter(|(_, d)| **d == name)
            .map(|(p, _)| p.clone())
            .collect();
        let mut holders = root.list(&format!("{base}/holders"));
        for p in &partitions {
            holders.extend(root.list(&format!("/sys/class/block/{p}/holders")));
        }
        holders.sort();
        holders.dedup();
        let md = (name.starts_with("md") && !real.contains("/pci")).then(|| MdArray {
            level: root.read(&format!("{base}/md/level")),
            array_state: root.read(&format!("{base}/md/array_state")),
            degraded: root.int(&format!("{base}/md/degraded")),
            members: root.list(&format!("{base}/slaves")),
            mdstat: mdstat.get(&name).cloned(),
        });
        st.disks.push(Disk {
            dev: root.read(&format!("{base}/dev")),
            size_bytes: root
                .int(&format!("{base}/size"))
                .and_then(|s| u64::try_from(s).ok())
                .map(|s| s * 512),
            rotational: root
                .int(&format!("{base}/queue/rotational"))
                .map(|r| r != 0),
            controller,
            pci: pci_of(&real),
            partitions,
            holders,
            md,
            name,
        });
    }
    // Physical disks under a block device: a partition's disk, an md array's members' disks.
    let disk_names: BTreeSet<String> = st.disks.iter().map(|d| d.name.clone()).collect();
    let physical = |dev: &str| -> Vec<String> {
        let mut out = BTreeSet::new();
        let mut stack = vec![dev.to_owned()];
        let mut guard = 0;
        while let Some(d) = stack.pop() {
            guard += 1;
            if guard > 64 {
                break;
            }
            let whole = part_of.get(&d).cloned().unwrap_or(d);
            match st.disks.iter().find(|x| x.name == whole) {
                Some(x) if x.md.is_some() => {
                    stack.extend(x.md.iter().flat_map(|m| m.members.iter().cloned()));
                }
                Some(x) => {
                    out.insert(x.name.clone());
                }
                None if disk_names.contains(&whole) => {
                    out.insert(whole);
                }
                None => {}
            }
        }
        out.into_iter().collect::<Vec<_>>()
    };
    let mountinfo = root.read("/proc/self/mountinfo").unwrap_or_default();
    let mut mounts = Vec::new();
    for line in mountinfo.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(sep) = f.iter().position(|x| *x == "-") else {
            continue;
        };
        let (Some(dev), Some(mp), Some(fstype)) = (f.get(2), f.get(4), f.get(sep + 1)) else {
            continue;
        };
        let Some(device) = by_dev.get(*dev).cloned() else {
            continue;
        };
        let mountpoint = unescape(mp);
        let disks = physical(&device);
        let pci: Vec<String> = {
            let s: BTreeSet<String> = disks
                .iter()
                .filter_map(|d| st.disks.iter().find(|x| &x.name == d)?.pci.clone())
                .collect();
            s.into_iter().collect()
        };
        mounts.push(Mount {
            mountpoint,
            device,
            fstype: (*fstype).to_owned(),
            roles: Vec::new(),
            disks,
            pci,
        });
    }
    // Roles: the journal lives on the longest mountpoint that is a prefix of its path.
    let holder_of = |path: &str, mounts: &[Mount]| -> Option<usize> {
        mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                m.mountpoint == "/"
                    || path == m.mountpoint
                    || path.starts_with(&format!("{}/", m.mountpoint))
            })
            .max_by_key(|(_, m)| m.mountpoint.len())
            .map(|(i, _)| i)
    };
    let journal = holder_of("/var/log/journal", &mounts);
    for (i, m) in mounts.iter_mut().enumerate() {
        if m.mountpoint == "/" {
            m.roles.push(Role::Root);
        }
        if journal == Some(i) {
            m.roles.push(Role::Journal);
        }
        if m.mountpoint == "/boot" || m.mountpoint.starts_with("/boot/") {
            m.roles.push(Role::Boot);
        }
        if m.roles.is_empty() {
            m.roles.push(Role::Data);
        }
    }
    st.mounts = mounts;
    st.io = root
        .read("/proc/diskstats")
        .map(|t| parse_diskstats(&t))
        .unwrap_or_default();
    st
}

/// mountinfo escapes space, tab, newline and backslash as octal.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8)
        {
            out.push(char::from(v));
            i += 4;
            continue;
        }
        out.push(char::from(b[i]));
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture() -> Root {
        Root::at(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/host/trx40/root"))
    }

    #[test]
    fn the_trx40_layout_matches_the_manual_findings() {
        let st = read(&fixture());
        assert_eq!(st.controllers.len(), 9);
        let c = |n: &str| st.controllers.iter().find(|c| c.name == n).unwrap();
        assert_eq!(c("nvme5").pci.as_deref(), Some("0000:43:00.0"));
        assert_eq!(c("nvme8").pci.as_deref(), Some("0000:44:00.0"));
        assert_eq!(c("nvme6").pci.as_deref(), Some("0000:45:00.0"));
        assert_eq!(c("nvme7").pci.as_deref(), Some("0000:4e:00.0"));
        let m = |p: &str| st.mounts.iter().find(|m| m.mountpoint == p).unwrap();
        let root = m("/");
        assert_eq!(root.device, "nvme5n1p2");
        assert_eq!(root.disks, ["nvme5n1"]);
        assert_eq!(root.roles, [Role::Root, Role::Journal]);
        assert_eq!(m("/boot/efi").roles, [Role::Boot]);
        assert_eq!(m("/mnt/development").disks, ["nvme8n1"]);
        assert_eq!(m("/mnt/development").pci, ["0000:44:00.0"]);
        // md1 (RAID1) is nvme6n1 behind the chipset and nvme4n1 on CPU lanes.
        let raid = m("/mnt/raid0");
        assert_eq!(raid.device, "md1");
        assert_eq!(raid.disks, ["nvme4n1", "nvme6n1"]);
        let md1 = st.disks.iter().find(|d| d.name == "md1").unwrap();
        let md = md1.md.as_ref().unwrap();
        assert_eq!(md.level.as_deref(), Some("raid1"));
        assert_eq!(md.mdstat.as_deref(), Some("[UU]"));
        assert_eq!(st.arrays_of("nvme6n1")[0].name, "md1");
        // nvme7 is on a CPU lane and holds nothing mounted.
        assert_eq!(st.mounts_on("nvme7n1").len(), 0);
        assert_eq!(st.arrays_of("nvme7n1").len(), 0);
        assert!(st.io.contains_key("nvme5n1"));
        assert!(st.smart_not_observed.is_some());
    }

    #[test]
    fn rates_and_parsers() {
        let a = IoCounters {
            reads: 10,
            sectors_read: 100,
            writes: 0,
            sectors_written: 0,
            io_ms: 0,
        };
        let b = IoCounters {
            reads: 20,
            sectors_read: 300,
            writes: 10,
            sectors_written: 1000,
            io_ms: 500,
        };
        let r = b.rates_since(&a, 1000);
        assert_eq!(r.read_bytes_per_s, 200 * 512);
        assert_eq!(r.iops, 20);
        assert_eq!(r.busy_permille, 500);
        assert_eq!(unescape("/mnt/a\\040b"), "/mnt/a b");
        let md = parse_mdstat(
            "md0 : active raid0 a[0]\n      1 blocks 512k chunks\n\nmd1 : active raid1 b[0] c[1]\n      2 blocks [2/1] [U_]\n",
        );
        assert_eq!(md.get("md1").map(String::as_str), Some("[U_]"));
        assert!(!md.contains_key("md0"));
    }
}
