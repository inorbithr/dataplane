//! `host.pcie`: the PCI topology from `/sys/bus/pci/devices`: each device's parent
//! bridge (so "behind the chipset" is a path, not a guess), vendor and device (named
//! from `pci.ids` when the host has it), driver, the link's current and maximum speed and
//! width, and ASPM.
//!
//! ASPM has three sources, each reported for what it is: the global policy
//! (`/sys/module/pcie_aspm/parameters/policy`), the per-link `link/*_aspm` switches when
//! the kernel exposes them, and the Link Control register in config space. Config space
//! past the first 64 bytes needs `CAP_SYS_ADMIN`; without it the per-link state is "not
//! observed", never assumed.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::hwmon::is_pci_addr;
use super::sysfs::{Root, natural};

/// PCI switch upstream ports known to be a chipset's uplink: everything behind one shares
/// the chipset's single link to the CPU (and its heat).
pub const CHIPSET_UPLINKS: &[(u16, u16, &str)] = &[(
    0x1022,
    0x57ad,
    "AMD Matisse chipset upstream port (X570, TRX40)",
)];

/// A link's state, as the downstream device of the link reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    /// Current speed, MT/s (`16.0 GT/s` is 16000).
    pub speed_mts: Option<u32>,
    /// Current width (lanes).
    pub width: Option<u32>,
    /// The device's own maximum speed, MT/s.
    pub max_speed_mts: Option<u32>,
    /// The device's own maximum width.
    pub max_width: Option<u32>,
    /// What the link could train to: the lower of this device's and its port's maximum.
    pub capable_speed_mts: Option<u32>,
    /// The same for width.
    pub capable_width: Option<u32>,
    /// Trained below what both ends support (speed or width): a link problem.
    pub downgraded: bool,
    /// Running below the device's own maximum because its port offers less (a x4 card
    /// in a x2 slot): wiring, not a fault, but bandwidth the device cannot use.
    pub limited_by_port: bool,
}

/// ASPM on one link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Aspm {
    /// The `link/` switches the kernel exposes (`l1_aspm` = true), empty when none.
    pub sysfs: BTreeMap<String, bool>,
    /// What the device supports, from Link Capabilities (`l0s`, `l1`, `l0s_l1`, `none`).
    pub supported: Option<String>,
    /// What is enabled, from Link Control (`disabled`, `l0s`, `l1`, `l0s_l1`).
    pub enabled: Option<String>,
    /// Why config space was not read, when it was not.
    pub not_observed: Option<String>,
}

/// One PCI function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Device {
    /// `0000:41:00.0`.
    pub addr: String,
    /// The bridge above it, if it is behind one.
    pub parent: Option<String>,
    /// Every bridge above it, nearest last.
    pub ancestors: Vec<String>,
    /// The root complex (`pci0000:40`).
    pub root_complex: String,
    /// `0x1022`.
    pub vendor: u16,
    /// `0x57ad`.
    pub device: u16,
    /// The class code (`0x010802` is an NVMe controller).
    pub class: u32,
    /// From `pci.ids`.
    pub vendor_name: Option<String>,
    /// From `pci.ids`.
    pub device_name: Option<String>,
    /// The bound driver.
    pub driver: Option<String>,
    /// The PCIe port type from config space (`root_port`, `upstream`, `downstream`,
    /// `endpoint`, ...), when config space was readable.
    pub port_type: Option<String>,
    /// The link above it.
    pub link: Option<Link>,
    /// ASPM on that link.
    pub aspm: Aspm,
    /// This device is a known chipset uplink.
    pub chipset_uplink: Option<String>,
    /// Network interfaces on it, with their link speed (Mb/s; `None` when down).
    pub net: Vec<(String, Option<i64>)>,
}

impl Device {
    /// `1022:57ad`.
    #[must_use]
    pub fn ids(&self) -> String {
        format!("{:04x}:{:04x}", self.vendor, self.device)
    }

    /// A display name: pci.ids names, else the ids.
    #[must_use]
    pub fn name(&self) -> String {
        match (&self.vendor_name, &self.device_name) {
            (Some(v), Some(d)) => format!("{v} {d}"),
            (Some(v), None) => format!("{v} device {:04x}", self.device),
            _ => self.ids(),
        }
    }

    /// A bridge (class 0x0604).
    #[must_use]
    pub fn is_bridge(&self) -> bool {
        self.class >> 8 == 0x0604
    }
}

/// The whole topology.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Topology {
    /// Devices by address.
    pub devices: BTreeMap<String, Device>,
    /// The global ASPM policy (`default`, `performance`, `powersave`, ...), the bracketed one.
    pub aspm_policy: Option<String>,
    /// Whether config space past 64 bytes was readable (privilege).
    pub config_readable: bool,
    /// Where names came from (`/usr/share/misc/pci.ids`), if anywhere.
    pub ids_source: Option<String>,
}

impl Topology {
    /// Devices whose ancestors include `addr`.
    #[must_use]
    pub fn behind(&self, addr: &str) -> Vec<&Device> {
        self.devices
            .values()
            .filter(|d| d.ancestors.iter().any(|a| a == addr))
            .collect()
    }

    /// The chipset uplinks this host has.
    #[must_use]
    pub fn chipset_uplinks(&self) -> Vec<&Device> {
        self.devices
            .values()
            .filter(|d| d.chipset_uplink.is_some())
            .collect()
    }

    /// The chipset uplink a device is behind, if any.
    #[must_use]
    pub fn uplink_of(&self, addr: &str) -> Option<&Device> {
        let d = self.devices.get(addr)?;
        d.ancestors
            .iter()
            .filter_map(|a| self.devices.get(a))
            .find(|a| a.chipset_uplink.is_some())
    }
}

/// `pci.ids`, reduced to the ids asked for.
#[derive(Debug, Clone, Default)]
pub struct PciIds {
    vendors: BTreeMap<u16, String>,
    devices: BTreeMap<(u16, u16), String>,
}

impl PciIds {
    /// Where distributions put `pci.ids`.
    pub const PATHS: [&'static str; 3] = [
        "/usr/share/misc/pci.ids",
        "/usr/share/hwdata/pci.ids",
        "/usr/share/pci.ids",
    ];

    /// Parses the vendor and device lines of `text` for the ids in `want` (subsystems
    /// and the class section are skipped).
    #[must_use]
    pub fn parse(text: &str, want: &BTreeSet<(u16, u16)>) -> Self {
        let vendors_wanted: BTreeSet<u16> = want.iter().map(|(v, _)| *v).collect();
        let mut out = Self::default();
        let mut vendor: Option<u16> = None;
        for line in text.lines() {
            if line.starts_with('#') || line.is_empty() || line.starts_with("\t\t") {
                continue;
            }
            if line.starts_with("C ") {
                break;
            }
            if let Some(rest) = line.strip_prefix('\t') {
                let Some(v) = vendor else { continue };
                if let Some((id, name)) = rest.split_once("  ")
                    && let Ok(d) = u16::from_str_radix(id.trim(), 16)
                    && want.contains(&(v, d))
                {
                    out.devices.insert((v, d), name.trim().to_owned());
                }
                continue;
            }
            vendor = line.split_once("  ").and_then(|(id, name)| {
                let v = u16::from_str_radix(id.trim(), 16).ok()?;
                vendors_wanted.contains(&v).then(|| {
                    out.vendors.insert(v, name.trim().to_owned());
                    v
                })
            });
        }
        out
    }
}

/// `16.0 GT/s PCIe` → 16000; `2.5 GT/s` → 2500.
#[must_use]
pub fn parse_speed(s: &str) -> Option<u32> {
    let n = s.split_whitespace().next()?;
    let (int, frac) = n.split_once('.').unwrap_or((n, "0"));
    let int: u32 = int.parse().ok()?;
    let frac: u32 = frac.chars().next()?.to_digit(10)?;
    Some(int * 1000 + frac * 100)
}

fn aspm_bits(b: u32) -> &'static str {
    match b & 3 {
        0 => "disabled",
        1 => "l0s",
        2 => "l1",
        _ => "l0s_l1",
    }
}

/// What config space says about the link: port type, ASPM supported and enabled.
fn parse_config(cfg: &[u8]) -> Option<(String, String, String)> {
    let u16_at = |o: usize| cfg.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| {
        cfg.get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    if cfg.len() < 256 || u16_at(0x06)? & 0x10 == 0 {
        return None;
    }
    let mut ptr = usize::from(*cfg.get(0x34)? & 0xfc);
    for _ in 0..48 {
        if ptr < 0x40 {
            return None;
        }
        let id = *cfg.get(ptr)?;
        if id == 0x10 {
            let caps = u16_at(ptr + 2)?;
            let port = match (caps >> 4) & 0xf {
                0 => "endpoint",
                1 => "legacy_endpoint",
                4 => "root_port",
                5 => "upstream",
                6 => "downstream",
                7 => "pcie_to_pci_bridge",
                8 => "pci_to_pcie_bridge",
                9 => "rc_integrated_endpoint",
                10 => "rc_event_collector",
                _ => "other",
            };
            let lnkcap = u32_at(ptr + 0x0c)?;
            let lnkctl = u16_at(ptr + 0x10)?;
            let supported = match (lnkcap >> 10) & 3 {
                0 => "none",
                1 => "l0s",
                2 => "l1",
                _ => "l0s_l1",
            };
            return Some((
                port.to_owned(),
                supported.to_owned(),
                aspm_bits(u32::from(lnkctl)).to_owned(),
            ));
        }
        ptr = usize::from(*cfg.get(ptr + 1)? & 0xfc);
    }
    None
}

/// Reads the topology. `ids` names devices when given.
#[must_use]
#[allow(clippy::too_many_lines)] // one attribute after another
pub fn read(root: &Root, ids_text: Option<(&str, &str)>) -> Topology {
    let mut topo = Topology {
        aspm_policy: root
            .read("/sys/module/pcie_aspm/parameters/policy")
            .and_then(|p| {
                p.split_whitespace()
                    .find(|w| w.starts_with('['))
                    .map(|w| w.trim_matches(['[', ']']).to_owned())
            }),
        ..Topology::default()
    };
    let mut paths = BTreeMap::new();
    for addr in root.list("/sys/bus/pci/devices") {
        if !is_pci_addr(&addr) {
            continue;
        }
        let base = format!("/sys/bus/pci/devices/{addr}");
        let real = root.resolve(&base).unwrap_or_else(|| base.clone());
        let comps: Vec<&str> = real.split('/').collect();
        let root_complex = comps
            .iter()
            .find(|c| c.starts_with("pci"))
            .map_or_else(String::new, |c| (*c).to_owned());
        let mut ancestors: Vec<String> = comps
            .iter()
            .filter(|c| is_pci_addr(c))
            .map(|c| (*c).to_owned())
            .collect();
        ancestors.pop(); // itself
        let hex = |f: &str| root.int(&format!("{base}/{f}"));
        let speed = |f: &str| {
            root.read(&format!("{base}/{f}"))
                .and_then(|s| parse_speed(&s))
        };
        let width = |f: &str| {
            root.int(&format!("{base}/{f}"))
                .and_then(|w| u32::try_from(w).ok())
                .filter(|w| *w > 0)
        };
        let mut sysfs_aspm = BTreeMap::new();
        for f in root.list(&format!("{base}/link")) {
            if let Some(v) = root.int(&format!("{base}/link/{f}")) {
                sysfs_aspm.insert(f, v != 0);
            }
        }
        let cfg = root.bytes(&format!("{base}/config")).ok();
        let parsed = cfg.as_deref().and_then(parse_config);
        if cfg.as_ref().is_some_and(|c| c.len() >= 256) {
            topo.config_readable = true;
        }
        let not_observed = match (&cfg, &parsed) {
            (_, Some(_)) => None,
            (Some(c), None) if c.len() < 256 => Some(
                "config space past 64 bytes needs CAP_SYS_ADMIN; per-link ASPM not observed"
                    .to_owned(),
            ),
            (Some(_), None) => Some("no PCI Express capability".to_owned()),
            (None, None) => Some("config space not readable".to_owned()),
        };
        let vendor = hex("vendor")
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(0);
        let device = hex("device")
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(0);
        let mut net = Vec::new();
        for n in root.list(&format!("{base}/net")) {
            let s = root
                .int(&format!("{base}/net/{n}/speed"))
                .filter(|s| *s > 0);
            net.push((n, s));
        }
        paths.insert(
            addr.clone(),
            (speed("max_link_speed"), width("max_link_width")),
        );
        topo.devices.insert(
            addr.clone(),
            Device {
                parent: ancestors.last().cloned(),
                ancestors,
                root_complex,
                vendor,
                device,
                class: hex("class")
                    .and_then(|v| u32::try_from(v).ok())
                    .unwrap_or(0),
                vendor_name: None,
                device_name: None,
                driver: root.link_name(&format!("{base}/driver")),
                port_type: parsed.as_ref().map(|p| p.0.clone()),
                link: Some(Link {
                    speed_mts: speed("current_link_speed"),
                    width: width("current_link_width"),
                    max_speed_mts: speed("max_link_speed"),
                    max_width: width("max_link_width"),
                    capable_speed_mts: None,
                    capable_width: None,
                    downgraded: false,
                    limited_by_port: false,
                })
                .filter(|l| l.speed_mts.is_some() && l.width.is_some()),
                aspm: Aspm {
                    sysfs: sysfs_aspm,
                    supported: parsed.as_ref().map(|p| p.1.clone()),
                    enabled: parsed.as_ref().map(|p| p.2.clone()),
                    not_observed,
                },
                chipset_uplink: CHIPSET_UPLINKS
                    .iter()
                    .find(|(v, d, _)| *v == vendor && *d == device)
                    .map(|(_, _, n)| (*n).to_owned()),
                addr,
                net,
            },
        );
    }
    // Each link is reported once, at its lower end: endpoints, and an upstream port (the
    // only child of its parent). Root and downstream ports describe the link below them,
    // which their child reports.
    let mut children: BTreeMap<String, usize> = BTreeMap::new();
    for d in topo.devices.values() {
        if let Some(p) = &d.parent {
            *children.entry(p.clone()).or_default() += 1;
        }
    }
    for d in topo.devices.values_mut() {
        if !d.is_bridge() {
            continue;
        }
        let upper_end = match d.port_type.as_deref() {
            Some("upstream") => false,
            Some(_) => true,
            None => d
                .parent
                .as_ref()
                .is_none_or(|p| children.get(p).copied().unwrap_or(0) != 1),
        };
        if upper_end {
            d.link = None;
        }
    }
    // A link's capability is the lower of its two ends' maximums.
    for d in topo.devices.values_mut() {
        let port_max = d.parent.as_ref().and_then(|p| paths.get(p)).copied();
        if let Some(l) = &mut d.link {
            let (pm_speed, pm_width) = port_max.unwrap_or((None, None));
            l.capable_speed_mts = min_opt(l.max_speed_mts, pm_speed);
            l.capable_width = min_opt(l.max_width, pm_width);
            l.downgraded = matches!((l.speed_mts, l.capable_speed_mts), (Some(c), Some(m)) if c < m)
                || matches!((l.width, l.capable_width), (Some(c), Some(m)) if c < m);
            l.limited_by_port = !l.downgraded
                && (matches!((l.speed_mts, l.max_speed_mts), (Some(c), Some(m)) if c < m)
                    || matches!((l.width, l.max_width), (Some(c), Some(m)) if c < m))
                && port_max.is_some();
        }
    }
    if let Some((source, text)) = ids_text {
        let want: BTreeSet<(u16, u16)> = topo
            .devices
            .values()
            .map(|d| (d.vendor, d.device))
            .collect();
        let ids = PciIds::parse(text, &want);
        for d in topo.devices.values_mut() {
            d.vendor_name = ids.vendors.get(&d.vendor).cloned();
            d.device_name = ids.devices.get(&(d.vendor, d.device)).cloned();
        }
        topo.ids_source = Some(source.to_owned());
    }
    topo
}

fn min_opt(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    }
}

/// Reads `pci.ids` from the first place the host has it.
#[must_use]
pub fn host_ids(root: &Root) -> Option<(String, String)> {
    PciIds::PATHS.iter().find_map(|p| {
        let b = root.bytes(p).ok()?;
        Some(((*p).to_owned(), String::from_utf8_lossy(&b).into_owned()))
    })
}

/// Sorted addresses (for stable output).
#[must_use]
pub fn sorted(addrs: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = addrs.into_iter().collect();
    v.sort_by(|a, b| natural(a, b));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture() -> (Root, String) {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/host/trx40");
        (
            Root::at(&dir.join("root")),
            std::fs::read_to_string(dir.join("pci.ids")).unwrap(),
        )
    }

    #[test]
    fn speeds() {
        assert_eq!(parse_speed("16.0 GT/s PCIe"), Some(16_000));
        assert_eq!(parse_speed("2.5 GT/s"), Some(2_500));
        assert_eq!(parse_speed("Unknown"), None);
    }

    #[test]
    fn the_trx40_chipset_and_what_is_behind_it() {
        let (root, ids) = fixture();
        let t = read(&root, Some(("pci.ids", &ids)));
        assert_eq!(t.aspm_policy.as_deref(), Some("default"));
        let up = t.chipset_uplinks();
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].addr, "0000:41:00.0");
        assert_eq!(up[0].parent.as_deref(), Some("0000:40:01.1"));
        let behind: Vec<&str> = t
            .behind("0000:41:00.0")
            .into_iter()
            .map(|d| d.addr.as_str())
            .collect();
        for a in [
            "0000:43:00.0", // nvme5, root
            "0000:44:00.0", // nvme8, /mnt/development
            "0000:45:00.0", // nvme6, half of md1
            "0000:46:00.0", // AQC107
            "0000:47:00.0", // ASM1061 SATA
        ] {
            assert!(behind.contains(&a), "{a} is behind the chipset");
        }
        assert!(
            t.uplink_of("0000:4e:00.0").is_none(),
            "nvme7 is on CPU lanes"
        );
        let nic = &t.devices["0000:46:00.0"];
        assert!(nic.name().contains("AQC107"), "{}", nic.name());
        let l = nic.link.as_ref().unwrap();
        // The AQC107 (x4) sits in a x2 chipset port: limited by the port, not trained down.
        assert_eq!(
            (l.speed_mts, l.width, l.max_width, l.capable_width),
            (Some(8_000), Some(2), Some(4), Some(2))
        );
        assert!(!l.downgraded && l.limited_by_port);
        // ... and its Ethernet link is at 1 Gb/s.
        assert_eq!(nic.net, vec![("enp70s0".to_owned(), Some(1_000))]);
        // nvme6 likewise (x4 drive, x2 port); nvme5 (a Gen3 drive) matches its port.
        let n6 = t.devices["0000:45:00.0"].link.as_ref().unwrap();
        assert!(!n6.downgraded && n6.limited_by_port);
        let n5 = t.devices["0000:43:00.0"].link.as_ref().unwrap();
        assert!(!n5.downgraded && !n5.limited_by_port);
        // Downstream ports report no link of their own (their child does).
        assert!(t.devices["0000:42:03.0"].link.is_none());
        assert!(
            t.devices["0000:41:00.0"].link.is_some(),
            "the chipset uplink is x8 Gen4"
        );
        // Only the idle GPU runs below both ends (2.5 GT/s): dynamic link power
        // management, reported as is.
        let down: BTreeSet<&str> = t
            .devices
            .values()
            .filter(|d| d.link.as_ref().is_some_and(|l| l.downgraded))
            .map(|d| d.addr.as_str())
            .collect();
        assert_eq!(down, BTreeSet::from(["0000:4f:00.0", "0000:4f:00.1"]));
        // The fixture's config space was captured as root: ASPM is disabled on the uplink.
        assert!(t.config_readable);
        assert_eq!(up[0].aspm.enabled.as_deref(), Some("disabled"));
        assert_eq!(up[0].aspm.supported.as_deref(), Some("l1"));
        assert_eq!(up[0].port_type.as_deref(), Some("upstream"));
        let enabled: BTreeSet<&str> = t
            .devices
            .values()
            .filter_map(|d| d.aspm.enabled.as_deref())
            .collect();
        assert_eq!(
            enabled,
            BTreeSet::from(["disabled"]),
            "ASPM is off on every link"
        );
    }

    #[test]
    fn without_privilege_aspm_is_not_observed() {
        let mut cfg = vec![0u8; 64];
        cfg[0x06] = 0x10;
        assert!(parse_config(&cfg).is_none());
    }
}
