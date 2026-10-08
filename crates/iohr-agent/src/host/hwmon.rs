//! `host.hwmon`: every sensor under `/sys/class/hwmon` (temperatures, fans, voltages,
//! currents, power), with its chip, label, the device it belongs to and the thresholds
//! the driver exposes. Values stay in the kernel's units (milli-degrees, RPM,
//! millivolts, milliamps, microwatts) as integers.
//!
//! How it can fail: a driver may not expose a label (the sensor is then `temp1`), may
//! return an I/O error for a value (it is left out), or may report a sentinel for a
//! probe that is not connected (`asusec` reads -40 °C; such a reading is marked
//! implausible, never silently used).

use std::collections::BTreeMap;

use serde::Serialize;

use super::sysfs::{Root, natural};

/// What a sensor measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Temperature, milli-degrees Celsius.
    Temp,
    /// Fan speed, RPM.
    Fan,
    /// Voltage, millivolts.
    In,
    /// Current, milliamps.
    Curr,
    /// Power, microwatts.
    Power,
}

impl Kind {
    /// Every kind read.
    pub const ALL: [Self; 5] = [Self::Temp, Self::Fan, Self::In, Self::Curr, Self::Power];

    /// The sysfs prefix (`temp`, `fan`, `in`, `curr`, `power`).
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Temp => "temp",
            Self::Fan => "fan",
            Self::In => "in",
            Self::Curr => "curr",
            Self::Power => "power",
        }
    }

    /// The unit of the raw value.
    #[must_use]
    pub const fn unit(self) -> &'static str {
        match self {
            Self::Temp => "millicelsius",
            Self::Fan => "rpm",
            Self::In => "millivolts",
            Self::Curr => "milliamps",
            Self::Power => "microwatts",
        }
    }

    /// The divisor to the human unit (°C, RPM, V, A, W).
    #[must_use]
    pub const fn scale(self) -> i64 {
        match self {
            Self::Temp | Self::In | Self::Curr => 1_000,
            Self::Fan => 1,
            Self::Power => 1_000_000,
        }
    }

    /// The human unit.
    #[must_use]
    pub const fn human_unit(self) -> &'static str {
        match self {
            Self::Temp => "°C",
            Self::Fan => "RPM",
            Self::In => "V",
            Self::Curr => "A",
            Self::Power => "W",
        }
    }

    /// Parses `temp`, `fan`, `in`, `curr`, `power`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.prefix() == s)
    }
}

/// One sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sensor {
    /// What it measures.
    pub kind: Kind,
    /// Its index on the chip (`temp1` is 1).
    pub index: u32,
    /// Its label, or `temp1` when the driver gives none.
    pub label: String,
    /// The sysfs file of its value (`/sys/class/hwmon/hwmon11/temp1_input`).
    pub input_path: String,
    /// The value, in the kind's unit; `None` when the read failed.
    pub input: Option<i64>,
    /// Thresholds the driver exposes, by name (`min`, `max`, `crit`, `crit_hyst`,
    /// `lcrit`, `emergency`), implausible ones left out.
    pub thresholds: BTreeMap<String, i64>,
    /// The driver's alarm flag, when exposed.
    pub alarm: Option<bool>,
    /// Whether the value is plausible for its kind (a disconnected probe's sentinel is not).
    pub plausible: bool,
}

/// One hwmon chip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Chip {
    /// `hwmon11`: changes across boots; never a key.
    pub hwmon: String,
    /// The driver's chip name (`asusec`, `k10temp`, `nvme`).
    pub name: String,
    /// The name sensors are addressed by: the chip name, or for NVMe the controller
    /// (`nvme5`), or `name@<pci address>` when two chips share a name.
    pub alias: String,
    /// The device it belongs to, as a host path (`/sys/devices/...`), when it has one.
    pub device: Option<String>,
    /// The PCI address of that device or its nearest PCI ancestor.
    pub pci: Option<String>,
    /// The NVMe controller it reports for (`nvme5`), when it is an NVMe drive's sensor.
    pub nvme: Option<String>,
    /// Its sensors.
    pub sensors: Vec<Sensor>,
}

impl Chip {
    /// The key of a sensor on this chip: `asusec/temp/Chipset`.
    #[must_use]
    pub fn key(&self, s: &Sensor) -> String {
        format!("{}/{}/{}", self.alias, s.kind.prefix(), s.label)
    }
}

/// The last PCI address (`0000:41:00.0`) in a device path.
#[must_use]
pub fn pci_of(path: &str) -> Option<String> {
    path.split('/')
        .rev()
        .find(|c| is_pci_addr(c))
        .map(str::to_owned)
}

/// Whether `s` is a PCI address `dddd:bb:dd.f`.
#[must_use]
pub fn is_pci_addr(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 12
        && b[4] == b':'
        && b[7] == b':'
        && b[10] == b'.'
        && b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 4 | 7 | 10) || c.is_ascii_hexdigit())
}

fn plausible(kind: Kind, chip: &str, v: i64) -> bool {
    match kind {
        // asusec reports exactly -40 °C for a header with no probe.
        Kind::Temp if chip == "asusec" && v == -40_000 => false,
        Kind::Temp => (-30_000..=150_000).contains(&v),
        Kind::Fan => (0..=50_000).contains(&v),
        _ => true,
    }
}

fn threshold_plausible(kind: Kind, v: i64) -> bool {
    match kind {
        // NVMe drives report 65261.8 °C (0xFFFF Kelvin) and -273.1 °C for "no limit".
        Kind::Temp => (-60_000..=200_000).contains(&v),
        _ => true,
    }
}

/// Reads every chip under `/sys/class/hwmon`.
#[must_use]
pub fn read(root: &Root) -> Vec<Chip> {
    let mut chips = Vec::new();
    for hwmon in root.list("/sys/class/hwmon") {
        let base = format!("/sys/class/hwmon/{hwmon}");
        let Some(name) = root.read(&format!("{base}/name")) else {
            continue;
        };
        let device = root.resolve(&format!("{base}/device"));
        let real = root.resolve(&base).unwrap_or_else(|| base.clone());
        let controller = real
            .split('/')
            .collect::<Vec<_>>()
            .windows(2)
            .find(|w| w[0] == "nvme" && w[1].starts_with("nvme"))
            .map(|w| w[1].to_owned());
        let pci = device.as_deref().and_then(pci_of).or_else(|| pci_of(&real));
        let sensors = read_sensors(root, &base, &name);
        chips.push(Chip {
            hwmon,
            alias: name.clone(),
            name,
            device,
            pci,
            nvme: controller,
            sensors,
        });
    }
    // Aliases: NVMe chips by controller; any other repeated name by its PCI address (or
    // hwmon index when it has none).
    let mut count: BTreeMap<String, usize> = BTreeMap::new();
    for c in &chips {
        *count.entry(c.name.clone()).or_default() += 1;
    }
    for c in &mut chips {
        if let Some(n) = &c.nvme {
            c.alias.clone_from(n);
        } else if count.get(&c.name).copied().unwrap_or(0) > 1 {
            c.alias = format!("{}@{}", c.name, c.pci.as_deref().unwrap_or(&c.hwmon));
        }
    }
    chips
}

fn read_sensors(root: &Root, base: &str, chip: &str) -> Vec<Sensor> {
    let files = root.list(base);
    let mut out = Vec::new();
    for kind in Kind::ALL {
        let mut indices: Vec<u32> = files
            .iter()
            .filter_map(|f| {
                let rest = f.strip_prefix(kind.prefix())?;
                let (n, attr) = rest.split_once('_')?;
                (attr == "input").then(|| n.parse().ok()).flatten()
            })
            .collect();
        indices.sort_unstable();
        indices.dedup();
        for index in indices {
            let p = format!("{}{index}", kind.prefix());
            let input_path = format!("{base}/{p}_input");
            let input = root.int(&input_path);
            let label = root
                .read(&format!("{base}/{p}_label"))
                .unwrap_or_else(|| p.clone());
            let mut thresholds = BTreeMap::new();
            for t in ["min", "max", "crit", "crit_hyst", "lcrit", "emergency"] {
                if let Some(v) = root.int(&format!("{base}/{p}_{t}"))
                    && threshold_plausible(kind, v)
                {
                    thresholds.insert(t.to_owned(), v);
                }
            }
            let alarm = root.int(&format!("{base}/{p}_alarm")).map(|v| v != 0);
            out.push(Sensor {
                kind,
                index,
                label,
                input_path,
                plausible: input.is_some_and(|v| plausible(kind, chip, v)),
                input,
                thresholds,
                alarm,
            });
        }
    }
    out.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(a.index.cmp(&b.index))
            .then(natural(&a.label, &b.label))
    });
    out
}

/// A sensor named the way `checks.toml` names it: `chip/label` (the label, or `temp1`),
/// with the kind given separately; or a full key `chip/kind/label`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorRef {
    /// The chip's alias or name.
    pub chip: String,
    /// The kind.
    pub kind: Kind,
    /// The label (or `temp1`).
    pub label: String,
}

impl SensorRef {
    /// Parses `chip/label` (with `kind`) or `chip/kind/label`.
    ///
    /// # Errors
    /// The name is malformed.
    pub fn parse(s: &str, kind: Kind) -> Result<Self, String> {
        let bad = || {
            format!(
                "sensor {s:?} must be chip/label (\"asusec/Chipset\", \"nvme5/Composite\") or chip/kind/label"
            )
        };
        if s.is_empty() || s.len() > 128 || s.chars().any(char::is_control) {
            return Err(bad());
        }
        let parts: Vec<&str> = s.splitn(3, '/').collect();
        if parts.iter().any(|p| p.is_empty()) {
            return Err(bad());
        }
        match parts.as_slice() {
            [chip, label] if !chip.is_empty() && !label.is_empty() => Ok(Self {
                chip: (*chip).to_owned(),
                kind,
                label: (*label).to_owned(),
            }),
            [chip, k, label] if !chip.is_empty() && !label.is_empty() => {
                match Kind::parse(k) {
                    Some(k2) => Ok(Self {
                        chip: (*chip).to_owned(),
                        kind: k2,
                        label: (*label).to_owned(),
                    }),
                    // A label with a slash in it.
                    None => Ok(Self {
                        chip: (*chip).to_owned(),
                        kind,
                        label: format!("{k}/{label}"),
                    }),
                }
            }
            _ => Err(bad()),
        }
    }

    /// The canonical key, `chip/kind/label`.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}/{}/{}", self.chip, self.kind.prefix(), self.label)
    }

    /// Finds the sensor in a reading: by alias first, then by chip name when only one
    /// chip has it; by label, then by `temp1`-style name.
    ///
    /// # Errors
    /// No such sensor, or the chip name is ambiguous.
    pub fn find<'a>(&self, chips: &'a [Chip]) -> Result<(&'a Chip, &'a Sensor), String> {
        let by_alias: Vec<&Chip> = chips.iter().filter(|c| c.alias == self.chip).collect();
        let candidates = if by_alias.is_empty() {
            chips.iter().filter(|c| c.name == self.chip).collect()
        } else {
            by_alias
        };
        if candidates.len() > 1 {
            let names: Vec<&str> = candidates.iter().map(|c| c.alias.as_str()).collect();
            return Err(format!(
                "{} names {} chips; use one of {}",
                self.chip,
                candidates.len(),
                names.join(", ")
            ));
        }
        let chip = candidates
            .first()
            .ok_or_else(|| format!("no hwmon chip named {}", self.chip))?;
        let raw = &self.label;
        chip.sensors
            .iter()
            .find(|s| s.kind == self.kind && s.label == self.label)
            .or_else(|| {
                chip.sensors.iter().find(|s| {
                    s.kind == self.kind && format!("{}{}", s.kind.prefix(), s.index) == *raw
                })
            })
            .map(|s| (*chip, s))
            .ok_or_else(|| {
                format!(
                    "{} has no {} sensor labelled {}",
                    chip.alias,
                    self.kind.prefix(),
                    self.label
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture() -> Root {
        Root::at(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/host/trx40/root"))
    }

    #[test]
    fn the_trx40_chipset_sensor_reads_as_the_manual_reading() {
        let chips = read(&fixture());
        assert_eq!(chips.len(), 15, "hwmon0..hwmon14");
        let (chip, s) = SensorRef::parse("asusec/Chipset", Kind::Temp)
            .unwrap()
            .find(&chips)
            .unwrap();
        assert_eq!(chip.name, "asusec");
        assert_eq!(s.input, Some(107_000), "`sensors` printed +107.0°C");
        assert!(s.plausible);
        assert_eq!(chip.key(s), "asusec/temp/Chipset");
        let (_, fan) = SensorRef::parse("asusec/Chipset", Kind::Fan)
            .unwrap()
            .find(&chips)
            .unwrap();
        assert!(fan.input.unwrap() > 5_000, "the chipset fan runs flat out");
        // A header with no probe reads the -40 °C sentinel: kept, marked implausible.
        let (_, t) = SensorRef::parse("asusec/T_Sensor", Kind::Temp)
            .unwrap()
            .find(&chips)
            .unwrap();
        assert!(!t.plausible);
    }

    #[test]
    fn nvme_chips_are_named_by_controller_and_pinned_to_their_pci_device() {
        let chips = read(&fixture());
        let n5 = chips.iter().find(|c| c.alias == "nvme5").unwrap();
        assert_eq!(n5.pci.as_deref(), Some("0000:43:00.0"));
        let comp = n5.sensors.iter().find(|s| s.label == "Composite").unwrap();
        assert!(comp.thresholds.contains_key("crit"));
        // 0xFFFF Kelvin "limits" are dropped.
        let s1 = n5.sensors.iter().find(|s| s.label == "Sensor 1").unwrap();
        assert!(!s1.thresholds.contains_key("max"));
        // "nvme" alone is ambiguous.
        let e = SensorRef::parse("nvme/Composite", Kind::Temp)
            .unwrap()
            .find(&chips)
            .unwrap_err();
        assert!(e.contains("9 chips"), "{e}");
        let nic = chips.iter().find(|c| c.name == "enp70s0").unwrap();
        assert_eq!(nic.pci.as_deref(), Some("0000:46:00.0"));
    }

    #[test]
    fn sensor_names() {
        let r = SensorRef::parse("asusec/temp/Chipset", Kind::Fan).unwrap();
        assert_eq!(r.kind, Kind::Temp);
        assert_eq!(r.key(), "asusec/temp/Chipset");
        assert!(SensorRef::parse("asusec", Kind::Temp).is_err());
        assert!(SensorRef::parse("/x", Kind::Temp).is_err());
        assert!(is_pci_addr("0000:41:00.0"));
        assert!(!is_pci_addr("pci0000:40"));
    }
}
