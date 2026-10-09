//! Host observers: the machine the agent runs on, read from `/sys` and `/proc`. Read-only
//! and unprivileged by default; what needs privilege (PCI config space past 64 bytes for
//! per-link ASPM, the NVMe SMART log) is reported as not observed, with the reason. The
//! only program ever run is `journalctl`, and only when the policy allows it
//! (`[host] journal = true`). See `docs/host.md`.
//!
//! - [`hwmon`]: sensors (temperatures, fans, voltages) with thresholds;
//! - [`pcie`]: PCI topology, link speed and width, ASPM, chipset uplinks;
//! - [`storage`]: NVMe → PCI → block → `md` → mounts, roles, I/O counters;
//! - [`pressure`]: PSI, load, memory, swap, OOM kills;
//! - [`boot`]: boots and whether each ended with a recorded shutdown, watchdog;
//! - [`derive`]: deterministic findings over the above, with honest verdicts;
//! - [`sampler`]: a rolling window of sensor readings and disk counters;
//! - [`check`]: the `hwmon` threshold check judged on that window;
//! - [`summary`]: the coarse host summary the heartbeat carries under `[share] host`.

pub mod boot;
pub mod check;
pub mod derive;
pub mod hwmon;
pub mod pcie;
pub mod pressure;
pub mod report;
pub mod sampler;
pub mod storage;
pub mod summary;
pub mod sysfs;

use std::time::Instant;

use serde::Serialize;

use sysfs::Root;

/// What to read.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Where (`/`, or a captured tree).
    pub root: Root,
    /// The policy allows running `journalctl` (`[host] journal`).
    pub journal: bool,
    /// `pci.ids` text, when the caller has it (else the host's is looked for).
    pub ids: Option<String>,
}

/// One reading of the host.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    /// The host's name.
    pub host: String,
    /// The kernel release, when readable.
    pub kernel: Option<String>,
    /// Sensors.
    pub hwmon: Vec<hwmon::Chip>,
    /// PCI.
    pub pcie: pcie::Topology,
    /// Storage.
    pub storage: storage::Storage,
    /// Pressure.
    pub pressure: pressure::Pressure,
    /// Boots.
    pub boot: boot::BootHistory,
    /// How long the reading took, microseconds.
    pub read_us: u64,
}

/// Reads the host once.
#[must_use]
pub fn snapshot(opts: &Options) -> Snapshot {
    let t = Instant::now();
    let root = &opts.root;
    let host_ids = if opts.ids.is_none() {
        pcie::host_ids(root)
    } else {
        None
    };
    let ids = match (&opts.ids, &host_ids) {
        (Some(t), _) => Some(("given", t.as_str())),
        (None, Some((src, t))) => Some((src.as_str(), t.as_str())),
        (None, None) => None,
    };
    let pcie = pcie::read(root, ids);
    Snapshot {
        host: if root.is_host() {
            sysfs::host_name()
        } else {
            "fixture".to_owned()
        },
        kernel: root.read("/proc/sys/kernel/osrelease"),
        hwmon: hwmon::read(root),
        pcie,
        storage: storage::read(root),
        pressure: pressure::read(root),
        boot: boot::read(root, opts.journal),
        read_us: u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX),
    }
}
