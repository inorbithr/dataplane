# Host observers (`atlas observe host`, the `hwmon` check)

The agent can read the machine it runs on: sensors, the PCI topology, storage, pressure
and boots. Read-only, from `/sys` and `/proc`, unprivileged by default. It produces the
same typed evidence as the other Atlas observers ([atlas.md](atlas.md)): every fact
cites the reading it came from and the method that made it, and what could not be read
is recorded as not observed, with the reason, never guessed.

Why: on 2026-10-08 a production host hung twice. Finding the probable cause (the chipset
at 113 °C at both hangs, the root disk, the build disk, half of a RAID1 and the 10G NIC
all behind its one uplink, ASPM off, a spare NVMe on CPU lanes) took `sensors`, `lspci`,
sysfs, `/proc/mdstat` and the journal by hand. The agent now says all of it itself, and a
`hwmon` check can page before the next hang.

```sh
# policy.toml: [work] host = true   (and [host] journal = true for boot history)
iohr-agent atlas observe host --report --out host.jsonl
iohr-agent atlas observe host --samples 30 --interval 10 --report   # rates, correlations
```

Nothing is sent anywhere by `atlas observe host`. A summary goes to standard error, the
report with `--report`.

## What it reads

| Observer | Method (category) | Reads | Writes (predicates) | How it can fail |
|---|---|---|---|---|
| `host-hwmon-reader` | `host.hwmon.sysfs` (metrics) | `/sys/class/hwmon/*`: name, `*_input`, `*_label`, `*_min/max/crit/crit_hyst/lcrit/emergency`, `*_alarm`, the `device` link | `host.temp.millicelsius`, `host.fan.rpm`, `host.voltage.millivolts`, `host.current.milliamps`, `host.power.microwatts`, `host.sensor.threshold_*`, `host.sensor.plausible`, `host.sensor.of_device`; sampled: `host.sensor.rate_per_min`, `host.sensor.window_max` | no label (the sensor is `temp1`); a driver I/O error (value not observed); a disconnected probe's sentinel (`asusec` reads -40 °C: implausible, never a value); NVMe "limits" of 65261.8 °C are dropped |
| `host-pcie-reader` | `host.pcie.sysfs` (runtime state) | `/sys/bus/pci/devices/*`: the device path (parents), `vendor`, `device`, `class`, `driver`, `current/max_link_speed/width`, `link/*_aspm`, `config`; `/sys/module/pcie_aspm/parameters/policy`; `pci.ids` | `host.pci.parent`, `host.pci.ids`, `host.pci.name`, `host.pci.driver`, `host.pci.port_type`, `host.pci.chipset_uplink`, `host.pci.behind_chipset`, `host.pcie.link_*`, `host.pcie.link_downgraded`, `host.pcie.link_limited_by_port`, `host.pcie.aspm_enabled`, `host.pcie.aspm_supported`, `host.pcie.aspm_policy`, `host.net.link_speed_mbps` | per-link ASPM needs config space past 64 bytes (`CAP_SYS_ADMIN`); a chipset is named only from a known uplink id (AMD `1022:57ad` today), else nothing is said |
| `host-storage-reader` | `host.storage.sysfs` (runtime state) | `/sys/class/nvme`, `/sys/block`, `/sys/class/block` (`dev`, `partition`, `holders`, `slaves`, `md/*`), `/proc/mdstat`, `/proc/self/mountinfo` | `host.nvme.on_pci`, `host.nvme.model`, `host.nvme.serial` (pins a drive across boots; `nvmeN` numbering can change), `host.block.on_controller`, `host.block.partition_of`, `host.md.level`, `host.md.member`, `host.md.members_up`, `host.mount.device`, `host.mount.role` (`root`, `journal`, `boot`, `data`), `host.mount.on_disk` | SMART needs the NVMe admin command set (`CAP_SYS_ADMIN` and an ioctl the agent does not issue): not observed; device-mapper and network mounts have no physical disk |
| `host-diskstats-reader` | `host.storage.diskstats` (metrics) | `/proc/diskstats` | `host.io.*_total`; sampled: `host.io.read_bytes_per_s`, `write_bytes_per_s`, `busy_permille` | counters wrap on very old kernels |
| `host-pressure-reader` | `host.pressure.procfs` (metrics) | `/proc/pressure/{cpu,io,memory}`, `/proc/loadavg`, `/proc/meminfo`, `/proc/vmstat` | `host.psi.*_avg{10,60,300}_centipct`, `host.load.*`, `host.mem.*`, `host.swap.*`, `host.oom.kills_since_boot` | no PSI in the kernel (not observed); the kernel log is often restricted, so OOM kills come from the `oom_kill` counter |
| `host-boot-reader` | `host.boot.records` (logs) | `/proc/sys/kernel/random/boot_id`, `/proc/uptime`, `/var/log/wtmp` (type and time of reboot/shutdown records only), `/sys/class/watchdog/*`, and with `[host] journal = true`: `journalctl --list-boots` and each earlier boot's last 60 entries | `host.boot.ending` (`running`, `shutdown_recorded`, `no_shutdown_record`, `unknown`), `host.boot.first/last_entry_unix`, `host.watchdog.*_bootstatus`, `host.wtmp.boot_records` | the platform reset-reason register is not read (Linux 6.15 and later log it at boot on AMD; nothing exposes it in sysfs); "no shutdown record" is what the journal shows, not proof of a crash: a journal can lose its tail on a clean power-off too; some distributions no longer write wtmp boot records |
| `host-derive` | `host.derive` (deterministic extractor) | the readings above | `host.derived.<check>` = `supported` / `not_supported` / `unknown`, with `_reason` and, for a correlation, `_value` (r × 1000) | see below |

Entity keys: `host/<name>`, `hwmon/<name>/<chip>/<kind>/<label>`, `pci/<name>/<address>`,
`nvme/<name>/<controller>`, `block/<name>/<device>`, `mount/<name>:<path>`,
`net/<name>/<interface>`, `boot/<name>/<boot id>`.

## Derived checks

Each says what the readings support and cites them. None says more.

| Check | `supported` when | Otherwise |
|---|---|---|
| `behind_hot_component` (per mount) | a disk under the mount is behind a chipset uplink whose temperature is at or past the threshold, or the drive's own composite temperature is at or past its `max` | `not_supported` when every component was read and is below; `unknown` when a component's temperature could not be read |
| `shared_uplink` (per chipset uplink) | two or more of root, journal, boot, data mounts, md members and network interfaces depend on it | `not_supported` |
| `idle_cpu_lane_drive` (per NVMe drive) | the drive is on CPU lanes and holds no mount and no array member | not written |
| `io_temp_correlation` (per disk behind a chipset uplink) | Pearson r ≥ 0.6 between the disk's I/O rate and the chipset temperature over at least 12 samples | `not_supported` for \|r\| < 0.2 with enough samples; `unknown` with too few samples, no variance, or anything in between. A correlation, never a cause |

The chipset temperature is the sensor labelled `Chipset` on the board's chip (the board
vendor's own name for it); the association with the uplink is by that label, and the
reason says so. The threshold is the `warn` of a `hwmon` check on that sensor in
`checks.toml`, else `--chipset-warn`, else 100 °C (RFC 0094).

PCIe links: `downgraded` means the link trained below what both ends support (a fault, or
a GPU saving power at idle); `limited_by_port` means a device runs below its own maximum
because its port offers less (a x4 card in a x2 slot), which is wiring, not a fault.

## Privileges

| Run as | Gets |
|---|---|
| any user | everything above except per-link ASPM and SMART; boots only with `[host] journal` and journal access (`adm` or `systemd-journal`) |
| + `CAP_SYS_ADMIN` only | per-link ASPM from PCI config space (Link Capabilities and Link Control) |
| root | the same; SMART is still not read (no ioctl in this agent) |

For a one-off reading with ASPM, without running as root:

```sh
sudo setpriv --reuid=$(id -u) --regid=$(id -g) --init-groups \
  --inh-caps=+sys_admin --ambient-caps=+sys_admin \
  iohr-agent atlas observe host --report
```

The observer's authority in the evidence names the uid and is marked insufficient when a
gap is due to privilege, so Atlas does not read a missing fact as an absent one.

## While the agent runs

With `[work] host = true` the agent samples every hwmon `*_input` file and
`/proc/diskstats` every `[host] sample_secs` and keeps `[host] window_secs` in memory.
Chips are rediscovered every 30 samples (hwmon numbers change when a driver reloads).
Nothing is written to disk: after a restart or a reboot the window starts empty, and the
first `hwmon` run judges what the sampler has seen since.

Measured on the TRX40 host (48 threads, 15 hwmon chips, 52 sensors, 9 NVMe drives) at a
10 s interval: under 0.1 % of one core, 7 MB RSS, no disk reads or writes from sampling.

With `[share] host = true` too, the heartbeat carries a summary of the host on the first
beat and every fourth (a minute at the platform's 15 s; `host/summary.rs`, RFC 0102): load,
CPUs, memory, filesystems with their free space (`statvfs`) and read-only flag, up to 16
temperatures, `md` arrays and NVMe controller states. An array counts a member as failed
when `md` says it is degraded or its controller is no longer `live`; a RAID 0 or linear
array with a failed member is `failed`, any other `degraded`, and one whose filesystem the
kernel turned read-only is `read_only`. The platform keeps the latest on the agent and
shows it; paging comes from declared `hwmon` checks, whose monitors open incidents.

## Fixture

`crates/iohr-agent/tests/fixtures/host/trx40/` is that host's sysfs and procfs, captured
read-only on 2026-10-08: values copied, symbolic links kept relative so the topology
resolves inside the tree, no serial numbers, mountinfo limited to block devices, PCI
config space limited to the first 256 bytes (read as root, for the ASPM tests). `pci.ids`
there is an excerpt with only that host's devices. `sensors.txt` and `lspci-tv.txt` are the
manual outputs the tests are checked against. `tests/host_observe.rs` runs
`atlas observe host` on it end to end.
