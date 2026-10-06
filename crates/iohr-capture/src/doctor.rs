//! `iohr-capture doctor`: read-only checks that say whether capture can run on this host,
//! one line per requirement with the exact fix. The facts are read from `/proc`, `/sys`
//! and `/etc/group` once ([`Facts::gather`]); [`evaluate`] is a pure function of them, so every probe is
//! unit-tested with fixtures.

use std::{fmt::Write as _, fs, path::Path};

use serde::Serialize;

use crate::kernel::{self, Version};

/// Linux capability numbers (include/uapi/linux/capability.h).
const CAP_NET_ADMIN: u32 = 12;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Below this `RLIMIT_MEMLOCK` (kernels before 5.11), loading maps may fail.
const MEMLOCK_NEEDED: u64 = 64 * 1024 * 1024;

/// What the checks read, as raw file contents (`None` when the file is missing).
#[derive(Debug, Default, Clone)]
pub(crate) struct Facts {
    /// `/proc/sys/kernel/osrelease`.
    pub(crate) osrelease: Option<String>,
    /// `/sys/kernel/btf/vmlinux` exists.
    pub(crate) btf_vmlinux: bool,
    /// `/proc/self/mounts`.
    pub(crate) mounts: Option<String>,
    /// `/proc/self/status`.
    pub(crate) status: Option<String>,
    /// `/proc/self/limits`.
    pub(crate) limits: Option<String>,
    /// The interface asked for, and whether `/sys/class/net/<name>` exists.
    pub(crate) interface: Option<(String, bool)>,
    /// `/sys/kernel/security/lockdown`.
    pub(crate) lockdown: Option<String>,
    /// `/proc/sys/kernel/unprivileged_bpf_disabled`.
    pub(crate) unprivileged_bpf_disabled: Option<String>,
    /// `/sys/fs/cgroup/cgroup.controllers` exists (cgroup v2 at the usual place).
    pub(crate) cgroup2: bool,
    /// `/sys/fs/selinux/enforce`.
    pub(crate) selinux_enforce: Option<String>,
    /// `/sys/module/apparmor/parameters/enabled`.
    pub(crate) apparmor_enabled: Option<String>,
    /// `/etc/group`, for the aggregates socket's group.
    pub(crate) groups: Option<String>,
    /// The socket group asked for (`--socket-group`).
    pub(crate) socket_group: String,
}

impl Facts {
    /// Reads the facts from this host. Never writes anything.
    pub(crate) fn gather(interface: Option<&str>, socket_group: &str) -> Self {
        Self {
            socket_group: socket_group.to_owned(),
            ..Self::gather_from(Path::new("/"), interface)
        }
    }

    /// Reads the facts below `root` (a fixture tree in tests).
    pub(crate) fn gather_from(root: &Path, interface: Option<&str>) -> Self {
        let read = |p: &str| fs::read_to_string(root.join(p)).ok();
        let exists = |p: &str| root.join(p).exists();
        Self {
            osrelease: read("proc/sys/kernel/osrelease"),
            btf_vmlinux: exists("sys/kernel/btf/vmlinux"),
            mounts: read("proc/self/mounts"),
            status: read("proc/self/status"),
            limits: read("proc/self/limits"),
            interface: interface.map(|name| {
                let valid = !name.is_empty() && !name.contains('/') && name != "." && name != "..";
                (
                    name.to_owned(),
                    valid && exists(&format!("sys/class/net/{name}")),
                )
            }),
            lockdown: read("sys/kernel/security/lockdown"),
            unprivileged_bpf_disabled: read("proc/sys/kernel/unprivileged_bpf_disabled"),
            cgroup2: exists("sys/fs/cgroup/cgroup.controllers"),
            selinux_enforce: read("sys/fs/selinux/enforce"),
            apparmor_enabled: read("sys/module/apparmor/parameters/enabled"),
            groups: read("etc/group"),
            socket_group: "iohr-agent".into(),
        }
    }
}

/// Outcome of one check. Only `Fail` stops capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Status {
    Pass,
    Info,
    Warn,
    Fail,
}

/// One requirement, its outcome, what was found and, unless it passed, the fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Check {
    pub(crate) name: &'static str,
    pub(crate) status: Status,
    pub(crate) detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fix: Option<String>,
}

impl Check {
    fn new(name: &'static str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
            fix: None,
        }
    }

    fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// True when no check failed: capture can run (warnings are limits of later layers).
pub(crate) fn can_run(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.status != Status::Fail)
}

/// Every check, in a fixed order.
pub(crate) fn evaluate(facts: &Facts) -> Vec<Check> {
    let version = facts.osrelease.as_deref().and_then(Version::parse);
    vec![
        check_kernel(facts.osrelease.as_deref(), version),
        check_btf(facts.btf_vmlinux),
        check_attach(version),
        check_bpffs(facts.mounts.as_deref()),
        check_capabilities(facts.status.as_deref()),
        check_memlock(version, facts.limits.as_deref()),
        check_interface(facts.interface.as_ref()),
        check_lockdown(facts.lockdown.as_deref()),
        check_unprivileged_bpf(version, facts.unprivileged_bpf_disabled.as_deref()),
        check_cgroup2(facts.cgroup2),
        check_lsm(
            facts.selinux_enforce.as_deref(),
            facts.apparmor_enabled.as_deref(),
        ),
        check_owners(version, facts.cgroup2),
        check_socket_group(facts.groups.as_deref(), &facts.socket_group),
    ]
}

/// Human-readable lines: `PASS  name  detail`, then `      fix: ...` where there is one,
/// and a last line with the verdict.
pub(crate) fn render(checks: &[Check]) -> String {
    let mut out = String::new();
    for c in checks {
        let tag = match c.status {
            Status::Pass => "PASS",
            Status::Info => "INFO",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        };
        let _ = writeln!(out, "{tag}  {:<22}{}", c.name, c.detail);
        if let Some(fix) = &c.fix {
            let _ = writeln!(out, "      {:<22}fix: {fix}", "");
        }
    }
    if can_run(checks) {
        out.push_str("capture can run on this host");
    } else {
        out.push_str("capture cannot run on this host: fix the FAIL lines above");
    }
    out
}

fn check_kernel(release: Option<&str>, version: Option<Version>) -> Check {
    match version {
        Some(v) if v >= kernel::MINIMUM => Check::new(
            "kernel",
            Status::Pass,
            format!("Linux {v} (5.8 or newer needed)"),
        ),
        Some(v) => Check::new(
            "kernel",
            Status::Fail,
            format!("Linux {v} is older than 5.8"),
        )
        .fix("upgrade to a kernel 5.8 or newer (any current LTS distribution kernel)"),
        None => Check::new(
            "kernel",
            Status::Fail,
            format!(
                "cannot read the kernel version ({})",
                release.map_or("no /proc/sys/kernel/osrelease", str::trim)
            ),
        )
        .fix("run on Linux with /proc mounted"),
    }
}

fn check_btf(present: bool) -> Check {
    if present {
        Check::new("btf", Status::Pass, "/sys/kernel/btf/vmlinux present")
    } else {
        Check::new("btf", Status::Fail, "/sys/kernel/btf/vmlinux missing")
            .fix("use a kernel built with CONFIG_DEBUG_INFO_BTF=y (default on Ubuntu 20.10+, Debian 11+, RHEL 8.2+, Fedora 31+); in a container, mount /sys/kernel/btf read-only")
    }
}

fn check_attach(version: Option<Version>) -> Check {
    match version {
        Some(v) if v >= kernel::TCX => Check::new(
            "tc attach",
            Status::Pass,
            "TCX links (Linux 6.6+): removed by the kernel when the process exits",
        ),
        Some(_) => Check::new(
            "tc attach",
            Status::Pass,
            "netlink filters (before Linux 6.6): removed on exit; after a crash by `iohr-capture cleanup` (the unit's ExecStopPost)",
        ),
        None => Check::new("tc attach", Status::Info, "unknown kernel version"),
    }
}

/// True when a `bpf` filesystem is mounted (field 3 of a mounts line).
fn bpffs_mounted(mounts: &str) -> bool {
    mounts
        .lines()
        .any(|line| line.split_whitespace().nth(2) == Some("bpf"))
}

fn check_bpffs(mounts: Option<&str>) -> Check {
    if mounts.is_some_and(bpffs_mounted) {
        Check::new("bpffs", Status::Pass, "bpf filesystem mounted")
    } else {
        Check::new(
            "bpffs",
            Status::Info,
            "no bpf filesystem mounted; not needed yet (nothing is pinned in this version)",
        )
        .fix("mount -t bpf bpf /sys/fs/bpf (systemd mounts it by default)")
    }
}

/// The effective capability mask from `/proc/self/status` (`CapEff:` in hex).
fn effective_capabilities(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let hex = line.strip_prefix("CapEff:")?.trim();
        u64::from_str_radix(hex, 16).ok()
    })
}

fn check_capabilities(status: Option<&str>) -> Check {
    let Some(mask) = status.and_then(effective_capabilities) else {
        return Check::new(
            "capabilities",
            Status::Fail,
            "cannot read CapEff from /proc/self/status",
        )
        .fix("run on Linux with /proc mounted");
    };
    let missing: Vec<&str> = [
        (CAP_BPF, "CAP_BPF"),
        (CAP_PERFMON, "CAP_PERFMON"),
        (CAP_NET_ADMIN, "CAP_NET_ADMIN"),
    ]
    .into_iter()
    .filter(|(bit, _)| mask & (1u64 << bit) == 0)
    .map(|(_, name)| name)
    .collect();
    if missing.is_empty() {
        Check::new(
            "capabilities",
            Status::Pass,
            "CAP_BPF, CAP_PERFMON and CAP_NET_ADMIN present (dropped right after attaching)",
        )
    } else {
        Check::new("capabilities", Status::Fail, format!("missing {}", missing.join(", ")))
            .fix("run it from the iohr-capture systemd unit, or as root (sudo iohr-capture ...), or in a container with --cap-add=BPF --cap-add=PERFMON --cap-add=NET_ADMIN")
    }
}

/// A soft `Max locked memory` limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Memlock {
    Unlimited,
    Bytes(u64),
}

/// The soft `Max locked memory` limit from `/proc/self/limits`.
fn memlock_limit(limits: &str) -> Option<Memlock> {
    limits.lines().find_map(|line| {
        let rest = line.strip_prefix("Max locked memory")?;
        let soft = rest.split_whitespace().next()?;
        if soft == "unlimited" {
            Some(Memlock::Unlimited)
        } else {
            soft.parse().ok().map(Memlock::Bytes)
        }
    })
}

fn check_memlock(version: Option<Version>, limits: Option<&str>) -> Check {
    if version.is_some_and(|v| v >= kernel::MEMCG_ACCOUNTING) {
        return Check::new(
            "memlock",
            Status::Pass,
            "not limiting: eBPF memory is charged to the memory cgroup (Linux 5.11+)",
        );
    }
    match limits.and_then(memlock_limit) {
        Some(Memlock::Unlimited) => Check::new("memlock", Status::Pass, "unlimited"),
        Some(Memlock::Bytes(n)) if n >= MEMLOCK_NEEDED => {
            Check::new("memlock", Status::Pass, format!("{} MiB", n / (1024 * 1024)))
        }
        Some(Memlock::Bytes(n)) => Check::new(
            "memlock",
            Status::Fail,
            format!("{} KiB locked memory; maps may fail to load before Linux 5.11", n / 1024),
        )
        .fix("LimitMEMLOCK=infinity in the unit (the shipped unit sets it), or `ulimit -l unlimited`, or docker --ulimit memlock=-1"),
        None => Check::new("memlock", Status::Warn, "cannot read Max locked memory from /proc/self/limits")
            .fix("set LimitMEMLOCK=infinity"),
    }
}

fn check_interface(interface: Option<&(String, bool)>) -> Check {
    match interface {
        None => Check::new("interface", Status::Info, "none given (--interface)"),
        Some((name, true)) => Check::new("interface", Status::Pass, format!("{name} exists")),
        Some((name, false)) => Check::new("interface", Status::Fail, format!("{name} not found"))
            .fix("pick one from `ip -br link`; in a container, run with --network host"),
    }
}

/// The selected lockdown mode: the bracketed word in `none [integrity] confidentiality`.
fn lockdown_mode(text: &str) -> Option<&str> {
    let start = text.find('[')? + 1;
    let end = start + text[start..].find(']')?;
    Some(&text[start..end])
}

fn check_lockdown(text: Option<&str>) -> Check {
    match text.and_then(lockdown_mode) {
        None | Some("none") => Check::new("lockdown", Status::Pass, "kernel lockdown off"),
        Some("integrity") => Check::new(
            "lockdown",
            Status::Pass,
            "integrity mode: TC programs load; kernel memory reads stay allowed",
        ),
        Some(mode) => Check::new(
            "lockdown",
            Status::Warn,
            format!("{mode} mode: packet counting works; later layers that read kernel memory (process owners, TCP state) will not"),
        )
        .fix("lockdown is set by Secure Boot or `lockdown=` on the kernel command line; integrity mode is enough for capture"),
    }
}

fn check_unprivileged_bpf(version: Option<Version>, value: Option<&str>) -> Check {
    let value = value.map_or("unknown", str::trim);
    let old = version.is_some_and(|v| v < kernel::UNPRIVILEGED_MAP_ACCESS);
    if old && value != "0" {
        Check::new(
            "unprivileged_bpf",
            Status::Info,
            format!(
                "kernel.unprivileged_bpf_disabled={value} before Linux 6.5: CAP_BPF stays effective after attach so the counters can be read; the other capabilities are dropped"
            ),
        )
    } else {
        Check::new(
            "unprivileged_bpf",
            Status::Pass,
            format!(
                "kernel.unprivileged_bpf_disabled={value} (fine: capture is privileged only while attaching)"
            ),
        )
    }
}

fn check_cgroup2(present: bool) -> Check {
    if present {
        Check::new(
            "cgroup v2",
            Status::Pass,
            "unified hierarchy at /sys/fs/cgroup",
        )
    } else {
        Check::new(
            "cgroup v2",
            Status::Warn,
            "not found at /sys/fs/cgroup; not needed for counting, needed later to name containers",
        )
        .fix("boot with systemd.unified_cgroup_hierarchy=1 (default on current distributions)")
    }
}

fn check_owners(version: Option<Version>, cgroup2: bool) -> Check {
    match (version, cgroup2) {
        (Some(v), true) if v >= kernel::SOCK_DIAG_CGROUP_ID => Check::new(
            "owners",
            Status::Pass,
            "sockets carry their cgroup id: owners named by systemd unit, container or pod (layer 4)",
        ),
        (Some(_), true) => Check::new(
            "owners",
            Status::Warn,
            "before Linux 5.9 sock_diag has no cgroup id: owners are named by user only",
        )
        .fix("upgrade to Linux 5.9 or newer for owners by unit, container and pod"),
        _ => Check::new(
            "owners",
            Status::Warn,
            "no cgroup v2: owners are named by user only",
        )
        .fix("boot with systemd.unified_cgroup_hierarchy=1 (default on current distributions)"),
    }
}

/// Whether `name` is a group in an `/etc/group`-format text.
fn group_exists(groups: &str, name: &str) -> bool {
    groups.lines().any(|l| l.split(':').next() == Some(name))
}

fn check_socket_group(groups: Option<&str>, name: &str) -> Check {
    if groups.is_some_and(|g| group_exists(g, name)) {
        Check::new(
            "socket group",
            Status::Pass,
            format!("{name} exists: the aggregates socket is 0660 {name}, readable by the agent"),
        )
    } else {
        Check::new(
            "socket group",
            Status::Warn,
            format!("group {name} not found: the aggregates socket will be 0600 and the agent cannot read it"),
        )
        .fix(format!("install iohr-agent (it creates the group), or `sudo groupadd --system {name}`"))
    }
}

fn check_lsm(selinux: Option<&str>, apparmor: Option<&str>) -> Check {
    let selinux_enforcing = selinux.is_some_and(|s| s.trim() == "1");
    let apparmor_on = apparmor.is_some_and(|s| s.trim().eq_ignore_ascii_case("y"));
    match (selinux_enforcing, apparmor_on) {
        (true, _) => Check::new("lsm", Status::Info, "SELinux enforcing")
            .fix("if loading fails with EACCES, the domain needs the `bpf` class permissions (map_create, map_read, map_write, prog_load, prog_run); check `ausearch -m avc -ts recent`"),
        (false, true) => Check::new("lsm", Status::Info, "AppArmor enabled")
            .fix("if loading fails with EACCES, the profile needs `capability bpf, capability perfmon, capability net_admin,`; check `journalctl -k | grep apparmor`"),
        (false, false) => Check::new("lsm", Status::Pass, "no SELinux enforcement, no AppArmor"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS_ROOT: &str = "Name:\tiohr-capture\nUmask:\t0022\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
    const STATUS_UNIT: &str =
        "CapInh:\t0000000000000000\nCapPrm:\t000000c000001000\nCapEff:\t000000c000001000\n";
    const STATUS_USER: &str =
        "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n";
    const LIMITS_64K: &str = "Limit                     Soft Limit           Hard Limit           Units     \nMax open files            1024                 524288               files     \nMax locked memory         65536                65536                bytes     \n";
    const LIMITS_UNLIMITED: &str =
        "Max locked memory         unlimited            unlimited            bytes     \n";
    const MOUNTS: &str = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\nbpf /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0\n";

    fn host(release: &str) -> Facts {
        Facts {
            osrelease: Some(format!("{release}\n")),
            btf_vmlinux: true,
            mounts: Some(MOUNTS.into()),
            status: Some(STATUS_ROOT.into()),
            limits: Some(LIMITS_UNLIMITED.into()),
            interface: Some(("eth0".into(), true)),
            lockdown: Some("[none] integrity confidentiality\n".into()),
            unprivileged_bpf_disabled: Some("2\n".into()),
            cgroup2: true,
            selinux_enforce: None,
            apparmor_enabled: None,
            groups: Some("root:x:0:\niohr-agent:x:998:alice\n".into()),
            socket_group: "iohr-agent".into(),
        }
    }

    fn find<'a>(checks: &'a [Check], name: &str) -> &'a Check {
        checks
            .iter()
            .find(|c| c.name == name)
            .expect("check present")
    }

    #[test]
    fn current_host_can_run() {
        let checks = evaluate(&host("6.8.0-45-generic"));
        assert!(can_run(&checks), "{}", render(&checks));
        assert!(find(&checks, "tc attach").detail.starts_with("TCX"));
        assert_eq!(find(&checks, "unprivileged_bpf").status, Status::Pass);
    }

    #[test]
    fn kernel_older_than_5_8_fails() {
        let checks = evaluate(&host("5.4.0-150-generic"));
        assert_eq!(find(&checks, "kernel").status, Status::Fail);
        assert!(!can_run(&checks));
        assert!(render(&checks).ends_with("fix the FAIL lines above"));
    }

    #[test]
    fn unreadable_kernel_fails() {
        let mut facts = host("6.8.0");
        facts.osrelease = None;
        assert_eq!(find(&evaluate(&facts), "kernel").status, Status::Fail);
    }

    #[test]
    fn netlink_before_6_6_and_cap_bpf_kept_before_6_5() {
        let checks = evaluate(&host("5.15.0-91-generic"));
        assert!(find(&checks, "tc attach").detail.starts_with("netlink"));
        assert_eq!(find(&checks, "unprivileged_bpf").status, Status::Info);
        let mut facts = host("5.15.0");
        facts.unprivileged_bpf_disabled = Some("0".into());
        assert_eq!(
            find(&evaluate(&facts), "unprivileged_bpf").status,
            Status::Pass
        );
    }

    #[test]
    fn btf_missing_fails() {
        let mut facts = host("6.8.0");
        facts.btf_vmlinux = false;
        let checks = evaluate(&facts);
        assert_eq!(find(&checks, "btf").status, Status::Fail);
        assert!(
            find(&checks, "btf")
                .fix
                .as_deref()
                .unwrap_or("")
                .contains("CONFIG_DEBUG_INFO_BTF")
        );
    }

    #[test]
    fn capabilities() {
        assert_eq!(effective_capabilities(STATUS_ROOT), Some(0x1ff_ffff_ffff));
        let mut facts = host("6.8.0");
        facts.status = Some(STATUS_UNIT.into());
        assert_eq!(find(&evaluate(&facts), "capabilities").status, Status::Pass);
        facts.status = Some(STATUS_USER.into());
        let c = evaluate(&facts);
        let caps = find(&c, "capabilities");
        assert_eq!(caps.status, Status::Fail);
        assert_eq!(caps.detail, "missing CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN");
        facts.status = Some("Name:\tx\n".into());
        assert_eq!(find(&evaluate(&facts), "capabilities").status, Status::Fail);
    }

    #[test]
    fn memlock() {
        assert_eq!(memlock_limit(LIMITS_64K), Some(Memlock::Bytes(65_536)));
        assert_eq!(memlock_limit(LIMITS_UNLIMITED), Some(Memlock::Unlimited));
        assert_eq!(memlock_limit("Max open files 1 1 files\n"), None);
        let mut facts = host("5.10.0");
        facts.limits = Some(LIMITS_64K.into());
        assert_eq!(find(&evaluate(&facts), "memlock").status, Status::Fail);
        facts.limits = Some(LIMITS_UNLIMITED.into());
        assert_eq!(find(&evaluate(&facts), "memlock").status, Status::Pass);
        let mut facts = host("5.15.0");
        facts.limits = Some(LIMITS_64K.into());
        assert_eq!(find(&evaluate(&facts), "memlock").status, Status::Pass);
    }

    #[test]
    fn bpffs() {
        assert!(bpffs_mounted(MOUNTS));
        assert!(!bpffs_mounted("sysfs /sys sysfs rw 0 0\n"));
        let mut facts = host("6.8.0");
        facts.mounts = Some("sysfs /sys sysfs rw 0 0\n".into());
        let checks = evaluate(&facts);
        assert_eq!(find(&checks, "bpffs").status, Status::Info);
        assert!(can_run(&checks));
    }

    #[test]
    fn interface() {
        let mut facts = host("6.8.0");
        facts.interface = Some(("eth9".into(), false));
        assert_eq!(find(&evaluate(&facts), "interface").status, Status::Fail);
        facts.interface = None;
        assert_eq!(find(&evaluate(&facts), "interface").status, Status::Info);
    }

    #[test]
    fn lockdown() {
        assert_eq!(
            lockdown_mode("none [integrity] confidentiality\n"),
            Some("integrity")
        );
        assert_eq!(lockdown_mode("garbage"), None);
        let mut facts = host("6.8.0");
        facts.lockdown = Some("none integrity [confidentiality]\n".into());
        let checks = evaluate(&facts);
        assert_eq!(find(&checks, "lockdown").status, Status::Warn);
        assert!(can_run(&checks));
        facts.lockdown = None;
        assert_eq!(find(&evaluate(&facts), "lockdown").status, Status::Pass);
    }

    #[test]
    fn cgroup_and_lsm() {
        let mut facts = host("6.8.0");
        facts.cgroup2 = false;
        facts.selinux_enforce = Some("1\n".into());
        let checks = evaluate(&facts);
        assert_eq!(find(&checks, "cgroup v2").status, Status::Warn);
        assert!(find(&checks, "lsm").detail.contains("SELinux"));
        facts.selinux_enforce = Some("0\n".into());
        facts.apparmor_enabled = Some("Y\n".into());
        assert!(find(&evaluate(&facts), "lsm").detail.contains("AppArmor"));
    }

    #[test]
    fn owners_and_socket_group() {
        let checks = evaluate(&host("6.8.0"));
        assert_eq!(find(&checks, "owners").status, Status::Pass);
        assert_eq!(find(&checks, "socket group").status, Status::Pass);
        let mut facts = host("5.8.0");
        facts.groups = Some("root:x:0:\n".into());
        let checks = evaluate(&facts);
        assert_eq!(find(&checks, "owners").status, Status::Warn);
        assert_eq!(find(&checks, "socket group").status, Status::Warn);
        assert!(can_run(&checks), "warnings never stop capture");
    }

    #[test]
    fn gathers_from_a_fixture_tree() {
        let dir = std::env::temp_dir().join(format!("iohr-capture-doctor-{}", std::process::id()));
        let w = |p: &str, s: &str| {
            let path = dir.join(p);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(path, s).expect("write");
        };
        w("proc/sys/kernel/osrelease", "6.6.17\n");
        w("sys/kernel/btf/vmlinux", "");
        w("proc/self/status", STATUS_UNIT);
        w("proc/self/limits", LIMITS_64K);
        w("proc/self/mounts", MOUNTS);
        w("sys/class/net/veth0/ifindex", "4\n");
        w("sys/fs/cgroup/cgroup.controllers", "cpu memory\n");
        let facts = Facts::gather_from(&dir, Some("veth0"));
        let checks = evaluate(&facts);
        assert!(can_run(&checks), "{}", render(&checks));
        let escape = Facts::gather_from(&dir, Some("../../../etc"));
        assert_eq!(escape.interface, Some(("../../../etc".into(), false)));
        let _ = fs::remove_dir_all(&dir);
    }
}
