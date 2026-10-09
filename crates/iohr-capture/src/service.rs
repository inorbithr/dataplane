#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
//! `iohr-capture service install|remove`: the system service for a companion installed
//! with `iohr ext install inorbit/capture` instead of the `.deb` or `.rpm`. It sets up the
//! same thing the packages do, from the same files (the unit, the settings file and the
//! tmpfiles rule in `packaging/`, built in), with the program copied to
//! `/usr/local/bin/iohr-capture`: the system user `iohr-capture`, the read group
//! `iohr-capture-read`, `/etc/iohr-capture/capture.env` with the interface set, the unit,
//! and the agent's user in the read group. Root only; it refuses next to a package
//! install, which owns `/usr/bin/iohr-capture` and the unit.

use std::{
    fmt::Write as _,
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::Command,
};

/// The unit the packages install, built in.
const UNIT: &str = include_str!("../../../packaging/systemd/iohr-capture.service");
/// The settings file the packages install, every setting commented with its default.
const ENV: &str = include_str!("../../../packaging/capture.env");
/// The tmpfiles rule that expires pcap files left by a host that went down hard.
const TMPFILES: &str = include_str!("../../../packaging/tmpfiles/iohr-capture.conf");

/// Where this install puts the program (a package install uses `/usr/bin`).
pub(crate) const BIN: &str = "/usr/local/bin/iohr-capture";
const PACKAGED_BIN: &str = "/usr/bin/iohr-capture";
const UNIT_PATH: &str = "/etc/systemd/system/iohr-capture.service";
const PACKAGED_UNIT: &str = "/usr/lib/systemd/system/iohr-capture.service";
const TMPFILES_PATH: &str = "/etc/tmpfiles.d/iohr-capture.conf";
const ETC: &str = "/etc/iohr-capture";
const ENV_PATH: &str = "/etc/iohr-capture/capture.env";
/// The companion's own user.
pub(crate) const USER: &str = "iohr-capture";
/// The group that may read the counts.
pub(crate) const READ_GROUP: &str = "iohr-capture-read";

/// What `install` was asked for.
#[derive(Debug, Clone)]
pub(crate) struct InstallArgs {
    /// The interfaces to attach to; none (and not `all`) picks the one the default route uses.
    pub(crate) interfaces: Vec<String>,
    /// Every interface `iohr-capture interfaces` picks, chosen again at each start.
    pub(crate) all: bool,
    /// Users that may read the counts (the agent's user); `iohr-agent` joins too if it exists.
    pub(crate) agent_users: Vec<String>,
    /// Write everything but don't enable or start the service.
    pub(crate) no_start: bool,
}

/// The unit with the program at [`BIN`].
#[must_use]
pub(crate) fn unit() -> String {
    UNIT.replace(PACKAGED_BIN, BIN)
}

/// Which interfaces the settings file names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Selection {
    /// These, in this order.
    List(Vec<String>),
    /// `--all`, chosen again at each start.
    All,
}

/// A settings file with the interfaces set: `IOHR_CAPTURE_INTERFACES` (a list) or
/// `IOHR_CAPTURE_ALL_INTERFACES=true`, the other one and the older
/// `IOHR_CAPTURE_INTERFACE` commented out. An existing file keeps every other line; a new
/// one starts from the packaged template.
#[must_use]
pub(crate) fn settings(existing: Option<&str>, selection: &Selection) -> String {
    let base = existing.unwrap_or(ENV);
    let (list, all) = match selection {
        Selection::List(names) => (format!("IOHR_CAPTURE_INTERFACES={}", names.join(",")), None),
        Selection::All => (
            "#IOHR_CAPTURE_INTERFACES=".to_owned(),
            Some("IOHR_CAPTURE_ALL_INTERFACES=true"),
        ),
    };
    let mut out = String::new();
    let (mut list_set, mut all_set) = (false, false);
    for l in base.lines() {
        let uncommented = l.trim_start_matches('#').trim_start();
        if uncommented.starts_with("IOHR_CAPTURE_INTERFACES=") {
            if !list_set {
                out.push_str(&list);
                list_set = true;
            }
        } else if uncommented.starts_with("IOHR_CAPTURE_ALL_INTERFACES=") {
            if !all_set {
                out.push_str(all.unwrap_or("#IOHR_CAPTURE_ALL_INTERFACES=true"));
                all_set = true;
            }
        } else if uncommented.starts_with("IOHR_CAPTURE_INTERFACE=") {
            out.push_str("#IOHR_CAPTURE_INTERFACE=");
        } else {
            out.push_str(l);
        }
        out.push('\n');
    }
    if !list_set {
        let _ = writeln!(out, "{list}");
    }
    if let (Some(a), false) = (all, all_set) {
        let _ = writeln!(out, "{a}");
    }
    out
}

/// The interface the IPv4 default route leaves through, from `/proc/net/route` text.
#[must_use]
pub(crate) fn default_interface(route_table: &str) -> Option<String> {
    route_table.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 7 && f[1] == "00000000" && f[7] == "00000000").then(|| f[0].to_string())
    })
}

/// A user or group name of the portable shape `useradd` accepts.
#[must_use]
pub(crate) fn valid_user(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Why setting up or removing the service failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ServiceError {
    /// Not root.
    #[error("run it as root: sudo iohr-capture service {0}")]
    NotRoot(&'static str),
    /// A package install is present.
    #[error(
        "iohr-capture is installed from the package here ({0}); manage it with apt or dnf, not `service`"
    )]
    Packaged(&'static str),
    /// A bad argument.
    #[error("{0}")]
    Invalid(String),
    /// A file could not be written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
    /// A system command failed.
    #[error("`{0}` failed: {1}")]
    Command(String, String),
}

fn io(path: &str) -> impl FnOnce(std::io::Error) -> ServiceError + '_ {
    move |source| ServiceError::Io {
        path: PathBuf::from(path),
        source,
    }
}

fn run(program: &str, args: &[&str]) -> Result<(), ServiceError> {
    let shown = format!("{program} {}", args.join(" "));
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| ServiceError::Command(shown.clone(), e.to_string()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(ServiceError::Command(
            shown,
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

fn exists(kind: &str, name: &str) -> bool {
    Command::new("getent")
        .args([kind, name])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn write(path: &str, contents: &str, mode: u32) -> Result<(), ServiceError> {
    fs::write(path, contents).map_err(io(path))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io(path))
}

fn root(cmd: &'static str) -> Result<(), ServiceError> {
    #[cfg(target_os = "linux")]
    if rustix::process::geteuid().is_root() {
        return Ok(());
    }
    Err(ServiceError::NotRoot(cmd))
}

fn not_packaged() -> Result<(), ServiceError> {
    for p in [
        PACKAGED_BIN,
        PACKAGED_UNIT,
        "/lib/systemd/system/iohr-capture.service",
    ] {
        if Path::new(p).exists() {
            return Err(ServiceError::Packaged(if p == PACKAGED_BIN {
                PACKAGED_BIN
            } else {
                PACKAGED_UNIT
            }));
        }
    }
    Ok(())
}

/// The interfaces `install` writes, and how to show them.
fn selection(args: &InstallArgs) -> Result<(Selection, String), ServiceError> {
    let selection = if args.all {
        let picked = crate::ifaces::select_all(&crate::ifaces::all_facts(Path::new("/"))).1;
        if picked.is_empty() {
            return Err(ServiceError::Invalid(
                "--all picks no interface here (see `iohr-capture interfaces`): name them with --interface".into(),
            ));
        }
        Selection::All
    } else {
        let named = if args.interfaces.is_empty() {
            vec![
                fs::read_to_string("/proc/net/route")
                    .ok()
                    .and_then(|t| default_interface(&t))
                    .ok_or_else(|| {
                        ServiceError::Invalid(
                            "no default route to pick an interface from: pass --interface or --all"
                                .into(),
                        )
                    })?,
            ]
        } else {
            args.interfaces.clone()
        };
        let resolved = crate::ifaces::resolve(
            Path::new("/"),
            &named,
            None,
            None,
            false,
            crate::ifaces::MAX,
        )
        .map_err(ServiceError::Invalid)?;
        Selection::List(resolved)
    };
    let shown = match &selection {
        Selection::List(n) => n.join(", "),
        Selection::All => format!(
            "all ({} today; chosen again at each start)",
            crate::ifaces::select_all(&crate::ifaces::all_facts(Path::new("/")))
                .1
                .join(", ")
        ),
    };
    Ok((selection, shown))
}

/// Sets up the service; returns what it did, one line each.
///
/// # Errors
///
/// [`ServiceError`] when not root, next to a package install, on a bad argument, or when
/// a file or a system command fails. Steps already done stay done; running it again
/// finishes the rest.
pub(crate) fn install(args: &InstallArgs) -> Result<Vec<String>, ServiceError> {
    root("install")?;
    not_packaged()?;
    let (selection, shown) = selection(args)?;
    for u in &args.agent_users {
        if !valid_user(u) || !exists("passwd", u) {
            return Err(ServiceError::Invalid(format!(
                "`{u}` is not a user on this host"
            )));
        }
    }
    let mut done = Vec::new();

    let me = std::env::current_exe().map_err(io("/proc/self/exe"))?;
    if me != Path::new(BIN) {
        let tmp = format!("{BIN}.new");
        fs::copy(&me, &tmp).map_err(io(BIN))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).map_err(io(BIN))?;
        fs::rename(&tmp, BIN).map_err(io(BIN))?;
        done.push(format!("program   {BIN}"));
    }

    if !exists("group", READ_GROUP) {
        run("groupadd", &["--system", READ_GROUP])?;
        done.push(format!("group     {READ_GROUP} (may read the counts)"));
    }
    if !exists("passwd", USER) {
        run(
            "useradd",
            &[
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                USER,
            ],
        )?;
        done.push(format!("user      {USER} (runs the companion)"));
    }
    let mut readers: Vec<String> = args.agent_users.clone();
    if exists("passwd", "iohr-agent") && !readers.iter().any(|u| u == "iohr-agent") {
        readers.push("iohr-agent".into());
    }
    for u in &readers {
        run("usermod", &["--append", "--groups", READ_GROUP, u])?;
        done.push(format!(
            "reader    {u} joined {READ_GROUP} (restart its agent to read the counts)"
        ));
    }

    fs::create_dir_all(ETC).map_err(io(ETC))?;
    let existing = fs::read_to_string(ENV_PATH).ok();
    write(ENV_PATH, &settings(existing.as_deref(), &selection), 0o640)?;
    fs::set_permissions(ETC, fs::Permissions::from_mode(0o750)).map_err(io(ETC))?;
    run("chown", &[&format!("root:{USER}"), ETC, ENV_PATH])?;
    done.push(format!("settings  {ENV_PATH} (interfaces: {shown})"));

    write(UNIT_PATH, &unit(), 0o644)?;
    write(TMPFILES_PATH, TMPFILES, 0o644)?;
    done.push(format!("unit      {UNIT_PATH}"));
    run("systemctl", &["daemon-reload"])?;
    if !args.no_start {
        run("systemctl", &["enable", "--now", "iohr-capture"])?;
        done.push("service   iohr-capture enabled and started".into());
    }
    Ok(done)
}

/// Stops and removes the service and the program; `purge` also removes the settings, the
/// user and the read group.
///
/// # Errors
///
/// [`ServiceError`] when not root, next to a package install, or when a step fails.
pub(crate) fn remove(purge: bool) -> Result<Vec<String>, ServiceError> {
    root("remove")?;
    not_packaged()?;
    let mut done = Vec::new();
    if Path::new(UNIT_PATH).exists() {
        // Stopping runs ExecStopPost (cleanup): no filter or pcap file is left behind.
        let _ = run("systemctl", &["disable", "--now", "iohr-capture"]);
        fs::remove_file(UNIT_PATH).map_err(io(UNIT_PATH))?;
        run("systemctl", &["daemon-reload"])?;
        done.push("service   stopped and removed".into());
    }
    for p in [TMPFILES_PATH, BIN] {
        if Path::new(p).exists() {
            fs::remove_file(p).map_err(io(p))?;
            done.push(format!("removed   {p}"));
        }
    }
    if purge {
        if Path::new(ETC).exists() {
            fs::remove_dir_all(ETC).map_err(io(ETC))?;
            done.push(format!("removed   {ETC}"));
        }
        if exists("passwd", USER) {
            run("userdel", &[USER])?;
            done.push(format!("removed   user {USER}"));
        }
        if exists("group", READ_GROUP) {
            run("groupdel", &[READ_GROUP])?;
            done.push(format!("removed   group {READ_GROUP}"));
        }
    }
    Ok(done)
}

/// The one policy line the agent needs to read the counts, and how to apply it.
#[must_use]
pub(crate) fn agent_hint() -> &'static str {
    "To let the agent read the counts: in its policy (policy.toml), under [work], set\n  \
     capture = true\n\
     then restart the agent (systemd: sudo systemctl restart iohr-agent; a user service: \
     systemctl --user restart iohr-agent)."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_runs_the_program_from_usr_local() {
        let u = unit();
        assert!(u.contains("ExecStart=/usr/local/bin/iohr-capture run"));
        assert!(u.contains("ExecStopPost=/usr/local/bin/iohr-capture cleanup"));
        assert!(!u.contains(PACKAGED_BIN));
        // The hardening is the package's, unchanged.
        for line in [
            "CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN",
            "IPAddressDeny=any",
            "NoNewPrivileges=yes",
            "User=iohr-capture",
            "Group=iohr-capture-read",
        ] {
            assert!(u.contains(line), "{line}");
        }
    }

    #[test]
    fn settings_set_the_interfaces_and_keep_every_other_line() {
        let list = |n: &[&str]| Selection::List(n.iter().map(|s| (*s).to_owned()).collect());
        let fresh = settings(None, &list(&["enp70s0", "bond0"]));
        assert!(
            fresh
                .lines()
                .any(|l| l == "IOHR_CAPTURE_INTERFACES=enp70s0,bond0")
        );
        assert!(
            fresh
                .lines()
                .any(|l| l == "#IOHR_CAPTURE_ALL_INTERFACES=true")
        );
        assert!(fresh.lines().any(|l| l == "#IOHR_CAPTURE_INTERFACE="));
        let all = settings(None, &Selection::All);
        assert!(all.lines().any(|l| l == "IOHR_CAPTURE_ALL_INTERFACES=true"));
        assert!(all.lines().any(|l| l == "#IOHR_CAPTURE_INTERFACES="));
        // An older file: the single name goes (commented), the list comes, the rest stays.
        let kept = settings(
            Some("A=1\nIOHR_CAPTURE_INTERFACE=eth0\nIOHR_CAPTURE_PACKETS=true\n"),
            &list(&["eth1", "eth2"]),
        );
        assert_eq!(
            kept,
            "A=1\n#IOHR_CAPTURE_INTERFACE=\nIOHR_CAPTURE_PACKETS=true\nIOHR_CAPTURE_INTERFACES=eth1,eth2\n"
        );
        assert_eq!(
            settings(Some("B=2\nIOHR_CAPTURE_INTERFACES=eth0\n"), &Selection::All),
            "B=2\n#IOHR_CAPTURE_INTERFACES=\nIOHR_CAPTURE_ALL_INTERFACES=true\n"
        );
    }

    #[test]
    fn the_default_interface_comes_from_the_default_route() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
                     enp70s0\t00000000\t01B2A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(default_interface(table).as_deref(), Some("enp70s0"));
        assert_eq!(default_interface("Iface\tDestination\n"), None);
    }

    #[test]
    fn names_are_checked_before_any_command_sees_them() {
        for good in ["eth0", "enp70s0", "wlan0", "br-1a2b", "eth0.100"] {
            assert!(crate::ifaces::valid(good), "{good}");
        }
        for bad in [
            "",
            "../etc",
            "eth 0",
            "a;rm",
            "verylonginterfacename0",
            "..",
        ] {
            assert!(!crate::ifaces::valid(bad), "{bad}");
        }
        for good in ["nevio", "iohr-agent", "svc_1"] {
            assert!(valid_user(good), "{good}");
        }
        for bad in ["", "-r", "a b", "x;y", &"a".repeat(33)] {
            assert!(!valid_user(bad), "{bad}");
        }
    }
}
