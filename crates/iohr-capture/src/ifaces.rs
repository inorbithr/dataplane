//! Which interfaces to attach to. `--interface` (repeatable), `IOHR_CAPTURE_INTERFACES`
//! (a comma or space separated list; `IOHR_CAPTURE_INTERFACE` is the older single name), or
//! `--all` / `IOHR_CAPTURE_ALL_INTERFACES=true`: every interface that is up and carries the
//! host's own traffic: physical NICs, bonds and VLANs. Loopback, a bond's members and the
//! virtual devices container runtimes and Kubernetes networking create (veth pairs,
//! bridges, overlays) are skipped unless named; `iohr-capture interfaces` shows each
//! decision and why.
//!
//! Reads `/sys/class/net` only; portable, so its tests run anywhere.

use std::{fs, path::Path};

use serde::Serialize;

/// Most interfaces one companion attaches to (`iohr_capture_common::MAX_INTERFACES`, which
/// the eBPF maps are sized by; `capture.rs` asserts the two are equal).
pub(crate) const MAX: usize = 16;

/// Name prefixes of devices container runtimes, Kubernetes CNIs and VPNs create. A pod's
/// veth, a bridge or an overlay sees pod-to-pod traffic; the host's NIC sees what enters
/// and leaves the host (docs/capture/install.md, "Kubernetes hosts").
pub(crate) const VIRTUAL_PREFIXES: &[&str] = &[
    "lo",
    "docker",
    "veth",
    "br-",
    "cni",
    "flannel",
    "cali",
    "cilium",
    "lxc",
    "kube-",
    "k3d",
    "virbr",
    "vxlan",
    "genev",
    "tun",
    "tap",
    "wg",
    "tailscale",
    "zt",
    "weave",
    "vnet",
    "podman",
    "nodelocaldns",
    "dummy",
];

/// One interface as `/sys/class/net` shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) name: String,
    /// `operstate` is `up` (or `unknown` with carrier, as some drivers report).
    pub(crate) up: bool,
    /// Has a `device` link: a NIC on a bus.
    pub(crate) physical: bool,
    /// `DEVTYPE` from `uevent`: `vlan`, `bond`, `bridge`, `veth`, `wlan`, ...
    pub(crate) devtype: Option<String>,
    /// Enslaved to a bond or bridge (`master` link): its master is the one to pick.
    pub(crate) has_master: bool,
}

/// What `--all` decided for one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Decision {
    pub(crate) name: String,
    pub(crate) picked: bool,
    pub(crate) why: String,
}

/// Reads one interface's facts under `root` (`/` on a host).
#[must_use]
pub(crate) fn facts(root: &Path, name: &str) -> Facts {
    let dir = root.join("sys/class/net").join(name);
    let read = |f: &str| fs::read_to_string(dir.join(f)).unwrap_or_default();
    let oper = read("operstate");
    let carrier = read("carrier").trim() == "1";
    let devtype = read("uevent")
        .lines()
        .find_map(|l| l.strip_prefix("DEVTYPE=").map(str::to_owned));
    Facts {
        name: name.to_owned(),
        up: oper.trim() == "up" || (oper.trim() == "unknown" && carrier),
        physical: dir.join("device").exists(),
        devtype,
        has_master: dir.join("master").exists(),
    }
}

/// Every interface under `root`, sorted by name.
#[must_use]
pub(crate) fn all_facts(root: &Path) -> Vec<Facts> {
    let mut names: Vec<String> = fs::read_dir(root.join("sys/class/net"))
        .map(|d| {
            d.filter_map(Result::ok)
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.iter().map(|n| facts(root, n)).collect()
}

/// The `--all` decision for one interface.
#[must_use]
pub(crate) fn decide(f: &Facts) -> Decision {
    let skip = |why: &str| Decision {
        name: f.name.clone(),
        picked: false,
        why: why.to_owned(),
    };
    let pick = |why: &str| Decision {
        name: f.name.clone(),
        picked: true,
        why: why.to_owned(),
    };
    if f.name == "lo" {
        return skip("loopback");
    }
    if let Some(p) = VIRTUAL_PREFIXES.iter().find(|p| f.name.starts_with(**p)) {
        return skip(&format!(
            "virtual ({p}*: containers, Kubernetes networking or a VPN); name it to include it"
        ));
    }
    match f.devtype.as_deref() {
        Some("bridge") => return skip("a bridge; name it to include it"),
        Some("veth") => return skip("a veth pair end; name it to include it"),
        _ => {}
    }
    if !f.up {
        return skip("down");
    }
    if f.has_master {
        return skip("a member of a bond or bridge: its master carries the traffic");
    }
    match (f.physical, f.devtype.as_deref()) {
        (_, Some("bond")) => pick("a bond, up"),
        (_, Some("vlan")) => pick("a VLAN, up"),
        (true, Some("wlan")) => pick("a Wi-Fi NIC, up"),
        (true, _) => pick("a physical NIC, up"),
        (false, _) => skip("virtual and not a bond or VLAN; name it to include it"),
    }
}

/// The `--all` selection: each decision, and the names picked.
#[must_use]
pub(crate) fn select_all(facts: &[Facts]) -> (Vec<Decision>, Vec<String>) {
    let decisions: Vec<Decision> = facts.iter().map(decide).collect();
    let picked = decisions
        .iter()
        .filter(|d| d.picked)
        .map(|d| d.name.clone())
        .collect();
    (decisions, picked)
}

/// A list from an environment value: names separated by commas or whitespace.
#[must_use]
pub(crate) fn parse_list(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// An interface name the kernel would accept (IFNAMSIZ, no path or space characters).
#[must_use]
pub(crate) fn valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'))
}

/// The interfaces to use: named ones first (flag, then `IOHR_CAPTURE_INTERFACES`, then
/// `IOHR_CAPTURE_INTERFACE`), else `--all`'s selection. Duplicates go; at most
/// `max`; every name must be valid and exist under `root`.
///
/// # Errors
/// Why there is nothing to attach to, or which name is wrong.
pub(crate) fn resolve(
    root: &Path,
    named: &[String],
    env_list: Option<&str>,
    env_single: Option<&str>,
    all: bool,
    max: usize,
) -> Result<Vec<String>, String> {
    let mut wanted: Vec<String> = named.iter().flat_map(|n| parse_list(n)).collect();
    if wanted.is_empty() {
        wanted = env_list.map(parse_list).unwrap_or_default();
    }
    if wanted.is_empty() {
        wanted = env_single.map(parse_list).unwrap_or_default();
    }
    if wanted.is_empty() && all {
        wanted = select_all(&all_facts(root)).1;
        if wanted.is_empty() {
            return Err(
                "--all found no interface that is up and physical, a bond or a VLAN \
                 (see `iohr-capture interfaces`); name one with --interface"
                    .into(),
            );
        }
    }
    if wanted.is_empty() {
        return Err("no interface: pass --interface (repeatable) or --all".into());
    }
    let mut out: Vec<String> = Vec::new();
    for n in wanted {
        if !valid(&n) || !root.join("sys/class/net").join(&n).exists() {
            return Err(format!(
                "`{n}` is not a network interface on this host (see `ip link`)"
            ));
        }
        if !out.contains(&n) {
            out.push(n);
        }
    }
    if out.len() > max {
        return Err(format!("at most {max} interfaces; {} given", out.len()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(
        root: &Path,
        name: &str,
        oper: &str,
        physical: bool,
        devtype: Option<&str>,
        master: bool,
    ) {
        let d = root.join("sys/class/net").join(name);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("operstate"), format!("{oper}\n")).unwrap();
        fs::write(d.join("carrier"), "1\n").unwrap();
        let uevent = devtype.map_or_else(
            || format!("INTERFACE={name}\n"),
            |t| format!("INTERFACE={name}\nDEVTYPE={t}\n"),
        );
        fs::write(d.join("uevent"), uevent).unwrap();
        if physical {
            fs::create_dir_all(d.join("device")).unwrap();
        }
        if master {
            fs::create_dir_all(d.join("master")).unwrap();
        }
    }

    /// nevio-server on 2026-10-09: one NIC, Docker, k3d's bridges and pods' veths.
    fn server(root: &Path) {
        iface(root, "lo", "unknown", false, None, false);
        iface(root, "enp70s0", "up", true, None, false);
        iface(root, "enp71s0", "down", true, None, false);
        iface(root, "docker0", "up", false, Some("bridge"), false);
        iface(root, "br-1a2b3c", "up", false, Some("bridge"), false);
        iface(root, "veth9f1", "up", false, Some("veth"), true);
        iface(root, "cni0", "up", false, Some("bridge"), false);
        iface(root, "flannel.1", "unknown", false, Some("vxlan"), false);
        iface(root, "wlp5s0", "down", true, Some("wlan"), false);
    }

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "iohr-ifaces-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn all_picks_the_host_nic_and_explains_every_skip() {
        let root = tmp();
        server(&root);
        let (decisions, picked) = select_all(&all_facts(&root));
        assert_eq!(picked, ["enp70s0"]);
        let why = |n: &str| decisions.iter().find(|d| d.name == n).unwrap().why.clone();
        assert_eq!(why("lo"), "loopback");
        assert_eq!(why("enp71s0"), "down");
        assert!(why("docker0").starts_with("virtual (docker*"));
        assert!(why("br-1a2b3c").starts_with("virtual (br-*"));
        assert!(why("veth9f1").starts_with("virtual (veth*"));
        assert!(why("cni0").starts_with("virtual (cni*"));
        assert!(why("flannel.1").starts_with("virtual (flannel*"));
        assert_eq!(decisions.len(), 9);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bonds_and_vlans_are_picked_and_bond_members_are_not() {
        let root = tmp();
        iface(&root, "eno1", "up", true, None, true);
        iface(&root, "eno2", "up", true, None, true);
        iface(&root, "bond0", "up", false, Some("bond"), false);
        iface(&root, "bond0.100", "up", false, Some("vlan"), false);
        iface(&root, "mybridge", "up", false, Some("bridge"), false);
        iface(&root, "dummy0", "unknown", false, None, false);
        let (_, picked) = select_all(&all_facts(&root));
        assert_eq!(picked, ["bond0", "bond0.100"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn named_interfaces_win_and_any_device_may_be_named() {
        let root = tmp();
        server(&root);
        let r = |named: &[&str], list: Option<&str>, single: Option<&str>, all: bool| {
            resolve(
                &root,
                &named.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                list,
                single,
                all,
                16,
            )
        };
        assert_eq!(
            r(&["enp70s0", "cni0", "enp70s0"], None, None, true).unwrap(),
            ["enp70s0", "cni0"]
        );
        assert_eq!(
            r(&["enp70s0,docker0"], None, None, false).unwrap(),
            ["enp70s0", "docker0"]
        );
        assert_eq!(
            r(&[], Some("enp70s0 cni0"), Some("lo"), false).unwrap(),
            ["enp70s0", "cni0"]
        );
        assert_eq!(
            r(&[], Some(""), Some("enp70s0"), false).unwrap(),
            ["enp70s0"]
        );
        assert_eq!(r(&[], None, None, true).unwrap(), ["enp70s0"]);
        assert!(
            r(&[], None, None, false)
                .unwrap_err()
                .contains("--interface")
        );
        assert!(
            r(&["eth9"], None, None, false)
                .unwrap_err()
                .contains("eth9")
        );
        assert!(r(&["../../etc"], None, None, false).is_err());
        let many: Vec<String> = (0..3).map(|i| format!("x{i}")).collect();
        for n in &many {
            iface(&root, n, "up", true, None, false);
        }
        assert!(
            resolve(&root, &many, None, None, false, 2)
                .unwrap_err()
                .contains("at most 2")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lists_split_on_commas_and_spaces() {
        assert_eq!(parse_list(" a, b  c,,d "), ["a", "b", "c", "d"]);
        assert_eq!(parse_list(""), Vec::<String>::new());
    }
}
