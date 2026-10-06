//! Owners (layer 4) without kernel probes: a socket's cgroup id (from `sock_diag`) is the
//! inode number of its cgroup v2 directory, so walking `/sys/fs/cgroup` maps it to a path,
//! and the path names the systemd unit, Docker or containerd container, or Kubernetes pod
//! the socket belongs to. The process name comes from the cgroup's `cgroup.procs` and
//! `/proc/<pid>/comm`, which any user may read for processes it can see.
//!
//! Known limits (phase 1): pod and container *names* need the container runtime's API,
//! which would give the companion more reach; the pod UID and container id are shown
//! instead. Sockets in other network namespaces (bridged containers) are not in the host's
//! `sock_diag` dump, so their flows count as unowned.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Most cgroup directories walked per refresh.
const MAX_DIRS: usize = 20_000;
/// Deepest cgroup path walked.
const MAX_DEPTH: usize = 16;
/// A missing id triggers a new walk at most this often.
const REFRESH_EVERY: Duration = Duration::from_secs(5);
/// Most processes read per cgroup to name it.
const MAX_PIDS: usize = 32;

/// What a cgroup path says about its owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Owner {
    /// `systemd`, `docker`, `containerd`, `podman`, `kubernetes`, `session`, `cgroup`,
    /// `root`, or `user` (no cgroup id, uid only).
    pub(crate) kind: &'static str,
    /// The unit, container id (12 characters), `pod <uid>/<container>`, or path.
    pub(crate) name: String,
}

impl Owner {
    /// The row key in the owners table.
    pub(crate) fn key(&self) -> String {
        format!("{}:{}", self.kind, self.name)
    }
}

/// Classifies a cgroup v2 path (relative to the cgroup root, starting with `/`).
pub(crate) fn classify(path: &str) -> Owner {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let Some(last) = segs.last().copied() else {
        return Owner {
            kind: "root",
            name: "/".into(),
        };
    };
    let container = container_id(last);
    if segs.iter().any(|s| s.starts_with("kubepods")) {
        let pod = segs.iter().find_map(|s| pod_uid(s)).unwrap_or_default();
        let name = match container {
            Some((_, id)) => format!("pod {pod}/{id}"),
            None => format!("pod {pod}"),
        };
        return Owner {
            kind: "kubernetes",
            name,
        };
    }
    if segs.len() >= 2 && segs[segs.len() - 2] == "docker" && is_hex_id(last) {
        return Owner {
            kind: "docker",
            name: short(last),
        };
    }
    if let Some((runtime, id)) = container {
        return Owner {
            kind: runtime,
            name: id,
        };
    }
    if let Some(unit) = last.strip_suffix(".service") {
        return Owner {
            kind: "systemd",
            name: format!("{unit}.service"),
        };
    }
    if last.starts_with("session-") && last.rsplit('.').next() == Some("scope") {
        let user = segs
            .iter()
            .find(|s| s.starts_with("user-") && s.rsplit('.').next() == Some("slice"))
            .map_or("user", |s| s.trim_end_matches(".slice"));
        return Owner {
            kind: "session",
            name: user.to_owned(),
        };
    }
    Owner {
        kind: "cgroup",
        name: path.to_owned(),
    }
}

/// `(runtime, short id)` from a scope name like `docker-<id>.scope`.
fn container_id(seg: &str) -> Option<(&'static str, String)> {
    let base = seg.strip_suffix(".scope").unwrap_or(seg);
    for (prefix, runtime) in [
        ("docker-", "docker"),
        ("cri-containerd-", "containerd"),
        ("crio-", "cri-o"),
        ("libpod-", "podman"),
    ] {
        if let Some(id) = base.strip_prefix(prefix)
            && is_hex_id(id)
        {
            return Some((runtime, short(id)));
        }
    }
    // cgroupfs driver (k3s, kubelet without systemd): the leaf is the bare container id.
    is_hex_id(base).then(|| ("container", short(base)))
}

fn pod_uid(seg: &str) -> Option<String> {
    let base = seg.strip_suffix(".slice").unwrap_or(seg);
    let i = base.rfind("pod")?;
    let uid = base.get(i + 3..)?;
    (uid.len() >= 32
        && uid
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'_' || b == b'-'))
    .then(|| uid.replace('_', "-"))
}

fn is_hex_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

/// Maps cgroup ids to paths below a cgroup v2 root, walking it again when an id is
/// unknown (at most every few seconds).
#[derive(Debug)]
pub(crate) struct CgroupIndex {
    root: PathBuf,
    by_id: HashMap<u64, String>,
    walked: Option<Instant>,
    procs: HashMap<String, Option<String>>,
    proc_root: PathBuf,
}

impl CgroupIndex {
    pub(crate) fn new(root: &Path, proc_root: &Path) -> Self {
        Self {
            root: root.to_owned(),
            by_id: HashMap::new(),
            walked: None,
            procs: HashMap::new(),
            proc_root: proc_root.to_owned(),
        }
    }

    /// Forgets cached process names (each poll starts fresh).
    pub(crate) fn new_round(&mut self) {
        self.procs.clear();
    }

    /// The cgroup path of `id`, if any.
    pub(crate) fn path(&mut self, id: u64) -> Option<String> {
        if let Some(p) = self.by_id.get(&id) {
            return Some(p.clone());
        }
        if self.walked.is_none_or(|t| t.elapsed() >= REFRESH_EVERY) {
            self.walk();
        }
        self.by_id.get(&id).cloned()
    }

    fn walk(&mut self) {
        self.walked = Some(Instant::now());
        self.by_id.clear();
        let mut stack = vec![(self.root.clone(), String::from("/"), 0usize)];
        let mut seen = 0usize;
        while let Some((dir, rel, depth)) = stack.pop() {
            seen += 1;
            if seen > MAX_DIRS {
                break;
            }
            if let Ok(meta) = fs::metadata(&dir) {
                self.by_id.insert(meta.ino(), rel.clone());
            }
            if depth >= MAX_DEPTH {
                continue;
            }
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let child = if rel == "/" {
                        format!("/{name}")
                    } else {
                        format!("{rel}/{name}")
                    };
                    stack.push((e.path(), child, depth + 1));
                }
            }
        }
    }

    /// The command names of the processes in a cgroup: `nginx`, or `nginx +2` when several
    /// different names share it. `None` when none is visible.
    pub(crate) fn processes(&mut self, cgroup: &str) -> Option<String> {
        if let Some(p) = self.procs.get(cgroup) {
            return p.clone();
        }
        let file = self
            .root
            .join(cgroup.trim_start_matches('/'))
            .join("cgroup.procs");
        let names = fs::read_to_string(file).ok().map(|text| {
            let mut names: Vec<String> = Vec::new();
            for pid in text.lines().take(MAX_PIDS) {
                if let Ok(comm) = fs::read_to_string(self.proc_root.join(pid.trim()).join("comm")) {
                    let comm = comm.trim().to_owned();
                    if !comm.is_empty() && !names.contains(&comm) {
                        names.push(comm);
                    }
                }
            }
            names
        });
        let label = names.and_then(|mut n| {
            n.sort();
            let first = n.first()?.clone();
            Some(if n.len() > 1 {
                format!("{first} +{}", n.len() - 1)
            } else {
                first
            })
        });
        if self.procs.len() < 4096 {
            self.procs.insert(cgroup.to_owned(), label.clone());
        }
        label
    }
}

/// User names by uid from an `/etc/passwd`-format file.
pub(crate) fn users(passwd: &str) -> HashMap<u32, String> {
    passwd
        .lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            Some((uid, name.to_owned()))
        })
        .take(10_000)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "3f2a9c1e7b4d4c1a9e2f0a1b2c3d4e5f3f2a9c1e7b4d4c1a9e2f0a1b2c3d4e5f";

    #[test]
    fn systemd_docker_containerd_kubernetes() {
        assert_eq!(
            classify("/system.slice/nginx.service").key(),
            "systemd:nginx.service"
        );
        assert_eq!(
            classify(&format!("/system.slice/docker-{ID}.scope")).key(),
            "docker:3f2a9c1e7b4d"
        );
        assert_eq!(
            classify(&format!("/docker/{ID}")).key(),
            "docker:3f2a9c1e7b4d"
        );
        assert_eq!(
            classify(&format!("/system.slice/cri-containerd-{ID}.scope")).key(),
            "containerd:3f2a9c1e7b4d"
        );
        // systemd driver (kubeadm, most distributions)
        assert_eq!(
            classify(&format!("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod0a1b2c3d_4e5f_6a7b_8c9d_0e1f2a3b4c5d.slice/cri-containerd-{ID}.scope")).key(),
            "kubernetes:pod 0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d/3f2a9c1e7b4d"
        );
        // cgroupfs driver (k3s)
        assert_eq!(
            classify(&format!(
                "/kubepods/besteffort/pod0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d/{ID}"
            ))
            .key(),
            "kubernetes:pod 0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d/3f2a9c1e7b4d"
        );
        assert_eq!(
            classify(&format!("/system.slice/libpod-{ID}.scope")).kind,
            "podman"
        );
    }

    #[test]
    fn sessions_root_and_other() {
        assert_eq!(
            classify("/user.slice/user-1000.slice/session-3.scope").key(),
            "session:user-1000"
        );
        assert_eq!(classify("/").kind, "root");
        assert_eq!(classify("/iohr-e2e-web").key(), "cgroup:/iohr-e2e-web");
        assert_eq!(
            classify("/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo.service")
                .key(),
            "systemd:app-foo.service"
        );
    }

    #[test]
    fn index_and_processes_from_a_fixture_tree() {
        let dir = std::env::temp_dir().join(format!("iohr-capture-owners-{}", std::process::id()));
        let cg = dir.join("cg");
        let proc_root = dir.join("proc");
        fs::create_dir_all(cg.join("system.slice/web.service")).unwrap();
        fs::write(
            cg.join("system.slice/web.service/cgroup.procs"),
            "11\n12\n13\n",
        )
        .unwrap();
        for (pid, comm) in [("11", "nginx"), ("12", "nginx"), ("13", "logger")] {
            fs::create_dir_all(proc_root.join(pid)).unwrap();
            fs::write(proc_root.join(pid).join("comm"), format!("{comm}\n")).unwrap();
        }
        let ino = fs::metadata(cg.join("system.slice/web.service"))
            .unwrap()
            .ino();
        let mut idx = CgroupIndex::new(&cg, &proc_root);
        assert_eq!(idx.path(ino).as_deref(), Some("/system.slice/web.service"));
        assert_eq!(idx.path(u64::MAX), None);
        assert_eq!(
            idx.processes("/system.slice/web.service").as_deref(),
            Some("logger +1")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn passwd() {
        let u = users("root:x:0:0:root:/root:/bin/bash\nbad\nweb:x:33:33::/:/bin/false\n");
        assert_eq!(u.get(&33).map(String::as_str), Some("web"));
        assert_eq!(u.len(), 2);
    }
}
