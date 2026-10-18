//! Plan then apply through fake binaries: a matching approval runs the apply, a
//! mismatched, missing, spent or edited one does not.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use iohr_agent::audit::Audit;
use iohr_agent::infra_conn::store::sha256_of;
use iohr_agent::infra_conn::{Approval, Conn, FedApprovals, InfraError, Kind, Runner};

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn s(x: &str) -> Vec<String> {
    x.split_whitespace().map(str::to_owned).collect()
}

struct Env {
    tmp: tempfile::TempDir,
    work: PathBuf,
    marks: PathBuf,
    runner: Runner,
    fed: Arc<FedApprovals>,
}

fn mode(p: &Path, m: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
}

impl Env {
    /// Writes a file into the working directory, which the agent may not write to.
    fn write(&self, name: &str, body: &str) {
        mode(&self.work, 0o755);
        std::fs::write(self.work.join(name), body).unwrap();
        mode(&self.work, 0o555);
    }

    fn conn(&self, kind: Kind) -> Conn {
        let mut c = Conn::new(
            "c1",
            kind,
            self.tmp.path().join("bin/tool"),
            self.work.clone(),
        );
        c.env = BTreeMap::from([
            ("MARKS".into(), self.marks.to_string_lossy().into_owned()),
            ("PATH".into(), "/usr/bin:/bin".into()),
        ]);
        c.timeout_secs = 10;
        c.max_output = 4096;
        c
    }

    /// Rebuilds the runner around `conn`, keeping the plans and the audit log.
    fn rebuild(&mut self, conn: Conn) {
        let audit = Arc::new(Audit::open(&self.tmp.path().join("audit")).unwrap());
        self.runner = Runner::new(conn, &self.tmp.path().join("plans"), audit)
            .unwrap()
            .with_approvals(self.fed.clone());
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        mode(&self.work, 0o755);
    }
}

fn env(kind: Kind, body: &str) -> Env {
    env_with(kind, body, |_| {})
}

fn env_with(kind: Kind, body: &str, f: impl FnOnce(&mut Conn)) -> Env {
    let t = tempfile::tempdir().unwrap();
    let bins = t.path().join("bin");
    let work = t.path().join("work");
    std::fs::create_dir_all(&bins).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let marks = t.path().join("marks");
    std::fs::create_dir_all(&marks).unwrap();
    let bin = script(&bins, "tool", body);
    if kind == Kind::Tofu {
        // An initialised working directory with a remote backend, as a plan needs.
        std::fs::create_dir_all(work.join(".terraform")).unwrap();
        std::fs::write(
            work.join(".terraform/terraform.tfstate"),
            r#"{"version":3,"backend":{"type":"s3","config":{}}}"#,
        )
        .unwrap();
    }
    mode(&work, 0o555);
    let mut conn = Conn::new("c1", kind, bin, work.clone());
    conn.env = BTreeMap::from([
        ("MARKS".into(), marks.to_string_lossy().into_owned()),
        ("PATH".into(), "/usr/bin:/bin".into()),
    ]);
    conn.timeout_secs = 10;
    conn.max_output = 4096;
    f(&mut conn);
    let audit = Arc::new(Audit::open(&t.path().join("audit")).unwrap());
    let fed = Arc::new(FedApprovals::new());
    let runner = Runner::new(conn, &t.path().join("plans"), audit)
        .unwrap()
        .with_approvals(fed.clone());
    Env {
        tmp: t,
        work,
        marks,
        runner,
        fed,
    }
}

const KUBECTL: &str = r#"
case "$1" in
  diff) echo "+ replicas: 3 password=hunter2hunter2"; exit 1 ;;
  apply) cat "$3" > "$MARKS/applied" 2>/dev/null || cat "$4" > "$MARKS/applied"; echo applied ;;
  get) echo "pod/web"; ;;
  *) exit 9 ;;
esac
"#;

#[tokio::test]
async fn kubectl_plan_then_apply_with_matching_hash() {
    let e = env(Kind::Kubectl, KUBECTL);
    e.write("m.yaml", "kind: Deployment\nreplicas: 3\n");
    let plan = e
        .runner
        .run("alice", &s("diff -f m.yaml -n shop"), None)
        .await
        .unwrap();
    let hash = plan.plan_hash.clone().unwrap();
    assert!(hash.starts_with("sha256:") && hash.len() == 71);
    assert!(
        !plan.stdout.contains("hunter2hunter2"),
        "plan output is redacted: {}",
        plan.stdout
    );
    // The file is edited after the plan: the apply still runs the snapshot.
    e.write("m.yaml", "kind: Deployment\nreplicas: 99\n");
    e.fed.feed("ap1", &hash);
    let ap = Approval {
        id: "ap1".into(),
        plan_hash: hash.clone(),
    };
    let r = e
        .runner
        .run(
            "alice",
            &s("apply --server-side -f m.yaml -n shop"),
            Some(&ap),
        )
        .await
        .unwrap();
    assert_eq!(r.code, 0);
    let applied = std::fs::read_to_string(e.marks.join("applied")).unwrap();
    assert!(
        applied.contains("replicas: 3"),
        "applied the snapshot, got {applied:?}"
    );
    // Single use.
    let again = e
        .runner
        .run(
            "alice",
            &s("apply --server-side -f m.yaml -n shop"),
            Some(&ap),
        )
        .await;
    assert!(matches!(again, Err(InfraError::Denied(_))), "{again:?}");
}

#[tokio::test]
async fn apply_is_refused_without_or_with_the_wrong_hash() {
    let e = env(Kind::Kubectl, KUBECTL);
    e.write("m.yaml", "kind: Deployment\n");
    let plan = e
        .runner
        .run("alice", &s("diff -f m.yaml"), None)
        .await
        .unwrap();
    let hash = plan.plan_hash.unwrap();
    let apply = s("apply --server-side -f m.yaml");
    // No approval at all.
    assert!(matches!(
        e.runner.run("a", &apply, None).await,
        Err(InfraError::Denied(_))
    ));
    // An approval for another hash.
    let other = sha256_of(b"another plan");
    e.fed.feed("ap2", &other);
    let bad = Approval {
        id: "ap2".into(),
        plan_hash: other,
    };
    assert!(matches!(
        e.runner.run("a", &apply, Some(&bad)).await,
        Err(InfraError::Denied(_))
    ));
    // A right hash that the checker never issued.
    let unissued = Approval {
        id: "nope".into(),
        plan_hash: hash.clone(),
    };
    assert!(matches!(
        e.runner.run("a", &apply, Some(&unissued)).await,
        Err(InfraError::Denied(_))
    ));
    // A good approval used for a different apply (other namespace) is refused and not spent.
    e.fed.feed("ap3", &hash);
    let good = Approval {
        id: "ap3".into(),
        plan_hash: hash,
    };
    let other_ns = e
        .runner
        .run(
            "a",
            &s("apply --server-side -f m.yaml -n prod"),
            Some(&good),
        )
        .await;
    assert!(
        matches!(other_ns, Err(InfraError::Denied(_))),
        "{other_ns:?}"
    );
    assert!(
        e.runner.run("a", &apply, Some(&good)).await.is_ok(),
        "the approval was not burned by the refusal"
    );
}

#[tokio::test]
async fn a_tampered_snapshot_blocks_the_apply() {
    let e = env(Kind::Kubectl, KUBECTL);
    e.write("m.yaml", "kind: Deployment\n");
    let hash = e
        .runner
        .run("a", &s("diff -f m.yaml"), None)
        .await
        .unwrap()
        .plan_hash
        .unwrap();
    let dir = e
        .tmp
        .path()
        .join("plans")
        .join(hash.strip_prefix("sha256:").unwrap());
    std::fs::write(dir.join("files/m.yaml"), "kind: Deployment\nevil: true\n").unwrap();
    e.fed.feed("ap", &hash);
    let ap = Approval {
        id: "ap".into(),
        plan_hash: hash,
    };
    let r = e
        .runner
        .run("a", &s("apply --server-side -f m.yaml"), Some(&ap))
        .await;
    assert!(matches!(r, Err(InfraError::Denied(_))), "{r:?}");
    assert!(!e.marks.join("applied").exists());
}

const TOFU: &str = r#"
case "$1" in
  plan) shift; while [ $# -gt 0 ]; do [ "$1" = "-out" ] && out="$2"; shift; done; echo "plan-bytes-v1" > "$out"; echo "Plan: 1 to add"; exit 2 ;;
  apply) cat "$(echo "$@" | awk '{print $NF}')" > "$MARKS/tofu-applied"; echo done ;;
  show) echo ok ;;
  *) exit 9 ;;
esac
"#;

#[tokio::test]
async fn tofu_hash_is_the_plan_files_sha256() {
    let e = env(Kind::Tofu, TOFU);
    let plan = e.runner.run("a", &s("plan"), None).await.unwrap();
    assert_eq!(plan.code, 2, "a plan with changes exits 2 and is a success");
    let hash = plan.plan_hash.unwrap();
    assert_eq!(hash, sha256_of(b"plan-bytes-v1\n"));
    e.fed.feed("t1", &hash);
    let ap = Approval {
        id: "t1".into(),
        plan_hash: hash,
    };
    e.runner.run("a", &s("apply"), Some(&ap)).await.unwrap();
    assert_eq!(
        std::fs::read_to_string(e.marks.join("tofu-applied")).unwrap(),
        "plan-bytes-v1\n"
    );
}

#[tokio::test]
async fn reads_run_freely_and_are_redacted_and_refusals_never_start_a_process() {
    let e = env(Kind::Kubectl, KUBECTL);
    let r = e
        .runner
        .run("a", &s("get pods -n shop"), None)
        .await
        .unwrap();
    assert_eq!(r.stdout.trim(), "pod/web");
    for bad in [
        "get secrets",
        "exec web -- sh",
        "delete pod web",
        "get pods; touch x",
    ] {
        let r = e.runner.run("a", &s(bad), None).await;
        assert!(matches!(r, Err(InfraError::Refused(_))), "{bad}: {r:?}");
    }
    assert!(!e.work.join("x").exists());
}

#[tokio::test]
async fn a_secret_manifest_is_never_planned() {
    let e = env(Kind::Kubectl, KUBECTL);
    e.write("s.yaml", "apiVersion: v1\nkind: Secret\ndata:\n  a: Yg==\n");
    let r = e.runner.run("a", &s("diff -f s.yaml"), None).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
}

#[tokio::test]
async fn path_escapes_are_refused() {
    let e = env(Kind::Kubectl, KUBECTL);
    mode(&e.work, 0o755);
    std::os::unix::fs::symlink("/etc/hosts", e.work.join("link.yaml")).unwrap();
    mode(&e.work, 0o555);
    let r = e.runner.run("a", &s("diff -f link.yaml"), None).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
}

#[tokio::test]
async fn output_is_capped_and_the_deadline_kills_the_whole_group() {
    let e = env(Kind::Ssh, "yes x | head -c 100000; echo");
    let r = e.runner.run("a", &s("uptime"), None).await.unwrap();
    assert!(r.truncated && r.stdout.len() <= 4096);
    // The tool starts a grandchild and waits; at the deadline both are stopped.
    let slow = env_with(
        Kind::Ssh,
        r#"sleep 30 & echo $! > "$MARKS/gc"; wait"#,
        |c| c.timeout_secs = 1,
    );
    let r = slow.runner.run("a", &s("uptime"), None).await;
    assert!(matches!(r, Err(InfraError::Failed(_))), "{r:?}");
    let gc = std::fs::read_to_string(slow.marks.join("gc")).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let alive = std::process::Command::new("kill")
        .args(["-0", gc.trim()])
        .status()
        .unwrap()
        .success();
    assert!(!alive, "the grandchild {} outlived the deadline", gc.trim());
}

#[tokio::test]
async fn the_ssh_remote_command_is_one_word_from_the_table_after_the_forced_options() {
    let e = env_with(Kind::Ssh, r#"printf '%s\n' "$@""#, |c| {
        c.prefix = s("-p 2222 ops@db1");
    });
    let r = e
        .runner
        .run("a", &s("journalctl -u nginx -n 5"), None)
        .await
        .unwrap();
    let args: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(
        args,
        [
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ControlPath=none",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ClearAllForwardings=yes",
            "-p",
            "2222",
            "ops@db1",
            "journalctl --no-pager -u nginx -n 5"
        ]
    );
    // A prefix naming its own config file is refused at load.
    let mut c = e.conn(Kind::Ssh);
    c.prefix = s("-F /tmp/evil ops@db1");
    let audit = Arc::new(Audit::open(&e.tmp.path().join("audit3")).unwrap());
    assert!(Runner::new(c, &e.tmp.path().join("plans3"), audit).is_err());
}

#[tokio::test]
async fn ssh_units_outside_the_allow_list_are_refused() {
    let e = env_with(Kind::Ssh, "echo ok", |c| {
        c.units = Some(vec!["nginx.service".into()]);
    });
    assert!(
        e.runner
            .run("a", &s("journalctl -u nginx -n 5"), None)
            .await
            .is_ok()
    );
    let r = e.runner.run("a", &s("journalctl -u sshd -n 5"), None).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
}

#[tokio::test]
async fn key_file_contents_never_reach_the_output() {
    let t = tempfile::tempdir().unwrap();
    let key = t.path().join("id_ed25519");
    let body = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n-----END OPENSSH PRIVATE KEY-----\n";
    std::fs::write(&key, body).unwrap();
    let k = key.to_string_lossy().into_owned();
    let e = env_with(Kind::Ssh, &format!("cat '{k}'"), |c| {
        c.prefix = vec!["-i".into(), k.clone(), "ops@db1".into()];
    });
    let r = e.runner.run("a", &s("uptime"), None).await.unwrap();
    assert!(
        !r.stdout
            .contains("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ"),
        "{}",
        r.stdout
    );
}

#[tokio::test]
async fn a_tree_the_agent_can_write_is_never_planned_or_read() {
    let e = env(Kind::Kubectl, KUBECTL);
    e.write("m.yaml", "kind: Deployment\n");
    mode(&e.work, 0o755);
    for argv in ["get pods", "diff -f m.yaml"] {
        let r = e.runner.run("a", &s(argv), None).await;
        assert!(matches!(r, Err(InfraError::Refused(_))), "{argv}: {r:?}");
    }
    mode(&e.work, 0o575);
    let r = e.runner.run("a", &s("get pods"), None).await;
    assert!(
        matches!(r, Err(InfraError::Refused(_))),
        "group-writable: {r:?}"
    );
}

#[tokio::test]
async fn ansible_runs_with_the_tree_plugins_and_config_switched_off() {
    let body = r#"env | grep ^ANSIBLE_ | grep -v ^ANSIBLE_CONFIG= | sort; [ -f "$ANSIBLE_CONFIG" ] && [ ! -s "$ANSIBLE_CONFIG" ] && echo empty-config"#;
    let e = env(Kind::Ansible, body);
    e.write("site.yml", "- hosts: all\n");
    let r = e
        .runner
        .run("a", &s("--list-hosts site.yml"), None)
        .await
        .unwrap();
    assert!(r.plan_hash.is_none(), "a listing saves no plan");
    assert_eq!(
        r.stdout,
        "ANSIBLE_INVENTORY_ENABLED=yaml,ini\nANSIBLE_VARS_ENABLED=host_group_vars\nempty-config\n"
    );
}

const SLOW_APPLY: &str = r#"
case "$1" in
  diff) echo "+ replicas: 3"; exit 1 ;;
  apply) sleep 2; echo applied ;;
  *) exit 9 ;;
esac
"#;

#[tokio::test]
async fn one_apply_per_connection_at_a_time() {
    let e = env(Kind::Kubectl, SLOW_APPLY);
    e.write("m.yaml", "kind: Deployment\n");
    let hash = e
        .runner
        .run("a", &s("diff -f m.yaml"), None)
        .await
        .unwrap()
        .plan_hash
        .unwrap();
    e.fed.feed("l1", &hash);
    e.fed.feed("l2", &hash);
    let (a1, a2) = (
        Approval {
            id: "l1".into(),
            plan_hash: hash.clone(),
        },
        Approval {
            id: "l2".into(),
            plan_hash: hash,
        },
    );
    let apply = s("apply --server-side -f m.yaml");
    let second = async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        e.runner.run("a", &apply, Some(&a2)).await
    };
    let (r1, r2) = tokio::join!(e.runner.run("a", &apply, Some(&a1)), second);
    assert!(r1.is_ok(), "{r1:?}");
    assert!(
        matches!(r2, Err(InfraError::Denied(ref m)) if m.contains("another apply")),
        "{r2:?}"
    );
}

#[tokio::test]
async fn a_plan_is_bound_to_its_connection_and_expires() {
    let mut e = env_with(Kind::Kubectl, KUBECTL, |c| c.plan_ttl_secs = 1);
    e.write("m.yaml", "kind: Deployment\n");
    let hash = e
        .runner
        .run("a", &s("diff -f m.yaml"), None)
        .await
        .unwrap()
        .plan_hash
        .unwrap();
    e.fed.feed("x", &hash);
    let ap = Approval {
        id: "x".into(),
        plan_hash: hash.clone(),
    };
    let apply = s("apply --server-side -f m.yaml");
    // Another connection sharing the plans directory cannot apply it.
    let mut other = e.conn(Kind::Kubectl);
    other.name = "c2".into();
    e.rebuild(other);
    let r = e.runner.run("a", &apply, Some(&ap)).await;
    assert!(
        matches!(r, Err(InfraError::Denied(ref m)) if m.contains("another connection")),
        "{r:?}"
    );
    // Past the TTL the plan is refused on its own connection too.
    let mut same = e.conn(Kind::Kubectl);
    same.plan_ttl_secs = 1;
    e.rebuild(same);
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    let r = e.runner.run("a", &apply, Some(&ap)).await;
    assert!(
        matches!(r, Err(InfraError::Denied(ref m)) if m.contains("TTL")),
        "{r:?}"
    );
}

#[tokio::test]
async fn kubectl_resource_types_follow_the_allow_list() {
    let e = env_with(Kind::Kubectl, KUBECTL, |c| {
        c.resources = Some(vec!["deployments".into(), "pods".into()]);
    });
    assert!(
        e.runner
            .run("a", &s("get pods -n shop"), None)
            .await
            .is_ok()
    );
    let r = e.runner.run("a", &s("get configmaps -n shop"), None).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
    e.write("c.yaml", "kind: ConfigMap\n");
    let r = e.runner.run("a", &s("diff -f c.yaml"), None).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
}

#[tokio::test]
async fn helm_oci_charts_come_only_from_listed_registries() {
    let digest = "a".repeat(64);
    let e = env_with(Kind::Helm, "echo diff; exit 0", |c| {
        c.oci_registries = vec!["ghcr.io".into()];
    });
    let bad = format!("diff upgrade web oci://evil.example/charts/web@sha256:{digest}");
    let r = e.runner.run("a", &s(&bad), None).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
    let good = format!("diff upgrade web oci://ghcr.io/acme/web@sha256:{digest}");
    let r = e.runner.run("a", &s(&good), None).await;
    assert!(!matches!(r, Err(InfraError::Refused(_))), "{r:?}");
}

#[tokio::test]
async fn a_secret_manifest_is_never_planned_in_any_spelling_and_the_audit_names_it() {
    let e = env(Kind::Kubectl, KUBECTL);
    let list = r#"{"apiVersion":"v1","kind":"List","items":[{"kind":"Secret","metadata":{"namespace":"shop"},"data":{"a":"Yg=="}}]}"#;
    e.write("l.json", list);
    e.write("c.yaml", "apiVersion: v1\nkind: Secret # the db password\nmetadata:\n  namespace: shop\ndata:\n  a: Yg==\n");
    e.write("q.yaml", "apiVersion: v1\n\"kind\": 'Secret'\n");
    for f in ["l.json", "c.yaml", "q.yaml"] {
        let r = e.runner.run("a", &s(&format!("diff -f {f}")), None).await;
        assert!(matches!(r, Err(InfraError::Refused(_))), "{f}: {r:?}");
    }
    let audit = Audit::open(&e.tmp.path().join("audit")).unwrap();
    let recent = audit.recent(10);
    let hit = recent
        .iter()
        .find(|x| x.action == "infra.kubectl.refused" && x.reason.contains("l.json"))
        .unwrap();
    assert!(
        hit.reason.contains("kind Secret, namespace shop"),
        "{}",
        hit.reason
    );
    assert!(recent.iter().all(|x| !x.reason.contains("Yg==")));
}

#[tokio::test]
async fn every_run_is_audited_and_the_chain_verifies() {
    let e = env(Kind::Kubectl, KUBECTL);
    e.runner.run("a", &s("get pods"), None).await.unwrap();
    let _ = e.runner.run("a", &s("delete pod x"), None).await;
    let audit = Audit::open(&e.tmp.path().join("audit")).unwrap();
    let recent = audit.recent(10);
    assert!(
        recent
            .iter()
            .any(|x| x.action == "infra.kubectl.read" && x.outcome == "ok")
    );
    assert!(recent.iter().any(|x| x.action == "infra.kubectl.refused"));
    assert!(audit.verify().is_ok());
}

#[tokio::test]
async fn a_secret_in_any_positional_of_get_or_describe_is_refused() {
    let e = env_with(Kind::Kubectl, KUBECTL, |c| {
        c.resources = Some(vec!["pods".into()]);
    });
    for bad in [
        "get pod/a secret/db",
        "get pod/a Secrets.v1/db",
        "get pod/a,secret/db",
        "describe pod/a secrets/db",
        "get pod/a configmap/c",
    ] {
        let r = e.runner.run("a", &s(bad), None).await;
        assert!(matches!(r, Err(InfraError::Refused(_))), "{bad}: {r:?}");
    }
    for good in ["get pod/a", "get pods a", "describe pod/a"] {
        let r = e.runner.run("a", &s(good), None).await;
        assert!(r.is_ok(), "{good}: {r:?}");
    }
}

#[tokio::test]
async fn helm_template_output_with_a_secret_is_refused_and_never_saved() {
    let body = r"printf 'apiVersion: v1\nkind: Secret\ndata:\n  a: Yg==\n'";
    let e = env(Kind::Helm, body);
    let r = e
        .runner
        .run("a", &s("template web repo/web --version 1.2.3"), None)
        .await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
    let plans = e.tmp.path().join("plans");
    let saved = std::fs::read_dir(&plans).map_or(0, |d| {
        d.filter_map(Result::ok)
            .filter(|x| x.path().join("plan.json").exists() || x.path().is_dir())
            .count()
    });
    assert_eq!(saved, 0, "no plan is saved for a refused render");
    let ok = env(Kind::Helm, "printf 'kind: Deployment\\n'");
    let r = ok
        .runner
        .run("a", &s("template web repo/web --version 1.2.3"), None)
        .await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test]
async fn url_passwords_and_every_env_value_are_redacted() {
    let e = env_with(
        Kind::Kubectl,
        r#"echo "dsn postgres://admin:pw-not-in-env@db:5432/x"; echo "ctx=$APP_CONTEXT""#,
        |c| {
            c.env
                .insert("APP_CONTEXT".into(), "plain-context-value".into());
        },
    );
    let r = e.runner.run("a", &s("get pods"), None).await.unwrap();
    assert!(
        r.stdout.contains("postgres://[redacted]@db:5432/x"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("pw-not-in-env"), "{}", r.stdout);
    assert!(!r.stdout.contains("plain-context-value"), "{}", r.stdout);
}

#[tokio::test]
async fn swapping_the_kubeconfig_file_between_plan_and_apply_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let kc = dir.path().join("kc");
    std::fs::write(&kc, "users: [one]").unwrap();
    let kcfile = kc.to_string_lossy().into_owned();
    let body = "shift 2; case \"$1\" in diff) echo diff; exit 1 ;; *) echo applied ;; esac";
    let e = env_with(Kind::Kubectl, body, |c| {
        c.prefix = vec!["--kubeconfig".into(), kcfile.clone()];
    });
    e.write("m.yaml", "kind: Deployment\n");
    let hash = e
        .runner
        .run("a", &s("diff -f m.yaml"), None)
        .await
        .unwrap()
        .plan_hash
        .unwrap();
    std::fs::write(&kc, "users: [two]").unwrap();
    e.fed.feed("kc", &hash);
    let ap = Approval {
        id: "kc".into(),
        plan_hash: hash,
    };
    let res = e
        .runner
        .run("a", &s("apply --server-side -f m.yaml"), Some(&ap))
        .await;
    assert!(
        matches!(res, Err(InfraError::Denied(ref m)) if m.contains("context")),
        "{res:?}"
    );
}

#[tokio::test]
async fn a_tofu_apply_needs_the_trusted_tree_too() {
    let e = env(Kind::Tofu, TOFU);
    let hash = e
        .runner
        .run("a", &s("plan"), None)
        .await
        .unwrap()
        .plan_hash
        .unwrap();
    mode(&e.work, 0o755);
    e.fed.feed("tt", &hash);
    let ap = Approval {
        id: "tt".into(),
        plan_hash: hash,
    };
    let r = e.runner.run("a", &s("apply"), Some(&ap)).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
    assert!(!e.marks.join("tofu-applied").exists());
}

#[tokio::test]
async fn a_background_process_does_not_outlive_a_command_that_exited() {
    let e = env(
        Kind::Ssh,
        r#"sleep 30 > /dev/null 2>&1 & echo $! > "$MARKS/gc"; echo done"#,
    );
    let r = e.runner.run("a", &s("uptime"), None).await.unwrap();
    assert_eq!(r.stdout.trim(), "done");
    let gc = std::fs::read_to_string(e.marks.join("gc")).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let alive = std::process::Command::new("kill")
        .args(["-0", gc.trim()])
        .status()
        .unwrap()
        .success();
    assert!(
        !alive,
        "the background process {} outlived the command",
        gc.trim()
    );
}

#[tokio::test]
async fn a_tofu_plan_on_the_local_backend_is_refused() {
    let e = env(Kind::Tofu, TOFU);
    mode(&e.work, 0o755);
    std::fs::create_dir_all(e.work.join(".terraform")).unwrap();
    std::fs::write(
        e.work.join(".terraform/terraform.tfstate"),
        r#"{"version":3,"backend":{"type":"local","config":{}}}"#,
    )
    .unwrap();
    mode(&e.work, 0o555);
    let r = e.runner.run("a", &s("plan"), None).await;
    assert!(
        matches!(r, Err(InfraError::Refused(ref m)) if m.contains("local backend")),
        "{r:?}"
    );
    mode(&e.work, 0o755);
    std::fs::write(
        e.work.join(".terraform/terraform.tfstate"),
        r#"{"version":3,"backend":{"type":"s3","config":{}}}"#,
    )
    .unwrap();
    mode(&e.work, 0o555);
    let r = e.runner.run("a", &s("plan"), None).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test]
async fn a_tofu_plan_without_an_initialised_backend_is_refused() {
    let e = env(Kind::Tofu, TOFU);
    // An implicit local backend leaves no file at all; an unreadable one is no better.
    mode(&e.work, 0o755);
    std::fs::remove_file(e.work.join(".terraform/terraform.tfstate")).unwrap();
    mode(&e.work, 0o555);
    let r = e.runner.run("a", &s("plan"), None).await;
    assert!(
        matches!(r, Err(InfraError::Refused(ref m)) if m.contains("run tofu init with a remote backend")),
        "{r:?}"
    );
    mode(&e.work, 0o755);
    std::fs::write(e.work.join(".terraform/terraform.tfstate"), "not json").unwrap();
    mode(&e.work, 0o555);
    let r = e.runner.run("a", &s("plan"), None).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
}

#[tokio::test]
async fn a_kind_that_cannot_be_read_as_a_plain_name_refuses_the_manifest() {
    let e = env(Kind::Kubectl, KUBECTL);
    for (i, bad) in [
        "kind:\n  Secret\n",
        "kind: !!str Secret\n",
        "kind: |\n  Secret\n",
        "kind: \"\"\n",
    ]
    .iter()
    .enumerate()
    {
        let name = format!("m{i}.yaml");
        e.write(&name, bad);
        let r = e
            .runner
            .run("a", &s(&format!("diff -f {name}")), None)
            .await;
        assert!(matches!(r, Err(InfraError::Refused(_))), "{bad:?}: {r:?}");
    }
    e.write("ok.yaml", "kind: Deployment\n");
    let r = e.runner.run("a", &s("diff -f ok.yaml"), None).await;
    assert!(r.is_ok(), "{r:?}");
}

#[tokio::test]
async fn every_file_of_a_kubeconfig_list_is_learned() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::write(&a, "token: first-file-token-0123456789").unwrap();
    std::fs::write(&b, "token: second-file-token-9876543210").unwrap();
    let list = format!("{}:{}", a.display(), b.display());
    let e = env_with(
        Kind::Kubectl,
        &format!("cat '{}' '{}'", a.display(), b.display()),
        |c| {
            c.env.insert("KUBECONFIG".into(), list);
        },
    );
    let r = e.runner.run("a", &s("get pods"), None).await.unwrap();
    assert!(!r.stdout.contains("second-file-token"), "{}", r.stdout);
    assert!(!r.stdout.contains("first-file-token"), "{}", r.stdout);
}

#[tokio::test]
async fn swapping_a_file_named_by_an_env_path_between_plan_and_apply_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("cfg");
    std::fs::write(&cfg, "one").unwrap();
    let path = cfg.to_string_lossy().into_owned();
    let e = env_with(
        Kind::Kubectl,
        "case \"$1\" in diff) echo d; exit 1 ;; *) echo applied ;; esac",
        |c| {
            c.env.insert("KUBE_CONFIG_PATH".into(), path);
        },
    );
    e.write("m.yaml", "kind: Deployment\n");
    let hash = e
        .runner
        .run("a", &s("diff -f m.yaml"), None)
        .await
        .unwrap()
        .plan_hash
        .unwrap();
    std::fs::write(&cfg, "two").unwrap();
    e.fed.feed("kp", &hash);
    let ap = Approval {
        id: "kp".into(),
        plan_hash: hash,
    };
    let res = e
        .runner
        .run("a", &s("apply --server-side -f m.yaml"), Some(&ap))
        .await;
    assert!(
        matches!(res, Err(InfraError::Denied(ref m)) if m.contains("context")),
        "{res:?}"
    );
}
