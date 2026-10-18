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

fn env(kind: Kind, body: &str) -> Env {
    let t = tempfile::tempdir().unwrap();
    let bins = t.path().join("bin");
    let work = t.path().join("work");
    std::fs::create_dir_all(&bins).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    let marks = t.path().join("marks");
    std::fs::create_dir_all(&marks).unwrap();
    let bin = script(&bins, "tool", body);
    let conn = Conn {
        name: "c1".into(),
        kind,
        bin,
        aux_bin: None,
        workdir: work.clone(),
        prefix: vec![],
        env: BTreeMap::from([("MARKS".into(), marks.to_string_lossy().into_owned()), ("PATH".into(), "/usr/bin:/bin".into())]),
        timeout_secs: 10,
        max_output: 4096,
    };
    let audit = Arc::new(Audit::open(&t.path().join("audit")).unwrap());
    let fed = Arc::new(FedApprovals::new());
    let runner = Runner::new(conn, &t.path().join("plans"), audit).unwrap().with_approvals(fed.clone());
    Env { tmp: t, work, marks, runner, fed }
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
    std::fs::write(e.work.join("m.yaml"), "kind: Deployment\nreplicas: 3\n").unwrap();
    let plan = e.runner.run("alice", &s("diff -f m.yaml -n shop"), None).await.unwrap();
    let hash = plan.plan_hash.clone().unwrap();
    assert!(hash.starts_with("sha256:") && hash.len() == 71);
    assert!(!plan.stdout.contains("hunter2hunter2"), "plan output is redacted: {}", plan.stdout);
    // The file is edited after the plan: the apply still runs the snapshot.
    std::fs::write(e.work.join("m.yaml"), "kind: Deployment\nreplicas: 99\n").unwrap();
    e.fed.feed("ap1", &hash);
    let ap = Approval { id: "ap1".into(), plan_hash: hash.clone() };
    let r = e.runner.run("alice", &s("apply --server-side -f m.yaml -n shop"), Some(&ap)).await.unwrap();
    assert_eq!(r.code, 0);
    let applied = std::fs::read_to_string(e.marks.join("applied")).unwrap();
    assert!(applied.contains("replicas: 3"), "applied the snapshot, got {applied:?}");
    // Single use.
    let again = e.runner.run("alice", &s("apply --server-side -f m.yaml -n shop"), Some(&ap)).await;
    assert!(matches!(again, Err(InfraError::Denied(_))), "{again:?}");
}

#[tokio::test]
async fn apply_is_refused_without_or_with_the_wrong_hash() {
    let e = env(Kind::Kubectl, KUBECTL);
    std::fs::write(e.work.join("m.yaml"), "kind: Deployment\n").unwrap();
    let plan = e.runner.run("alice", &s("diff -f m.yaml"), None).await.unwrap();
    let hash = plan.plan_hash.unwrap();
    let apply = s("apply --server-side -f m.yaml");
    // No approval at all.
    assert!(matches!(e.runner.run("a", &apply, None).await, Err(InfraError::Denied(_))));
    // An approval for another hash.
    let other = sha256_of(b"another plan");
    e.fed.feed("ap2", &other);
    let bad = Approval { id: "ap2".into(), plan_hash: other };
    assert!(matches!(e.runner.run("a", &apply, Some(&bad)).await, Err(InfraError::Denied(_))));
    // A right hash that the checker never issued.
    let unissued = Approval { id: "nope".into(), plan_hash: hash.clone() };
    assert!(matches!(e.runner.run("a", &apply, Some(&unissued)).await, Err(InfraError::Denied(_))));
    // A good approval used for a different apply (other namespace) is refused and not spent.
    e.fed.feed("ap3", &hash);
    let good = Approval { id: "ap3".into(), plan_hash: hash };
    let other_ns = e.runner.run("a", &s("apply --server-side -f m.yaml -n prod"), Some(&good)).await;
    assert!(matches!(other_ns, Err(InfraError::Denied(_))), "{other_ns:?}");
    assert!(e.runner.run("a", &apply, Some(&good)).await.is_ok(), "the approval was not burned by the refusal");
}

#[tokio::test]
async fn a_tampered_snapshot_blocks_the_apply() {
    let e = env(Kind::Kubectl, KUBECTL);
    std::fs::write(e.work.join("m.yaml"), "kind: Deployment\n").unwrap();
    let hash = e.runner.run("a", &s("diff -f m.yaml"), None).await.unwrap().plan_hash.unwrap();
    let dir = e.tmp.path().join("plans").join(hash.strip_prefix("sha256:").unwrap());
    std::fs::write(dir.join("files/m.yaml"), "kind: Deployment\nevil: true\n").unwrap();
    e.fed.feed("ap", &hash);
    let ap = Approval { id: "ap".into(), plan_hash: hash };
    let r = e.runner.run("a", &s("apply --server-side -f m.yaml"), Some(&ap)).await;
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
    let ap = Approval { id: "t1".into(), plan_hash: hash };
    e.runner.run("a", &s("apply"), Some(&ap)).await.unwrap();
    assert_eq!(std::fs::read_to_string(e.marks.join("tofu-applied")).unwrap(), "plan-bytes-v1\n");
}

#[tokio::test]
async fn reads_run_freely_and_are_redacted_and_refusals_never_start_a_process() {
    let e = env(Kind::Kubectl, KUBECTL);
    let r = e.runner.run("a", &s("get pods -n shop"), None).await.unwrap();
    assert_eq!(r.stdout.trim(), "pod/web");
    for bad in ["get secrets", "exec web -- sh", "delete pod web", "get pods; touch x"] {
        let r = e.runner.run("a", &s(bad), None).await;
        assert!(matches!(r, Err(InfraError::Refused(_))), "{bad}: {r:?}");
    }
    assert!(!e.work.join("x").exists());
}

#[tokio::test]
async fn a_secret_manifest_is_never_planned() {
    let e = env(Kind::Kubectl, KUBECTL);
    std::fs::write(e.work.join("s.yaml"), "apiVersion: v1\nkind: Secret\ndata:\n  a: Yg==\n").unwrap();
    let r = e.runner.run("a", &s("diff -f s.yaml"), None).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
}

#[tokio::test]
async fn path_escapes_are_refused() {
    let e = env(Kind::Kubectl, KUBECTL);
    std::os::unix::fs::symlink("/etc/hosts", e.work.join("link.yaml")).unwrap();
    let r = e.runner.run("a", &s("diff -f link.yaml"), None).await;
    assert!(matches!(r, Err(InfraError::Refused(_))), "{r:?}");
}

#[tokio::test]
async fn output_is_capped_and_the_deadline_kills() {
    let e = env(Kind::Ssh, "yes x | head -c 100000; echo");
    let r = e.runner.run("a", &s("uptime"), None).await.unwrap();
    assert!(r.truncated && r.stdout.len() <= 4096);
    let mut slow = env(Kind::Ssh, "sleep 30");
    // Rebuild the runner with a one second deadline.
    let conn = Conn { name: "c".into(), kind: Kind::Ssh, bin: slow.work.parent().unwrap().join("bin/tool"), aux_bin: None, workdir: slow.work.clone(), prefix: vec![], env: BTreeMap::new(), timeout_secs: 1, max_output: 4096 };
    let audit = Arc::new(Audit::open(&slow.work.parent().unwrap().join("audit2")).unwrap());
    slow.runner = Runner::new(conn, &slow.work.parent().unwrap().join("plans2"), audit).unwrap();
    let r = slow.runner.run("a", &s("uptime"), None).await;
    assert!(matches!(r, Err(InfraError::Failed(_))), "{r:?}");
}

#[tokio::test]
async fn the_ssh_remote_command_is_one_word_from_the_table() {
    let e = env(Kind::Ssh, r#"printf '%s\n' "$#" "$1""#);
    let r = e.runner.run("a", &s("journalctl -u nginx -n 5"), None).await.unwrap();
    assert_eq!(r.stdout, "1\njournalctl --no-pager -u nginx -n 5\n");
}

#[tokio::test]
async fn every_run_is_audited_and_the_chain_verifies() {
    let e = env(Kind::Kubectl, KUBECTL);
    e.runner.run("a", &s("get pods"), None).await.unwrap();
    let _ = e.runner.run("a", &s("delete pod x"), None).await;
    let audit = Audit::open(&e.tmp.path().join("audit")).unwrap();
    let recent = audit.recent(10);
    assert!(recent.iter().any(|x| x.action == "infra.kubectl.read" && x.outcome == "ok"));
    assert!(recent.iter().any(|x| x.action == "infra.kubectl.refused"));
    assert!(audit.verify().is_ok());
}
