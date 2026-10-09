//! The system as its code describes it, read from a checkout: Cargo manifests (which
//! crates exist and depend on which), Kubernetes manifests (what runs where, with which
//! image and secrets, what selects and reaches what) and Envoy's static routes (which
//! path goes to which cluster, and where that cluster points). Every file read is an
//! artefact observation; every fact derived from it cites that artefact.
//!
//! The reader runs no program: `cargo metadata` is what the manifests say, read directly.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use iohr_evidence::ids::ArtifactObservationId;
use iohr_evidence::method::MethodCategory;
use iohr_evidence::observer::ObserverClass;
use iohr_evidence::vocabulary::Value as EvValue;
use serde::Deserialize as _;
use serde_json::Value;

use super::common::{Ctx, ObservedNow, method};
use super::k8s;
use super::record::Sink;
use crate::error::{Error, Result};

/// The largest file read.
const MAX_FILE: u64 = 8 * 1024 * 1024;
/// How deep the walk goes.
const MAX_DEPTH: usize = 12;
/// Directories never entered.
const SKIPPED_DIRS: [&str; 6] = [
    "target",
    "node_modules",
    "dist",
    "build",
    "vendor",
    ".cargo",
];

/// The methods this reader writes through.
pub mod methods {
    /// Cargo manifests.
    pub const CARGO: &str = "cargo.metadata";
    /// Kubernetes workloads and services.
    pub const K8S: &str = "k8s.manifest";
    /// Network policies.
    pub const NETPOL: &str = "k8s.networkpolicy";
    /// Envoy routes and clusters.
    pub const ENVOY: &str = "envoy.route";
}

/// A checkout.
#[derive(Debug, Clone)]
pub struct Repo {
    root: PathBuf,
    /// The directory's name.
    pub name: String,
    /// The commit checked out, if this is a git checkout.
    pub commit: Option<String>,
}

impl Repo {
    /// Opens `path`.
    ///
    /// # Errors
    /// The path is not a directory.
    pub fn open(path: &Path) -> Result<Self> {
        let root = path.canonicalize().map_err(|e| Error::io(path, e))?;
        if !root.is_dir() {
            return Err(Error::Atlas(format!("{}: not a directory", path.display())));
        }
        let name = root.file_name().map_or_else(
            || "repository".to_owned(),
            |n| n.to_string_lossy().into_owned(),
        );
        let commit = git_head(&root);
        Ok(Self { root, name, commit })
    }

    /// The location an artefact at `rel` is cited by: name, commit and path, never the
    /// absolute path.
    fn location(&self, rel: &Path) -> String {
        let rel = rel.to_string_lossy();
        match &self.commit {
            Some(c) => format!("{}@{c}:{rel}", self.name),
            None => format!("{}:{rel}", self.name),
        }
    }

    /// Every regular file under the root with one of `extensions`, as relative paths,
    /// sorted. Skips build output, dependencies and hidden directories.
    pub(super) fn files(&self, extensions: &[&str]) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![(self.root.clone(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(ft) = entry.file_type() else { continue };
                let fname = entry.file_name().to_string_lossy().into_owned();
                if ft.is_dir() {
                    if depth < MAX_DEPTH
                        && !fname.starts_with('.')
                        && !SKIPPED_DIRS.contains(&fname.as_str())
                    {
                        stack.push((path, depth + 1));
                    }
                } else if ft.is_file()
                    && path
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| extensions.contains(&e))
                    && let Ok(rel) = path.strip_prefix(&self.root)
                {
                    out.push(rel.to_path_buf());
                }
            }
        }
        out.sort();
        out
    }

    /// Reads `rel`, records the artefact, and returns its bytes with the artefact id.
    pub(super) fn read(
        &self,
        ctx: &Ctx,
        sink: &mut Sink,
        rel: &Path,
    ) -> Result<Option<(Vec<u8>, ArtifactObservationId)>> {
        let path = self.root.join(rel);
        let meta = std::fs::metadata(&path).map_err(|e| Error::io(&path, e))?;
        if meta.len() > MAX_FILE {
            tracing::debug!(path = %rel.display(), "skipped: larger than the limit");
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|e| Error::io(&path, e))?;
        let id = ctx.artifact(sink, &self.location(rel), &bytes)?;
        Ok(Some((bytes, id)))
    }
}

/// The commit `root` has checked out: `.git/HEAD`, through `gitdir:` files (worktrees),
/// symbolic refs and `packed-refs`. None when it is not a git checkout.
fn git_head(root: &Path) -> Option<String> {
    let dotgit = root.join(".git");
    let gitdir = if dotgit.is_file() {
        let text = std::fs::read_to_string(&dotgit).ok()?;
        let rel = text.strip_prefix("gitdir:")?.trim();
        let p = PathBuf::from(rel);
        if p.is_absolute() { p } else { root.join(p) }
    } else if dotgit.is_dir() {
        dotgit
    } else {
        return None;
    };
    let head = std::fs::read_to_string(gitdir.join("HEAD")).ok()?;
    let head = head.trim();
    let Some(reference) = head.strip_prefix("ref:") else {
        return is_hex(head).then(|| head.to_owned());
    };
    let reference = reference.trim();
    let common = std::fs::read_to_string(gitdir.join("commondir"))
        .ok()
        .map_or_else(
            || gitdir.clone(),
            |c| {
                let p = PathBuf::from(c.trim());
                if p.is_absolute() { p } else { gitdir.join(p) }
            },
        );
    for base in [&gitdir, &common] {
        if let Ok(s) = std::fs::read_to_string(base.join(reference)) {
            let s = s.trim();
            if is_hex(s) {
                return Some(s.to_owned());
            }
        }
    }
    let packed = std::fs::read_to_string(common.join("packed-refs")).ok()?;
    packed
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('^'))
        .filter_map(|l| l.split_once(' '))
        .find(|(_, r)| *r == reference)
        .map(|(sha, _)| sha.to_owned())
        .filter(|s| is_hex(s))
}

fn is_hex(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What one reading of a checkout found, for the summary.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Found {
    /// Cargo manifests read.
    pub cargo_manifests: usize,
    /// Kubernetes objects read, by kind.
    pub k8s_objects: BTreeMap<String, usize>,
    /// Envoy routes read.
    pub envoy_routes: usize,
    /// The decided world: documents, typed facts, constraint sentences, refusals.
    pub decided: super::decided::Found,
}

/// A parsed Kubernetes object with the artefact it came from.
struct Object {
    namespace: String,
    value: Value,
    artifact: ArtifactObservationId,
}

/// Reads the checkout and writes what it finds to `sink`.
///
/// # Errors
/// A file could not be read, or a record could not be built.
pub fn observe(repo: &Repo, sink: &mut Sink, clock: &ObservedNow) -> Result<Found> {
    let principal = std::env::var("USER").unwrap_or_else(|_| "local".to_owned());
    let mut found = Found::default();
    let cargo = Ctx::new(
        sink,
        "cargo-manifest-reader",
        ObserverClass::DeterministicExtractor,
        method(methods::CARGO, MethodCategory::StaticResolution)?,
        &principal,
        &["read"],
        clock,
    )?;
    found.cargo_manifests = observe_cargo(repo, &cargo, sink)?;

    let k8s_ctx = Ctx::new(
        sink,
        "k8s-manifest-reader",
        ObserverClass::DeterministicExtractor,
        method(methods::K8S, MethodCategory::Configuration)?,
        &principal,
        &["read"],
        clock,
    )?;
    let netpol_ctx = Ctx::new(
        sink,
        "k8s-networkpolicy-reader",
        ObserverClass::DeterministicExtractor,
        method(methods::NETPOL, MethodCategory::Configuration)?,
        &principal,
        &["read"],
        clock,
    )?;
    let envoy_ctx = Ctx::new(
        sink,
        "envoy-route-reader",
        ObserverClass::DeterministicExtractor,
        method(methods::ENVOY, MethodCategory::Configuration)?,
        &principal,
        &["read"],
        clock,
    )?;

    let mut objects: Vec<Object> = Vec::new();
    let mut envoy: Vec<(Value, ArtifactObservationId)> = Vec::new();
    let mut namespaces = NamespaceLookup::default();
    for rel in repo.files(&["yaml", "yml"]) {
        let is_envoy = rel.file_name().is_some_and(|n| n == "envoy.yaml");
        let ctx = if is_envoy { &envoy_ctx } else { &k8s_ctx };
        let Some((bytes, artifact)) = repo.read(ctx, sink, &rel)? else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if is_envoy {
            for doc in parse_yaml(text) {
                if doc.get("static_resources").is_some() {
                    envoy.push((doc, artifact));
                }
            }
            continue;
        }
        let dir = rel.parent().unwrap_or_else(|| Path::new(""));
        for doc in parse_yaml(text) {
            let Some(kind) = k8s::kind(&doc) else {
                continue;
            };
            if doc.get("apiVersion").is_none() || k8s::name(&doc).is_none() {
                continue;
            }
            if ![
                "Deployment",
                "StatefulSet",
                "DaemonSet",
                "Service",
                "NetworkPolicy",
            ]
            .contains(&kind)
            {
                continue;
            }
            let namespace = doc
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .map_or_else(|| namespaces.for_dir(repo, dir), ToOwned::to_owned);
            *found.k8s_objects.entry(kind.to_owned()).or_insert(0) += 1;
            objects.push(Object {
                namespace,
                value: doc,
                artifact,
            });
        }
    }
    observe_k8s(&k8s_ctx, &netpol_ctx, &objects, sink)?;
    for (doc, artifact) in &envoy {
        found.envoy_routes += observe_envoy(&envoy_ctx, doc, *artifact, &objects, sink)?;
    }

    let decided_ctx = Ctx::new(
        sink,
        "decided-document-reader",
        ObserverClass::DeterministicExtractor,
        method(super::decided::METHOD, MethodCategory::Configuration)?,
        &principal,
        &["read"],
        clock,
    )?;
    for rel in repo.files(&["md"]) {
        let Some(kind) = super::decided::kind_for(&rel) else {
            continue;
        };
        let Some((bytes, artifact)) = repo.read(&decided_ctx, sink, &rel)? else {
            continue;
        };
        super::decided::observe_document(
            &decided_ctx,
            sink,
            &rel,
            kind,
            &bytes,
            artifact,
            &mut found.decided,
        )?;
    }
    Ok(found)
}

/// Every document in `text` that is a map; a document that does not parse is skipped
/// (a Helm template, say), because a reader reports what it read, not what it guessed.
fn parse_yaml(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for doc in serde_yaml_ng::Deserializer::from_str(text) {
        match Value::deserialize(doc) {
            Ok(v) if v.is_object() => out.push(v),
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(error = %e, "skipped a YAML document that does not parse");
                break;
            }
        }
    }
    out
}

/// The namespace a manifest lands in: the nearest `kustomization.yaml` up the tree that
/// sets one, else `default`.
#[derive(Default)]
struct NamespaceLookup {
    cache: BTreeMap<PathBuf, Option<String>>,
}

impl NamespaceLookup {
    fn for_dir(&mut self, repo: &Repo, dir: &Path) -> String {
        let mut cur = Some(dir.to_path_buf());
        while let Some(d) = cur {
            if let Some(ns) = self.at(repo, &d) {
                return ns;
            }
            cur = if d.as_os_str().is_empty() {
                None
            } else {
                d.parent().map(Path::to_path_buf)
            };
        }
        "default".to_owned()
    }

    fn at(&mut self, repo: &Repo, dir: &Path) -> Option<String> {
        if let Some(v) = self.cache.get(dir) {
            return v.clone();
        }
        let ns = ["kustomization.yaml", "kustomization.yml"]
            .iter()
            .find_map(|k| std::fs::read_to_string(repo.root.join(dir).join(k)).ok())
            .and_then(|t| parse_yaml(&t).into_iter().next())
            .and_then(|v| {
                v.get("namespace")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
        self.cache.insert(dir.to_path_buf(), ns.clone());
        ns
    }
}

#[allow(clippy::too_many_lines)] // one pass over the objects, in reading order
fn observe_cargo(repo: &Repo, ctx: &Ctx, sink: &mut Sink) -> Result<usize> {
    struct Manifest {
        name: String,
        rel: PathBuf,
        deps: Vec<String>,
        artifact: ArtifactObservationId,
        workspace_members: bool,
    }
    let mut manifests: Vec<Manifest> = Vec::new();
    for rel in repo.files(&["toml"]) {
        if rel.file_name().is_none_or(|n| n != "Cargo.toml") {
            continue;
        }
        let Some((bytes, artifact)) = repo.read(ctx, sink, &rel)? else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let Ok(doc) = toml::from_str::<toml::Value>(text) else {
            tracing::debug!(path = %rel.display(), "skipped a manifest that does not parse");
            continue;
        };
        let workspace_members = doc.get("workspace").is_some();
        let Some(name) = doc
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
        else {
            if workspace_members {
                manifests.push(Manifest {
                    name: String::new(),
                    rel,
                    deps: Vec::new(),
                    artifact,
                    workspace_members,
                });
            }
            continue;
        };
        let mut deps = Vec::new();
        for table in ["dependencies", "dev-dependencies", "build-dependencies"] {
            let Some(t) = doc.get(table).and_then(toml::Value::as_table) else {
                continue;
            };
            for (key, spec) in t {
                // A renamed dependency names the real crate in `package`.
                let real = spec
                    .get("package")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(key);
                deps.push(real.to_owned());
            }
        }
        manifests.push(Manifest {
            name: name.to_owned(),
            rel,
            deps,
            artifact,
            workspace_members,
        });
    }
    let names: BTreeMap<&str, &Manifest> = manifests
        .iter()
        .filter(|m| !m.name.is_empty())
        .map(|m| (m.name.as_str(), m))
        .collect();
    for m in &manifests {
        if m.name.is_empty() {
            continue;
        }
        let key = format!("crate/{}", m.name);
        ctx.observe(
            sink,
            &key,
            "defined_in",
            EvValue::Text(m.rel.to_string_lossy().into_owned()),
            &[m.artifact],
        )?;
        for d in &m.deps {
            // Only edges inside the checkout: a registry crate is not a component here.
            if let Some(target) = names.get(d.as_str()) {
                let dep = sink.entity(&format!("crate/{}", target.name));
                ctx.observe(
                    sink,
                    &key,
                    "depends_on",
                    EvValue::Entity(dep),
                    &[m.artifact, target.artifact],
                )?;
            }
        }
    }
    for m in manifests.iter().filter(|m| m.workspace_members) {
        let key = format!("workspace/{}", repo.name);
        ctx.observe(
            sink,
            &key,
            "defined_in",
            EvValue::Text(m.rel.to_string_lossy().into_owned()),
            &[m.artifact],
        )?;
    }
    Ok(manifests.len())
}

#[allow(clippy::too_many_lines)] // one pass over the objects, in reading order
fn observe_k8s(k8s_ctx: &Ctx, netpol_ctx: &Ctx, objects: &[Object], sink: &mut Sink) -> Result<()> {
    let workloads: Vec<&Object> = objects
        .iter()
        .filter(|o| {
            matches!(
                k8s::kind(&o.value),
                Some("Deployment" | "StatefulSet" | "DaemonSet")
            )
        })
        .collect();
    for o in &workloads {
        let kind = k8s::kind(&o.value)
            .unwrap_or("Deployment")
            .to_ascii_lowercase();
        let Some(name) = k8s::name(&o.value) else {
            continue;
        };
        let key = format!("{kind}/{}/{name}", o.namespace);
        for image in k8s::images(&o.value) {
            k8s_ctx.observe(
                sink,
                &key,
                "runs_image",
                EvValue::Text(image.to_owned()),
                &[o.artifact],
            )?;
        }
        let labels = k8s::pod_labels(&o.value);
        if !labels.is_empty() {
            k8s_ctx.observe(
                sink,
                &key,
                "labelled",
                EvValue::Text(k8s::render_labels(&labels)),
                &[o.artifact],
            )?;
        }
        for (secret, skey) in k8s::secret_refs(&o.value) {
            let s = sink.entity(&format!("secret/{}/{secret}", o.namespace));
            k8s_ctx.observe(
                sink,
                &key,
                "reads_secret",
                EvValue::Entity(s),
                &[o.artifact],
            )?;
            if !skey.is_empty() {
                k8s_ctx.observe(
                    sink,
                    &key,
                    "reads_secret_key",
                    EvValue::Text(format!("{secret}/{skey}")),
                    &[o.artifact],
                )?;
            }
        }
    }
    for o in objects
        .iter()
        .filter(|o| k8s::kind(&o.value) == Some("Service"))
    {
        let Some(name) = k8s::name(&o.value) else {
            continue;
        };
        let key = format!("service/{}/{name}", o.namespace);
        let selector = k8s::labels(o.value.pointer("/spec/selector"));
        if !selector.is_empty() {
            k8s_ctx.observe(
                sink,
                &key,
                "selects",
                EvValue::Text(k8s::render_labels(&selector)),
                &[o.artifact],
            )?;
            for w in &workloads {
                if w.namespace == o.namespace
                    && k8s::plain_selector_matches(&selector, &k8s::pod_labels(&w.value))
                {
                    let kind = k8s::kind(&w.value)
                        .unwrap_or("Deployment")
                        .to_ascii_lowercase();
                    let Some(wname) = k8s::name(&w.value) else {
                        continue;
                    };
                    let target = sink.entity(&format!("{kind}/{}/{wname}", w.namespace));
                    k8s_ctx.observe(
                        sink,
                        &key,
                        "targets",
                        EvValue::Entity(target),
                        &[o.artifact, w.artifact],
                    )?;
                }
            }
        }
        for port in o
            .value
            .pointer("/spec/ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(n) = port.get("port").and_then(Value::as_i64) {
                k8s_ctx.observe(sink, &key, "exposes_port", EvValue::Int(n), &[o.artifact])?;
            }
        }
    }
    for o in objects
        .iter()
        .filter(|o| k8s::kind(&o.value) == Some("NetworkPolicy"))
    {
        let Some(name) = k8s::name(&o.value) else {
            continue;
        };
        let key = format!("networkpolicy/{}/{name}", o.namespace);
        let selector = o
            .value
            .pointer("/spec/podSelector")
            .cloned()
            .unwrap_or(Value::Null);
        netpol_ctx.observe(
            sink,
            &key,
            "selects",
            EvValue::Text(k8s::render_selector(&selector)),
            &[o.artifact],
        )?;
        for w in &workloads {
            if w.namespace == o.namespace
                && k8s::selector_matches(&selector, &k8s::pod_labels(&w.value))
            {
                let kind = k8s::kind(&w.value)
                    .unwrap_or("Deployment")
                    .to_ascii_lowercase();
                let Some(wname) = k8s::name(&w.value) else {
                    continue;
                };
                let target = sink.entity(&format!("{kind}/{}/{wname}", w.namespace));
                netpol_ctx.observe(
                    sink,
                    &key,
                    "applies_to",
                    EvValue::Entity(target),
                    &[o.artifact, w.artifact],
                )?;
            }
        }
        for rule in o
            .value
            .pointer("/spec/egress")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            netpol_ctx.observe(
                sink,
                &key,
                "allows_egress",
                EvValue::Text(k8s::render_egress(rule)),
                &[o.artifact],
            )?;
        }
    }
    Ok(())
}

/// The text a route matches on: `prefix:/v1`, `path:/healthz`, `path_separated_prefix:/v1/labs`,
/// `regex:…`, or `any`, then `grpc` and each header condition, so two routes that differ
/// only by a header are two routes.
fn route_match(m: &Value) -> String {
    let mut out = "any".to_owned();
    for key in ["path_separated_prefix", "prefix", "path"] {
        if let Some(v) = m.get(key).and_then(Value::as_str) {
            out = format!("{key}:{v}");
            break;
        }
    }
    if let Some(r) = m.pointer("/safe_regex/regex").and_then(Value::as_str) {
        out = format!("regex:{r}");
    }
    if m.get("grpc").is_some() {
        out.push_str(" grpc");
    }
    for h in m
        .get("headers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = h.get("name").and_then(Value::as_str).unwrap_or("?");
        let sm = h.get("string_match");
        let cond = ["exact", "prefix", "suffix", "contains"]
            .iter()
            .find_map(|k| {
                sm.and_then(|s| s.get(*k))
                    .or_else(|| h.get(format!("{k}_match")))
                    .and_then(Value::as_str)
                    .map(|v| format!("{k}:{v}"))
            })
            .or_else(|| {
                sm.and_then(|s| s.pointer("/safe_regex/regex"))
                    .and_then(Value::as_str)
                    .map(|r| format!("regex:{r}"))
            })
            .unwrap_or_else(|| "present".to_owned());
        let invert = if h.get("invert_match").and_then(Value::as_bool) == Some(true) {
            "!"
        } else {
            ""
        };
        // Writing to a String cannot fail.
        let _ = write!(out, " [{invert}{name} {cond}]");
    }
    out
}

/// Entity keys carry no whitespace.
fn key_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect()
}

#[allow(clippy::too_many_lines)] // one pass over the objects, in reading order
fn observe_envoy(
    ctx: &Ctx,
    doc: &Value,
    artifact: ArtifactObservationId,
    objects: &[Object],
    sink: &mut Sink,
) -> Result<usize> {
    let mut routes = 0;
    let listeners = doc
        .pointer("/static_resources/listeners")
        .and_then(Value::as_array);
    for listener in listeners.into_iter().flatten() {
        let chains = listener.get("filter_chains").and_then(Value::as_array);
        for chain in chains.into_iter().flatten() {
            let filters = chain.get("filters").and_then(Value::as_array);
            for filter in filters.into_iter().flatten() {
                let Some(rc) = filter.pointer("/typed_config/route_config") else {
                    continue;
                };
                let vhosts = rc.get("virtual_hosts").and_then(Value::as_array);
                for vh in vhosts.into_iter().flatten() {
                    let vh_name = vh.get("name").and_then(Value::as_str).unwrap_or("default");
                    for route in vh
                        .get("routes")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let m = route.get("match").cloned().unwrap_or(Value::Null);
                        let matched = route_match(&m);
                        let key = key_text(&format!("envoy.route/{vh_name}/{matched}"));
                        ctx.observe(
                            sink,
                            &key,
                            "matches_path",
                            EvValue::Text(matched.clone()),
                            &[artifact],
                        )?;
                        ctx.observe(
                            sink,
                            &key,
                            "in_virtual_host",
                            EvValue::Text(vh_name.to_owned()),
                            &[artifact],
                        )?;
                        let mut clusters: Vec<&str> = Vec::new();
                        if let Some(c) = route.pointer("/route/cluster").and_then(Value::as_str) {
                            clusters.push(c);
                        }
                        let weighted = route
                            .pointer("/route/weighted_clusters/clusters")
                            .and_then(Value::as_array);
                        for wc in weighted.into_iter().flatten() {
                            if let Some(c) = wc.get("name").and_then(Value::as_str) {
                                clusters.push(c);
                            }
                        }
                        for c in clusters {
                            let target = sink.entity(&format!("envoy.cluster/{c}"));
                            ctx.observe(
                                sink,
                                &key,
                                "routes_to",
                                EvValue::Entity(target),
                                &[artifact],
                            )?;
                        }
                        routes += 1;
                    }
                }
            }
        }
    }
    let services: Vec<(&str, &str)> = objects
        .iter()
        .filter(|o| k8s::kind(&o.value) == Some("Service"))
        .filter_map(|o| k8s::name(&o.value).map(|n| (o.namespace.as_str(), n)))
        .collect();
    let clusters = doc
        .pointer("/static_resources/clusters")
        .and_then(Value::as_array);
    for cluster in clusters.into_iter().flatten() {
        let Some(name) = cluster.get("name").and_then(Value::as_str) else {
            continue;
        };
        let key = format!("envoy.cluster/{name}");
        let endpoints = cluster
            .pointer("/load_assignment/endpoints")
            .and_then(Value::as_array);
        for ep in endpoints.into_iter().flatten() {
            for lb in ep
                .get("lb_endpoints")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(addr) = lb.pointer("/endpoint/address/socket_address") else {
                    continue;
                };
                let Some(host) = addr.get("address").and_then(Value::as_str) else {
                    continue;
                };
                ctx.observe(
                    sink,
                    &key,
                    "upstream_host",
                    EvValue::Text(host.to_owned()),
                    &[artifact],
                )?;
                if let Some(port) = addr.get("port_value").and_then(Value::as_i64) {
                    ctx.observe(sink, &key, "upstream_port", EvValue::Int(port), &[artifact])?;
                }
                // `name`, `name.ns`, `name.ns.svc`, `name.ns.svc.cluster.local`: a Service
                // in the manifests read, by its first label (and namespace when given).
                let mut parts = host.split('.');
                let first = parts.next().unwrap_or(host);
                let ns_hint = parts.next();
                for (ns, svc) in &services {
                    if *svc == first && ns_hint.is_none_or(|h| h == *ns) {
                        let target = sink.entity(&format!("service/{ns}/{svc}"));
                        ctx.observe(
                            sink,
                            &key,
                            "upstream_service",
                            EvValue::Entity(target),
                            &[artifact],
                        )?;
                    }
                }
            }
        }
    }
    Ok(routes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_head_follows_refs_and_packed_refs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(git_head(root), None, "not a checkout");
        std::fs::create_dir_all(root.join(".git/refs/heads")).unwrap();
        std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(
            root.join(".git/packed-refs"),
            "# pack-refs\n0123456789abcdef0123456789abcdef01234567 refs/heads/main\n",
        )
        .unwrap();
        assert_eq!(
            git_head(root).as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        std::fs::write(
            root.join(".git/refs/heads/main"),
            "89abcdef0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        assert_eq!(
            git_head(root).as_deref(),
            Some("89abcdef0123456789abcdef0123456789abcdef"),
            "a loose ref wins"
        );
        // A worktree: `.git` is a file pointing at the worktree's git dir, whose
        // `commondir` holds the shared refs.
        let wt = dir.path().join("wt");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::create_dir_all(root.join(".git/worktrees/wt")).unwrap();
        std::fs::write(
            wt.join(".git"),
            format!("gitdir: {}\n", root.join(".git/worktrees/wt").display()),
        )
        .unwrap();
        std::fs::write(
            root.join(".git/worktrees/wt/HEAD"),
            "ref: refs/heads/main\n",
        )
        .unwrap();
        std::fs::write(root.join(".git/worktrees/wt/commondir"), "../..\n").unwrap();
        assert_eq!(
            git_head(&wt).as_deref(),
            Some("89abcdef0123456789abcdef0123456789abcdef")
        );
        std::fs::write(
            root.join(".git/HEAD"),
            "abcdefabcdefabcdefabcdefabcdefabcdefabcd\n",
        )
        .unwrap();
        assert_eq!(
            git_head(root).as_deref(),
            Some("abcdefabcdefabcdefabcdefabcdefabcdefabcd"),
            "detached"
        );
    }

    #[test]
    fn route_matches_and_keys() {
        assert_eq!(
            route_match(&serde_json::json!({"path_separated_prefix": "/v1/labs"})),
            "path_separated_prefix:/v1/labs"
        );
        assert_eq!(route_match(&serde_json::json!({"prefix": "/"})), "prefix:/");
        assert_eq!(
            route_match(&serde_json::json!({"safe_regex": {"regex": "^/a b$"}})),
            "regex:^/a b$"
        );
        assert_eq!(route_match(&serde_json::json!({})), "any");
        let health = |backend: &str| {
            route_match(
                &serde_json::json!({"prefix": "/grpc.health.v1.Health/", "grpc": {},
                "headers": [{"name": "x-iohr-backend", "string_match": {"exact": backend}}]}),
            )
        };
        assert_eq!(
            health("labs"),
            "prefix:/grpc.health.v1.Health/ grpc [x-iohr-backend exact:labs]"
        );
        assert_ne!(
            health("labs"),
            health("connections"),
            "routes differing by a header stay apart"
        );
        assert_eq!(
            key_text("envoy.route/x/regex:^/a b$"),
            "envoy.route/x/regex:^/a_b$"
        );
    }

    #[test]
    fn yaml_documents_that_do_not_parse_are_skipped() {
        let docs = parse_yaml("a: 1\n---\nkind: X\n");
        assert_eq!(docs.len(), 2);
        let docs = parse_yaml("kind: {{ .Values.kind }}\n");
        assert_eq!(docs, Vec::<Value>::new());
        assert_eq!(parse_yaml("just a scalar\n"), Vec::<Value>::new());
    }
}
