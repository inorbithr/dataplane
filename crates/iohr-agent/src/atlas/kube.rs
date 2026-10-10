//! The running system, read from the Kubernetes API: deployments, pods, services and
//! network policies in the namespaces asked for. Read-only, through a kubeconfig
//! (client certificate or bearer token; `exec` plugins and `insecure-skip-tls-verify`
//! are refused), and only after the API server passes the local policy like any other
//! target.
//!
//! What it reports is `RuntimeState`: what the control plane says is running, not what
//! was seen happening, so the observer is an external system, not a sensor. A pod's
//! image digest is the one fact here that pins a build.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use iohr_evidence::digest::ContentDigest;
use iohr_evidence::ids::ObservationId;
use iohr_evidence::vocabulary::Value as EvValue;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use super::common::Ctx;
use super::k8s;
use super::record::Sink;
use crate::error::{Error, Result};
use crate::policy::{Policy, TargetError};
use crate::tls::TlsContext;

/// The largest API answer accepted (a namespace's pods, with their statuses).
const MAX_ANSWER: usize = 32 * 1024 * 1024;
/// How long one API call may take.
const TIMEOUT: Duration = Duration::from_secs(30);
/// The method every reading here carries.
pub const METHOD: &str = "k8s.api.read";
/// Where Kubernetes mounts a pod's ServiceAccount.
const SA_MOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// A kubeconfig, reduced to what one context needs.
#[derive(Debug, Clone)]
pub struct KubeContext {
    /// The context's name.
    pub name: String,
    /// The user's name in the kubeconfig: the principal the observations are made as.
    pub user: String,
    /// The API server.
    pub server: Url,
    /// The cluster's CA bundle, PEM.
    ca_pem: Vec<u8>,
    /// How to authenticate.
    auth: Auth,
    /// The context's default namespace, if set.
    pub namespace: Option<String>,
}

#[derive(Clone)]
enum Auth {
    ClientCert {
        cert_pem: Vec<u8>,
        key_pem: Zeroizing<Vec<u8>>,
    },
    Token(Zeroizing<String>),
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ClientCert { .. } => "client certificate",
            Self::Token(_) => "bearer token",
        })
    }
}

#[derive(Debug, Deserialize)]
struct KubeConfigFile {
    #[serde(default)]
    clusters: Vec<Named<ClusterEntry>>,
    #[serde(default)]
    users: Vec<Named<UserEntry>>,
    #[serde(default)]
    contexts: Vec<Named<ContextEntry>>,
    #[serde(rename = "current-context", default)]
    current_context: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Named<T> {
    name: String,
    #[serde(flatten)]
    inner: T,
}

#[derive(Debug, Deserialize)]
struct ClusterEntry {
    cluster: ClusterSpec,
}

#[derive(Debug, Deserialize)]
struct ClusterSpec {
    server: String,
    #[serde(rename = "certificate-authority-data", default)]
    ca_data: Option<String>,
    #[serde(rename = "certificate-authority", default)]
    ca_file: Option<PathBuf>,
    #[serde(rename = "insecure-skip-tls-verify", default)]
    insecure: bool,
}

#[derive(Debug, Deserialize)]
struct UserEntry {
    user: UserSpec,
}

#[derive(Debug, Deserialize)]
struct UserSpec {
    #[serde(rename = "client-certificate-data", default)]
    cert_data: Option<String>,
    #[serde(rename = "client-key-data", default)]
    key_data: Option<String>,
    #[serde(rename = "client-certificate", default)]
    cert_file: Option<PathBuf>,
    #[serde(rename = "client-key", default)]
    key_file: Option<PathBuf>,
    #[serde(default)]
    token: Option<String>,
    #[serde(rename = "token-file", default)]
    token_file: Option<PathBuf>,
    #[serde(default)]
    exec: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ContextEntry {
    context: ContextSpec,
}

#[derive(Debug, Deserialize)]
struct ContextSpec {
    cluster: String,
    user: String,
    #[serde(default)]
    namespace: Option<String>,
}

impl KubeContext {
    /// Reads `path` and picks `context` (or the file's current context).
    ///
    /// # Errors
    /// The file is missing or malformed, the context, cluster or user is unknown, the
    /// cluster skips TLS verification, or the user authenticates through an `exec`
    /// plugin (the agent runs no other program).
    pub fn load(path: &Path, context: Option<&str>) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
        let cfg: KubeConfigFile = serde_yaml_ng::from_str(&text)
            .map_err(|e| Error::Atlas(format!("{}: not a kubeconfig: {e}", path.display())))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_file(&cfg, context, base)
    }

    fn from_file(cfg: &KubeConfigFile, context: Option<&str>, base: &Path) -> Result<Self> {
        let name = context
            .map(ToOwned::to_owned)
            .or_else(|| cfg.current_context.clone())
            .ok_or_else(|| {
                Error::Atlas("the kubeconfig has no current context; pass --kube-context".into())
            })?;
        let ctx = cfg
            .contexts
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| Error::Atlas(format!("the kubeconfig has no context {name:?}")))?;
        let cluster = cfg
            .clusters
            .iter()
            .find(|c| c.name == ctx.inner.context.cluster)
            .ok_or_else(|| {
                Error::Atlas(format!(
                    "the kubeconfig has no cluster {:?}",
                    ctx.inner.context.cluster
                ))
            })?;
        let user = cfg
            .users
            .iter()
            .find(|u| u.name == ctx.inner.context.user)
            .ok_or_else(|| {
                Error::Atlas(format!(
                    "the kubeconfig has no user {:?}",
                    ctx.inner.context.user
                ))
            })?;
        if cluster.inner.cluster.insecure {
            return Err(Error::Atlas(format!(
                "cluster {:?} skips TLS verification; the agent refuses that",
                cluster.name
            )));
        }
        let server = Url::parse(&cluster.inner.cluster.server).map_err(|e| {
            Error::Atlas(format!(
                "cluster {:?}: server is not a URL: {e}",
                cluster.name
            ))
        })?;
        let ca_pem = match (
            &cluster.inner.cluster.ca_data,
            &cluster.inner.cluster.ca_file,
        ) {
            (Some(data), _) => decode(data, "certificate-authority-data")?,
            (None, Some(file)) => read_rel(base, file)?,
            (None, None) if server.scheme() == "https" => {
                return Err(Error::Atlas(format!(
                    "cluster {:?} names no certificate authority",
                    cluster.name
                )));
            }
            (None, None) => Vec::new(),
        };
        let u = &user.inner.user;
        if u.exec.is_some() {
            return Err(Error::Atlas(format!(
                "user {:?} authenticates through an exec plugin; the agent runs no other program. Use a client certificate or a token",
                user.name
            )));
        }
        let auth = if let (Some(c), Some(k)) = (&u.cert_data, &u.key_data) {
            Auth::ClientCert {
                cert_pem: decode(c, "client-certificate-data")?,
                key_pem: Zeroizing::new(decode(k, "client-key-data")?),
            }
        } else if let (Some(c), Some(k)) = (&u.cert_file, &u.key_file) {
            Auth::ClientCert {
                cert_pem: read_rel(base, c)?,
                key_pem: Zeroizing::new(read_rel(base, k)?),
            }
        } else if let Some(t) = &u.token {
            Auth::Token(Zeroizing::new(t.trim().to_owned()))
        } else if let Some(f) = &u.token_file {
            let t = read_rel(base, f)?;
            Auth::Token(Zeroizing::new(
                String::from_utf8_lossy(&t).trim().to_owned(),
            ))
        } else {
            return Err(Error::Atlas(format!(
                "user {:?} has neither a client certificate nor a token",
                user.name
            )));
        };
        Ok(Self {
            name,
            user: user.name.clone(),
            server,
            ca_pem,
            auth,
            namespace: ctx.inner.context.namespace.clone(),
        })
    }

    /// The pod's own ServiceAccount: the token and CA Kubernetes mounts into every pod
    /// that asks for them, and the API server from `KUBERNETES_SERVICE_HOST`/`_PORT`.
    ///
    /// # Errors
    /// Not running in a pod, or the mount is missing or unreadable.
    pub fn in_cluster() -> Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| Error::Atlas("not in a pod: KUBERNETES_SERVICE_HOST is not set".into()))?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        Self::from_mount(Path::new(SA_MOUNT), &host, &port)
    }

    /// [`Self::in_cluster`] from an explicit mount directory, host and port.
    ///
    /// # Errors
    /// The token or CA cannot be read, or the address is not a URL.
    pub fn from_mount(dir: &Path, host: &str, port: &str) -> Result<Self> {
        let token = std::fs::read_to_string(dir.join("token"))
            .map_err(|e| Error::io(dir.join("token"), e))?;
        let ca_pem =
            std::fs::read(dir.join("ca.crt")).map_err(|e| Error::io(dir.join("ca.crt"), e))?;
        let namespace = std::fs::read_to_string(dir.join("namespace"))
            .ok()
            .map(|n| n.trim().to_owned());
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let server = Url::parse(&format!("https://{authority}"))
            .map_err(|e| Error::Atlas(format!("the in-cluster API address: {e}")))?;
        Ok(Self {
            name: "in-cluster".into(),
            user: "serviceaccount".into(),
            server,
            ca_pem,
            auth: Auth::Token(Zeroizing::new(token.trim().to_owned())),
            namespace,
        })
    }

    /// A plain-HTTP context with no credential, for tests against a local fake server.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn plain_for_tests(server: Url) -> Self {
        Self {
            name: "test".into(),
            user: "test".into(),
            server,
            ca_pem: Vec::new(),
            auth: Auth::Token(Zeroizing::new("test-token".into())),
            namespace: None,
        }
    }

    /// The API server's host and port, for the policy check.
    #[must_use]
    pub fn host_port(&self) -> Option<(String, u16)> {
        let host = self.server.host_str()?.to_owned();
        let port =
            self.server
                .port_or_known_default()
                .unwrap_or(if self.server.scheme() == "https" {
                    443
                } else {
                    80
                });
        Some((host, port))
    }

    /// A client for this context, after the policy admitted the API server.
    ///
    /// # Errors
    /// The policy refuses the server, or TLS cannot be set up.
    pub async fn client(&self, policy: &Policy) -> Result<KubeClient> {
        let (host, port) = self
            .host_port()
            .ok_or_else(|| Error::Atlas("the API server URL has no host".into()))?;
        policy
            .resolve_target(&host, port, Duration::from_secs(5))
            .await
            .map_err(|e| match e {
                TargetError::Refused(r) => Error::Policy(format!(
                    "the Kubernetes API server {host}:{port} is refused: {r}"
                )),
                TargetError::Dns(r) => {
                    Error::Atlas(format!("the Kubernetes API server {host}:{port}: {r}"))
                }
            })?;
        // reqwest needs a process provider even for plain HTTP; the agent uses ring.
        crate::tls::install_crypto_provider();
        let builder = if self.server.scheme() == "https" {
            let tls = TlsContext::from_pem(&self.ca_pem)?;
            let config = match &self.auth {
                Auth::ClientCert { cert_pem, key_pem } => {
                    let certs: Vec<CertificateDer<'static>> =
                        CertificateDer::pem_slice_iter(cert_pem)
                            .collect::<std::result::Result<_, _>>()
                            .map_err(|e| Error::Tls(format!("client certificate: {e}")))?;
                    let key = PrivateKeyDer::from_pem_slice(key_pem)
                        .map_err(|e| Error::Tls(format!("client key: {e}")))?;
                    tls.client_config_with_identity(&[b"http/1.1"], certs, key)?
                }
                Auth::Token(_) => tls.client_config(&[b"http/1.1"]),
            };
            reqwest::Client::builder().tls_backend_preconfigured(config)
        } else {
            reqwest::Client::builder()
        };
        let http = builder
            .user_agent(concat!("iohr-agent/", env!("CARGO_PKG_VERSION")))
            .no_proxy()
            // A redirect would take the credential somewhere the policy never admitted.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| Error::Tls(e.to_string()))?;
        let token = match &self.auth {
            Auth::Token(t) => Some(t.clone()),
            Auth::ClientCert { .. } => None,
        };
        Ok(KubeClient {
            base: self.server.clone(),
            http,
            token,
        })
    }
}

fn decode(data: &str, what: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(data.trim())
        .map_err(|_| Error::Atlas(format!("the kubeconfig's {what} is not base64")))
}

fn read_rel(base: &Path, file: &Path) -> Result<Vec<u8>> {
    let path = if file.is_absolute() {
        file.to_path_buf()
    } else {
        base.join(file)
    };
    std::fs::read(&path).map_err(|e| Error::io(path, e))
}

/// A read-only client for one API server.
#[derive(Debug, Clone)]
pub struct KubeClient {
    base: Url,
    http: reqwest::Client,
    token: Option<Zeroizing<String>>,
}

impl KubeClient {
    /// GET a list at `path` (relative to the server) and return its `items`.
    ///
    /// # Errors
    /// The request failed, the answer was not success, too large or not JSON.
    pub async fn list(&self, path: &str) -> Result<Vec<Value>> {
        match self.try_list(path).await? {
            Listed::Items(items) => Ok(items),
            Listed::Refused(code) => Err(Error::Atlas(format!(
                "{path}: the API server answered {code}"
            ))),
        }
    }

    /// Like [`Self::list`], but an answer of 401, 403 or 404 is an outcome, not an error:
    /// the RBAC the customer applied does not allow it, or the kind is not served.
    ///
    /// # Errors
    /// The request failed, any other non-success answer, too large or not JSON.
    pub async fn try_list(&self, path: &str) -> Result<Listed> {
        let url = self
            .base
            .join(path)
            .map_err(|e| Error::Atlas(format!("bad API path {path}: {e}")))?;
        let mut req = self.http.get(url);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t.as_str());
        }
        let mut resp = req.send().await.map_err(|e| {
            Error::Atlas(if e.is_timeout() {
                format!("{path}: timed out")
            } else {
                format!("{path}: could not reach the API server")
            })
        })?;
        let status = resp.status();
        if matches!(status.as_u16(), 401 | 403 | 404) {
            return Ok(Listed::Refused(status.as_u16()));
        }
        if !status.is_success() {
            return Err(Error::Atlas(format!(
                "{path}: the API server answered {}",
                status.as_u16()
            )));
        }
        let mut buf = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|_| Error::Atlas(format!("{path}: the answer was cut off")))?
        {
            if buf.len() + chunk.len() > MAX_ANSWER {
                return Err(Error::Atlas(format!("{path}: the answer is too large")));
            }
            buf.extend_from_slice(&chunk);
        }
        let v: Value = serde_json::from_slice(&buf)
            .map_err(|_| Error::Atlas(format!("{path}: the answer is not JSON")))?;
        Ok(Listed::Items(
            v.get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        ))
    }
}

/// What a list request came back with.
#[derive(Debug, Clone)]
pub enum Listed {
    /// The items.
    Items(Vec<Value>),
    /// 401, 403 or 404: not allowed, or not served.
    Refused(u16),
}

/// What one namespace holds, as the API reports it.
#[derive(Debug, Default)]
pub struct NamespaceState {
    /// The namespace.
    pub namespace: String,
    /// Deployments.
    pub deployments: Vec<Value>,
    /// Pods.
    pub pods: Vec<Value>,
    /// Services.
    pub services: Vec<Value>,
    /// Network policies.
    pub network_policies: Vec<Value>,
}

/// Reads one namespace.
///
/// # Errors
/// Any list call failed.
pub async fn read_namespace(client: &KubeClient, namespace: &str) -> Result<NamespaceState> {
    Ok(NamespaceState {
        namespace: namespace.to_owned(),
        deployments: client
            .list(&format!("apis/apps/v1/namespaces/{namespace}/deployments"))
            .await?,
        pods: client
            .list(&format!("api/v1/namespaces/{namespace}/pods"))
            .await?,
        services: client
            .list(&format!("api/v1/namespaces/{namespace}/services"))
            .await?,
        network_policies: client
            .list(&format!(
                "apis/networking.k8s.io/v1/namespaces/{namespace}/networkpolicies"
            ))
            .await?,
    })
}

/// What the snapshot needs about one deployment.
#[derive(Debug, Default, Clone)]
pub struct DeploymentFacts {
    /// Distinct image digests of its running pods (more than one: a rollout in progress).
    pub digests: Vec<ContentDigest>,
    /// The commit its image was built from, when annotated.
    pub commit: Option<String>,
    /// The observations that reported these.
    pub observations: Vec<ObservationId>,
}

/// Turns a namespace's state into observations. Returns, per deployment key, what the
/// snapshot needs.
///
/// # Errors
/// An observation could not be built.
#[allow(clippy::too_many_lines)] // one pass over the objects, in reading order
pub fn observe(
    ctx: &Ctx,
    state: &NamespaceState,
    sink: &mut Sink,
) -> Result<BTreeMap<String, DeploymentFacts>> {
    let ns = &state.namespace;
    let mut facts: BTreeMap<String, DeploymentFacts> = BTreeMap::new();
    for d in &state.deployments {
        let Some(name) = k8s::name(d) else { continue };
        let key = format!("deployment/{ns}/{name}");
        let mut f = DeploymentFacts::default();
        for image in k8s::images(d) {
            let o = ctx.observe(
                sink,
                &key,
                "runs_image",
                EvValue::Text(image.to_owned()),
                &[],
            )?;
            f.observations.push(o);
        }
        if let Some(commit) = d
            .pointer("/metadata/annotations/inorbit.hr~1commit")
            .and_then(Value::as_str)
        {
            let o = ctx.observe(
                sink,
                &key,
                "built_from_commit",
                EvValue::Text(commit.to_owned()),
                &[],
            )?;
            f.commit = Some(commit.to_owned());
            f.observations.push(o);
        }
        if let Some(ready) = d.pointer("/status/readyReplicas").and_then(Value::as_i64) {
            let o = ctx.observe(sink, &key, "replicas_ready", EvValue::Int(ready), &[])?;
            f.observations.push(o);
        }
        let selector = d.pointer("/spec/selector").cloned().unwrap_or(Value::Null);
        for pod in &state.pods {
            let pod_labels = k8s::labels(pod.pointer("/metadata/labels"));
            if !k8s::selector_matches(&selector, &pod_labels) {
                continue;
            }
            let statuses = pod
                .pointer("/status/containerStatuses")
                .and_then(Value::as_array);
            for st in statuses.into_iter().flatten() {
                let Some(id) = st.get("imageID").and_then(Value::as_str) else {
                    continue;
                };
                let Some(digest) = k8s::image_digest(id) else {
                    continue;
                };
                if f.digests.contains(&digest) {
                    continue;
                }
                let o = ctx.observe(
                    sink,
                    &key,
                    "runs_image_digest",
                    EvValue::Digest(digest),
                    &[],
                )?;
                f.observations.push(o);
                f.digests.push(digest);
            }
        }
        facts.insert(key, f);
    }
    for s in &state.services {
        let Some(name) = k8s::name(s) else { continue };
        let key = format!("service/{ns}/{name}");
        let selector = k8s::labels(s.pointer("/spec/selector"));
        if !selector.is_empty() {
            ctx.observe(
                sink,
                &key,
                "selects",
                EvValue::Text(k8s::render_labels(&selector)),
                &[],
            )?;
            for d in &state.deployments {
                let Some(dname) = k8s::name(d) else { continue };
                if k8s::plain_selector_matches(&selector, &k8s::pod_labels(d)) {
                    let target = sink.entity(&format!("deployment/{ns}/{dname}"));
                    ctx.observe(sink, &key, "targets", EvValue::Entity(target), &[])?;
                }
            }
        }
        for port in s
            .pointer("/spec/ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(n) = port.get("port").and_then(Value::as_i64) {
                ctx.observe(sink, &key, "exposes_port", EvValue::Int(n), &[])?;
            }
        }
    }
    for np in &state.network_policies {
        let Some(name) = k8s::name(np) else { continue };
        let key = format!("networkpolicy/{ns}/{name}");
        let selector = np
            .pointer("/spec/podSelector")
            .cloned()
            .unwrap_or(Value::Null);
        ctx.observe(
            sink,
            &key,
            "selects",
            EvValue::Text(k8s::render_selector(&selector)),
            &[],
        )?;
        for d in &state.deployments {
            let Some(dname) = k8s::name(d) else { continue };
            if k8s::selector_matches(&selector, &k8s::pod_labels(d)) {
                let target = sink.entity(&format!("deployment/{ns}/{dname}"));
                ctx.observe(sink, &key, "applies_to", EvValue::Entity(target), &[])?;
            }
        }
        for rule in np
            .pointer("/spec/egress")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            ctx.observe(
                sink,
                &key,
                "allows_egress",
                EvValue::Text(k8s::render_egress(rule)),
                &[],
            )?;
        }
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlas::common::{ObservedNow, method};
    use crate::atlas::record::Record;
    use iohr_evidence::method::MethodCategory;
    use iohr_evidence::observer::ObserverClass;
    use serde_json::json;

    const KUBECONFIG: &str = r"
apiVersion: v1
kind: Config
clusters:
- name: k3d-tbd
  cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: Q0EtUEVN
users:
- name: admin@k3d-tbd
  user:
    client-certificate-data: Q0VSVA==
    client-key-data: S0VZ
- name: robot
  user:
    token: tok-123
- name: plugin
  user:
    exec: { command: aws }
contexts:
- name: k3d-tbd
  context: { cluster: k3d-tbd, user: admin@k3d-tbd, namespace: tbd }
- name: robot
  context: { cluster: k3d-tbd, user: robot }
- name: plugin
  context: { cluster: k3d-tbd, user: plugin }
current-context: k3d-tbd
";

    #[test]
    fn kubeconfig_picks_the_context_and_its_auth() {
        let cfg: KubeConfigFile = serde_yaml_ng::from_str(KUBECONFIG).unwrap();
        let c = KubeContext::from_file(&cfg, None, Path::new("/tmp")).unwrap();
        assert_eq!(c.name, "k3d-tbd");
        assert_eq!(c.user, "admin@k3d-tbd");
        assert_eq!(c.namespace.as_deref(), Some("tbd"));
        assert_eq!(c.host_port(), Some(("127.0.0.1".into(), 6443)));
        assert_eq!(c.ca_pem, b"CA-PEM");
        assert!(matches!(c.auth, Auth::ClientCert { .. }));
        let r = KubeContext::from_file(&cfg, Some("robot"), Path::new("/tmp")).unwrap();
        assert!(matches!(r.auth, Auth::Token(_)));
        let shown = format!("{r:?}");
        assert!(
            shown.contains("bearer token") && !shown.contains("tok-123"),
            "{shown}"
        );
    }

    #[test]
    fn exec_plugins_and_insecure_clusters_are_refused() {
        let cfg: KubeConfigFile = serde_yaml_ng::from_str(KUBECONFIG).unwrap();
        let e = KubeContext::from_file(&cfg, Some("plugin"), Path::new("/tmp")).unwrap_err();
        assert!(e.to_string().contains("exec plugin"), "{e}");
        let insecure = KUBECONFIG.replace(
            "certificate-authority-data: Q0EtUEVN",
            "insecure-skip-tls-verify: true",
        );
        let cfg: KubeConfigFile = serde_yaml_ng::from_str(&insecure).unwrap();
        let e = KubeContext::from_file(&cfg, None, Path::new("/tmp")).unwrap_err();
        assert!(e.to_string().contains("skips TLS verification"), "{e}");
        let e = KubeContext::from_file(&cfg, Some("nope"), Path::new("/tmp")).unwrap_err();
        assert!(e.to_string().contains("no context"), "{e}");
    }

    #[test]
    fn runtime_observations_name_deployments_pods_services_and_policies() {
        let state = NamespaceState {
            namespace: "tbd".into(),
            deployments: vec![json!({
                "metadata": {"name": "labs", "annotations": {"inorbit.hr/commit": "0b708ed1"}},
                "spec": {"selector": {"matchLabels": {"app.kubernetes.io/name": "labs"}},
                         "template": {"metadata": {"labels": {"app.kubernetes.io/name": "labs"}},
                                      "spec": {"containers": [{"image": "ghcr.io/inorbithr/iohr-labs:dev"}]}}},
                "status": {"readyReplicas": 1}
            })],
            pods: vec![json!({
                "metadata": {"name": "labs-1", "labels": {"app.kubernetes.io/name": "labs"}},
                "status": {"containerStatuses": [{"imageID": "ghcr.io/inorbithr/iohr-labs@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]}
            })],
            services: vec![json!({
                "metadata": {"name": "labs"},
                "spec": {"selector": {"app.kubernetes.io/name": "labs"}, "ports": [{"port": 50073}]}
            })],
            network_policies: vec![json!({
                "metadata": {"name": "egress-internet-https"},
                "spec": {"podSelector": {"matchExpressions": [{"key": "app.kubernetes.io/name", "operator": "In", "values": ["paging", "labs"]}]},
                         "egress": [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}], "ports": [{"protocol": "TCP", "port": 443}]}]}
            })],
        };
        let mut sink = Sink::default();
        let ctx = Ctx::new(
            &mut sink,
            "k8s-reader",
            ObserverClass::ExternalSystem,
            method(METHOD, MethodCategory::RuntimeState).unwrap(),
            "test",
            &["list"],
            &ObservedNow::now(),
        )
        .unwrap();
        let facts = observe(&ctx, &state, &mut sink).unwrap();
        let labs = &facts["deployment/tbd/labs"];
        assert_eq!(labs.commit.as_deref(), Some("0b708ed1"));
        assert_eq!(labs.digests.len(), 1);
        assert_eq!(labs.observations.len(), 4);
        let preds: Vec<String> = sink
            .records()
            .iter()
            .filter_map(|r| match r {
                Record::Observation(o) => Some(o.statement().predicate.name.as_str().to_owned()),
                _ => None,
            })
            .collect();
        for p in [
            "runs_image",
            "built_from_commit",
            "replicas_ready",
            "runs_image_digest",
            "selects",
            "targets",
            "exposes_port",
            "applies_to",
            "allows_egress",
        ] {
            assert!(preds.contains(&p.to_owned()), "missing {p}: {preds:?}");
        }
        assert_eq!(sink.per_method()[METHOD], preds.len());
    }
}
