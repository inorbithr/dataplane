//! Secret references: `env:NAME`, `file:/path`, `k8s:<namespace>/<name>#<key>`,
//! `vault:<mount>/<path>#<key>`. The platform only ever holds the reference; the value is
//! read here at the moment of the call, kept in memory that is zeroed on drop, and never
//! logged, reported or written anywhere.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

use crate::config::{KubernetesConfig, SecretsConfig, VaultConfig, check_platform_url};
use crate::error::{Error, Result};
use crate::tls::TlsContext;

/// The largest secret store answer accepted.
const MAX_ANSWER: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

/// A parsed reference. Display gives it back as written; it is not secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// An environment variable of the agent's process.
    Env(String),
    /// A file on the agent's machine.
    File(PathBuf),
    /// A key of a Kubernetes Secret.
    K8s {
        /// Namespace.
        namespace: String,
        /// Secret name.
        name: String,
        /// Key inside `data`.
        key: String,
    },
    /// A key of a Vault KV v2 secret.
    Vault {
        /// The mount (`kv`, `secret`).
        mount: String,
        /// The path under the mount.
        path: String,
        /// The key inside the secret's data.
        key: String,
    },
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(n) => write!(f, "env:{n}"),
            Self::File(p) => write!(f, "file:{}", p.display()),
            Self::K8s {
                namespace,
                name,
                key,
            } => write!(f, "k8s:{namespace}/{name}#{key}"),
            Self::Vault { mount, path, key } => write!(f, "vault:{mount}/{path}#{key}"),
        }
    }
}

impl FromStr for SecretRef {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bad = |reason: &str| Error::Secret {
            reference: s.to_owned(),
            reason: reason.to_owned(),
        };
        let (kind, rest) = s
            .split_once(':')
            .ok_or_else(|| bad("expected kind:reference"))?;
        match kind {
            "env" => {
                let ok = rest
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                    && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if ok {
                    Ok(Self::Env(rest.to_owned()))
                } else {
                    Err(bad("not a variable name"))
                }
            }
            "file" => {
                let p = PathBuf::from(rest);
                if p.is_absolute() {
                    Ok(Self::File(p))
                } else {
                    Err(bad("the path must be absolute"))
                }
            }
            "k8s" => {
                let (loc, key) = rest
                    .split_once('#')
                    .ok_or_else(|| bad("expected k8s:<namespace>/<name>#<key>"))?;
                let (namespace, name) = loc
                    .split_once('/')
                    .ok_or_else(|| bad("expected k8s:<namespace>/<name>#<key>"))?;
                let dns = |v: &str| {
                    !v.is_empty()
                        && v.len() <= 253
                        && v.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
                        })
                };
                let key_ok = !key.is_empty()
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
                if dns(namespace) && dns(name) && key_ok {
                    Ok(Self::K8s {
                        namespace: namespace.into(),
                        name: name.into(),
                        key: key.into(),
                    })
                } else {
                    Err(bad("invalid namespace, name or key"))
                }
            }
            "vault" => {
                let (loc, key) = rest
                    .split_once('#')
                    .ok_or_else(|| bad("expected vault:<mount>/<path>#<key>"))?;
                let (mount, path) = loc
                    .split_once('/')
                    .ok_or_else(|| bad("expected vault:<mount>/<path>#<key>"))?;
                let seg_ok = |v: &str| {
                    !v.is_empty()
                        && v.split('/')
                            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
                        && v.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))
                };
                if seg_ok(mount) && !mount.contains('/') && seg_ok(path) && !key.is_empty() {
                    Ok(Self::Vault {
                        mount: mount.into(),
                        path: path.into(),
                        key: key.into(),
                    })
                } else {
                    Err(bad("invalid mount, path or key"))
                }
            }
            _ => Err(bad("unknown kind; use env:, file:, k8s: or vault:")),
        }
    }
}

/// Resolves references against the stores in the configuration.
#[derive(Debug, Clone)]
pub struct SecretResolver {
    config: SecretsConfig,
    tls: TlsContext,
}

impl SecretResolver {
    /// A resolver for these stores.
    #[must_use]
    pub fn new(config: SecretsConfig, tls: TlsContext) -> Self {
        Self { config, tls }
    }

    /// Reads the value now. Errors name the reference, never the value.
    ///
    /// # Errors
    /// When the store is not configured, unreachable, or has no such key.
    pub async fn resolve(&self, r: &SecretRef) -> Result<Zeroizing<String>> {
        let fail = |reason: String| Error::Secret {
            reference: r.to_string(),
            reason,
        };
        match r {
            SecretRef::Env(name) => std::env::var(name)
                .map(Zeroizing::new)
                .map_err(|_| fail("not set in the agent's environment".into())),
            SecretRef::File(path) => tokio::fs::read_to_string(path)
                .await
                .map(|s| Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_owned()))
                .map_err(|e| fail(e.kind().to_string())),
            SecretRef::K8s {
                namespace,
                name,
                key,
            } => self.kubernetes(namespace, name, key).await.map_err(fail),
            SecretRef::Vault { mount, path, key } => {
                let vault = self
                    .config
                    .vault
                    .as_ref()
                    .ok_or_else(|| fail("no [secrets.vault] in agent.toml".into()))?;
                self.vault(vault, mount, path, key).await.map_err(fail)
            }
        }
    }

    async fn kubernetes(
        &self,
        namespace: &str,
        name: &str,
        key: &str,
    ) -> std::result::Result<Zeroizing<String>, String> {
        let k: &KubernetesConfig = &self.config.kubernetes;
        let api = match &k.api {
            Some(u) => u.clone(),
            None => in_cluster_api()?,
        };
        check_platform_url(&api)?;
        let token = Zeroizing::new(tokio::fs::read_to_string(&k.token_file).await.map_err(
            |e| {
                format!(
                    "service account token {}: {}",
                    k.token_file.display(),
                    e.kind()
                )
            },
        )?);
        let builder = if api.scheme() == "https" {
            TlsContext::only(&k.ca_file)
                .map_err(|e| e.to_string())?
                .reqwest_builder()
        } else {
            reqwest::Client::builder()
        };
        let client = builder
            .no_proxy()
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        let url = api
            .join(&format!("api/v1/namespaces/{namespace}/secrets/{name}"))
            .map_err(|e| e.to_string())?;
        let body = get_json(client.get(url).bearer_auth(token.as_str())).await?;
        let encoded = body
            .get("data")
            .and_then(|d| d.get(key))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("the Secret has no key {key}"))?;
        let bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "the Secret's value is not base64".to_owned())?,
        );
        String::from_utf8(bytes.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| "the Secret's value is not UTF-8".to_owned())
    }

    async fn vault(
        &self,
        v: &VaultConfig,
        mount: &str,
        path: &str,
        key: &str,
    ) -> std::result::Result<Zeroizing<String>, String> {
        let token_ref: SecretRef = v.token.parse().map_err(|e: Error| e.to_string())?;
        if !matches!(token_ref, SecretRef::Env(_) | SecretRef::File(_)) {
            return Err("secrets.vault.token must be env: or file:".into());
        }
        let token = Box::pin(self.resolve(&token_ref))
            .await
            .map_err(|e| e.to_string())?;
        let builder = if v.addr.scheme() == "https" {
            self.tls.reqwest_builder()
        } else {
            reqwest::Client::builder()
        };
        let client = builder
            .no_proxy()
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        let url: Url = v
            .addr
            .join(&format!("v1/{mount}/data/{path}"))
            .map_err(|e| e.to_string())?;
        let mut req = client.get(url).header("X-Vault-Token", token.as_str());
        if let Some(ns) = &v.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        let body = get_json(req).await?;
        body.pointer("/data/data")
            .and_then(|d| d.get(key))
            .and_then(Value::as_str)
            .map(|s| Zeroizing::new(s.to_owned()))
            .ok_or_else(|| format!("the secret has no string key {key}"))
    }
}

fn in_cluster_api() -> std::result::Result<Url, String> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST")
        .map_err(|_| "not running in Kubernetes and no secrets.kubernetes.api set".to_owned())?;
    let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    Url::parse(&format!("https://{host}:{port}/")).map_err(|e| e.to_string())
}

/// Sends a GET and parses a bounded JSON answer. The error never includes the body.
async fn get_json(req: reqwest::RequestBuilder) -> std::result::Result<Value, String> {
    let mut resp = req.send().await.map_err(|e| {
        if e.is_timeout() {
            "timed out".to_owned()
        } else {
            "could not reach the store".to_owned()
        }
    })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("the store answered {}", status.as_u16()));
    }
    let mut buf = Zeroizing::new(Vec::new());
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| "the answer was cut off".to_owned())?
    {
        if buf.len() + chunk.len() > MAX_ANSWER {
            return Err("the answer is too large".into());
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|_| "the answer is not JSON".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::HeaderMap;
    use axum::routing::get;

    #[test]
    fn parses_references() {
        assert_eq!(
            "env:A_B".parse::<SecretRef>().unwrap(),
            SecretRef::Env("A_B".into())
        );
        assert!("env:1A".parse::<SecretRef>().is_err());
        assert!("file:relative".parse::<SecretRef>().is_err());
        assert_eq!(
            "k8s:checks/api-token#token".parse::<SecretRef>().unwrap(),
            SecretRef::K8s {
                namespace: "checks".into(),
                name: "api-token".into(),
                key: "token".into()
            }
        );
        assert!("k8s:checks/api-token".parse::<SecretRef>().is_err());
        assert!("k8s:Checks/x#y".parse::<SecretRef>().is_err());
        assert_eq!(
            "vault:kv/staging/app#token"
                .parse::<SecretRef>()
                .unwrap()
                .to_string(),
            "vault:kv/staging/app#token"
        );
        assert!("vault:kv/../sys#x".parse::<SecretRef>().is_err());
        assert!("vault:kv#x".parse::<SecretRef>().is_err());
        assert!("aws:x".parse::<SecretRef>().is_err());
    }

    fn resolver(config: SecretsConfig) -> SecretResolver {
        crate::tls::install_crypto_provider();
        SecretResolver::new(config, TlsContext::new(None).unwrap())
    }

    #[tokio::test]
    async fn env_and_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s");
        std::fs::write(&p, "value\n").unwrap();
        let r = resolver(SecretsConfig::default());
        let v = r.resolve(&SecretRef::File(p)).await.unwrap();
        assert_eq!(v.as_str(), "value");
        let e = r
            .resolve(&SecretRef::Env("IOHR_AGENT_TEST_UNSET_VAR".into()))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("env:IOHR_AGENT_TEST_UNSET_VAR"));
    }

    async fn serve(router: Router) -> Url {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        Url::parse(&format!("http://{addr}/")).unwrap()
    }

    #[tokio::test]
    async fn vault_kv2() {
        let url = serve(Router::new().route(
            "/v1/kv/data/staging/app",
            get(|h: HeaderMap| async move {
                if h.get("x-vault-token").and_then(|v| v.to_str().ok()) != Some("vt") {
                    return (
                        axum::http::StatusCode::FORBIDDEN,
                        axum::Json(serde_json::json!({})),
                    );
                }
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({"data": {"data": {"token": "s3cret"}}})),
                )
            }),
        ))
        .await;
        let dir = tempfile::tempdir().unwrap();
        let tf = dir.path().join("vt");
        std::fs::write(&tf, "vt\n").unwrap();
        let cfg = SecretsConfig {
            vault: Some(VaultConfig {
                addr: url,
                token: format!("file:{}", tf.display()),
                namespace: None,
            }),
            ..SecretsConfig::default()
        };
        let r = resolver(cfg);
        let v = r
            .resolve(&"vault:kv/staging/app#token".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(v.as_str(), "s3cret");
        let e = r
            .resolve(&"vault:kv/staging/app#missing".parse().unwrap())
            .await
            .unwrap_err();
        assert!(
            !e.to_string().contains("s3cret"),
            "errors never carry values"
        );
        let e = r
            .resolve(&"vault:kv/other#x".parse().unwrap())
            .await
            .unwrap_err();
        assert!(e.to_string().contains("404"), "{e}");
    }

    #[tokio::test]
    async fn kubernetes_secret() {
        let url = serve(Router::new().route(
            "/api/v1/namespaces/checks/secrets/api",
            get(|h: HeaderMap| async move {
                assert_eq!(h.get("authorization").unwrap(), "Bearer sa-token");
                axum::Json(serde_json::json!({"data": {"token": "aGVsbG8="}}))
            }),
        ))
        .await;
        let dir = tempfile::tempdir().unwrap();
        let tf = dir.path().join("token");
        std::fs::write(&tf, "sa-token").unwrap();
        let cfg = SecretsConfig {
            kubernetes: KubernetesConfig {
                api: Some(url),
                token_file: tf,
                ca_file: dir.path().join("none"),
            },
            ..SecretsConfig::default()
        };
        let r = resolver(cfg);
        let v = r
            .resolve(&"k8s:checks/api#token".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(v.as_str(), "hello");
    }
}
