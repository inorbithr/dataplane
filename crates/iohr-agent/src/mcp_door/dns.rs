//! A resolver that survives the router. A session that starts while the router's DNS blips
//! used to lose its MCP server for the whole session; here the platform's names fall back to
//! the last good addresses, then to DNS-over-HTTPS addressed by IP (so asking needs no DNS).
//! Only the names the door was configured with get the fallback; everything else resolves
//! as the system does.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde::Deserialize;
use tokio::sync::Mutex;

/// The system's answer for a name.
pub type Lookup = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>> + Send + Sync,
>;

/// The operating system's resolver.
#[must_use]
pub fn system_lookup() -> Lookup {
    Arc::new(|name: String| {
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            Ok(found.map(|a| a.ip()).collect())
        })
    })
}

/// DNS-over-HTTPS endpoints, addressed by IP.
pub const DOH: [&str; 2] = ["https://1.1.1.1/dns-query", "https://8.8.8.8/resolve"];

/// The resolver.
#[derive(Clone)]
pub struct FallbackResolver {
    names: Vec<String>,
    cache: PathBuf,
    system: Lookup,
    doh: Vec<String>,
    lock: Arc<Mutex<()>>,
}

impl std::fmt::Debug for FallbackResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackResolver")
            .field("names", &self.names)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohRecord>,
}

#[derive(Deserialize)]
struct DohRecord {
    #[serde(rename = "type")]
    kind: u32,
    data: String,
}

impl FallbackResolver {
    /// A resolver for `names`, remembering good answers in `cache`.
    #[must_use]
    pub fn new(names: Vec<String>, cache: PathBuf, system: Lookup, doh: Vec<String>) -> Self {
        Self {
            names,
            cache,
            system,
            doh,
            lock: Arc::new(Mutex::new(())),
        }
    }

    fn load(&self) -> serde_json::Map<String, serde_json::Value> {
        std::fs::read(&self.cache)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn remembered(&self, host: &str) -> Vec<Ipv4Addr> {
        self.load()
            .get(host)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().and_then(|s| s.parse().ok()))
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn remember(&self, host: &str, ips: &[Ipv4Addr]) {
        let _g = self.lock.lock().await;
        let mut c = self.load();
        let new = serde_json::json!(ips.iter().map(ToString::to_string).collect::<Vec<_>>());
        if c.get(host) == Some(&new) {
            return;
        }
        c.insert(host.to_owned(), new);
        if let Ok(bytes) = serde_json::to_vec(&c) {
            let _ = super::write_state(&self.cache, &bytes);
        }
    }

    async fn doh(&self, host: &str) -> Vec<Ipv4Addr> {
        for url in &self.doh {
            let Ok(client) = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .user_agent(super::USER_AGENT)
                .build()
            else {
                return Vec::new();
            };
            let Ok(resp) = client
                .get(url)
                .query(&[("name", host), ("type", "A")])
                .header("Accept", "application/dns-json")
                .send()
                .await
            else {
                continue;
            };
            let Ok(answer) = resp.json::<DohAnswer>().await else {
                continue;
            };
            let ips: Vec<Ipv4Addr> = answer
                .answer
                .iter()
                .filter(|r| r.kind == 1)
                .filter_map(|r| r.data.parse().ok())
                .collect();
            if !ips.is_empty() {
                return ips;
            }
        }
        Vec::new()
    }

    /// The addresses for `host`: the system's, or for a configured name the last good ones,
    /// or `DoH`'s.
    ///
    /// # Errors
    /// The system's error when no fallback has an address.
    pub async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        match (self.system)(host.to_owned()).await {
            Ok(ips) if !ips.is_empty() => {
                if self.names.iter().any(|n| n == host) {
                    let mut v4: Vec<Ipv4Addr> = ips
                        .iter()
                        .filter_map(|i| match i {
                            IpAddr::V4(a) => Some(*a),
                            IpAddr::V6(_) => None,
                        })
                        .collect();
                    v4.sort();
                    v4.dedup();
                    if !v4.is_empty() {
                        self.remember(host, &v4).await;
                    }
                }
                Ok(ips)
            }
            other => {
                if !self.names.iter().any(|n| n == host) {
                    return other;
                }
                let remembered = self.remembered(host);
                let (ips, from) = if remembered.is_empty() {
                    (self.doh(host).await, "DoH")
                } else {
                    (remembered, "cache")
                };
                if ips.is_empty() {
                    return other.and_then(|_| Err(io::Error::other("no address")));
                }
                tracing::warn!(host, from, "dns: the system resolver failed");
                Ok(ips.into_iter().map(IpAddr::V4).collect())
            }
        }
    }
}

impl Resolve for FallbackResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let this = self.clone();
        Box::pin(async move {
            let ips = this.lookup(&host).await?;
            let addrs: Addrs = Box::new(
                ips.into_iter()
                    .map(|ip| SocketAddr::new(ip, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addrs)
        })
    }
}
