//! The local admin page: read-only, on loopback by default, HTML at `/` and JSON at
//! `/status.json`. A small hand-written HTTP/1.1 responder keeps a server framework out of
//! the dependency tree; it answers GET and HEAD and closes every connection.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::state::{AgentState, Snapshot};

const MAX_REQUEST: usize = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Serves until `shutdown` turns true.
pub async fn serve(
    listener: TcpListener,
    state: Arc<AgentState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let local = listener.local_addr().ok();
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            accepted = listener.accept() => {
                if let Ok((sock, _)) = accepted {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let _ = handle(sock, &state, local).await;
                    });
                }
            }
        }
    }
}

async fn handle(
    mut sock: TcpStream,
    state: &AgentState,
    local: Option<SocketAddr>,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let read = tokio::time::timeout(READ_TIMEOUT, async {
        let mut chunk = [0u8; 1024];
        loop {
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                return Ok::<bool, std::io::Error>(false);
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                return Ok(true);
            }
            if buf.len() > MAX_REQUEST {
                return Ok(false);
            }
        }
    })
    .await;
    if !matches!(read, Ok(Ok(true))) {
        return respond(&mut sock, 400, "text/plain", b"bad request\n", false).await;
    }
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (method, path) = (
        first.next().unwrap_or_default(),
        first.next().unwrap_or_default(),
    );
    let host = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.trim().to_owned());
    let head = method == "HEAD";
    if method != "GET" && !head {
        return respond(&mut sock, 405, "text/plain", b"read-only\n", false).await;
    }
    // A web page in a browser on this machine must not read the status through DNS
    // rebinding: only accept Host headers naming the loopback interface or our address.
    if !host_allowed(host.as_deref(), local) {
        return respond(&mut sock, 421, "text/plain", b"wrong host\n", head).await;
    }
    match path {
        "/status.json" => {
            let body = serde_json::to_vec_pretty(&state.snapshot()).unwrap_or_default();
            respond(&mut sock, 200, "application/json", &body, head).await
        }
        "/" => {
            let body = render_html(&state.snapshot());
            respond(
                &mut sock,
                200,
                "text/html; charset=utf-8",
                body.as_bytes(),
                head,
            )
            .await
        }
        "/healthz" => respond(&mut sock, 200, "text/plain", b"ok\n", head).await,
        _ => respond(&mut sock, 404, "text/plain", b"not found\n", head).await,
    }
}

fn host_allowed(host: Option<&str>, local: Option<SocketAddr>) -> bool {
    let Some(host) = host else { return false };
    let name = host.rsplit_once(':').map_or(host, |(h, p)| {
        if p.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            host
        }
    });
    let name = name.trim_start_matches('[').trim_end_matches(']');
    if name.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match name.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback() || local.is_some_and(|l| l.ip() == ip),
        Err(_) => false,
    }
}

async fn respond(
    sock: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
    head: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        421 => "Misdirected Request",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(header.as_bytes()).await?;
    if !head {
        sock.write_all(body).await?;
    }
    sock.shutdown().await
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The Traffic section: what the capture companion counted on this host. Counts only;
/// none of it is sent to the platform (only the `capture:*` strings in the hello).
#[allow(clippy::too_many_lines)] // one table, row by row
fn traffic(h: &mut String, t: &crate::capture::TrafficInfo) {
    let row = |h: &mut String, k: &str, v: &str| {
        let _ = write!(h, "<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(v));
    };
    h.push_str("<h2>Traffic</h2><p>Counted by iohr-capture on this host. Counts only; they stay on this machine. The platform learns only which capture layers this host offers.</p><table>");
    row(h, "Companion", &t.state);
    if let Some(r) = &t.reason {
        row(h, "Why", r);
    }
    row(
        h,
        "Announced",
        &if t.capabilities.is_empty() {
            "nothing".to_owned()
        } else {
            t.capabilities.join(", ")
        },
    );
    if let Some(a) = t.age_secs {
        row(h, "Numbers from", &format!("{a} s ago"));
    }
    if let Some(c) = &t.counts {
        let n = |v: u64| v.to_string();
        row(
            h,
            "Ingress",
            &format!(
                "{} skb, {} bytes",
                c.headers.ingress.packets, c.headers.ingress.bytes
            ),
        );
        row(
            h,
            "Egress",
            &format!(
                "{} skb, {} bytes",
                c.headers.egress.packets, c.headers.egress.bytes
            ),
        );
        row(
            h,
            "Drops",
            &format!(
                "{} rate limited, {} ring buffer full, {} flows evicted",
                c.drops.rate_limited, c.drops.ring_buffer_full, c.drops.flows_evicted
            ),
        );
        row(
            h,
            "Flows",
            &format!(
                "{} seen, {} active, {} recognised",
                c.flows.seen, c.flows.active, c.flows.recognised
            ),
        );
        row(h, "HTTP/1 requests", &n(c.protocols.http1_requests));
        row(h, "TLS handshakes", &n(c.protocols.tls_client_hellos));
        row(h, "DNS queries", &n(c.protocols.dns_queries));
        row(
            h,
            "HTTP/2 connections (gRPC calls)",
            &format!(
                "{} ({})",
                c.protocols.http2_connections, c.protocols.grpc_calls
            ),
        );
        row(
            h,
            "Owners",
            &format!(
                "{} sockets, {} owners, {} flows owned, {} unowned",
                c.owners.sockets, c.owners.owners, c.owners.flows_owned, c.owners.flows_unowned
            ),
        );
        row(
            h,
            "Request timing",
            &format!(
                "{} requests, {} answered ({} 2xx, {} 4xx, {} 5xx), {} unanswered, {} connections out of sync",
                c.timing.requests,
                c.timing.responses,
                c.timing.status_classes.c2xx,
                c.timing.status_classes.c4xx,
                c.timing.status_classes.c5xx,
                c.timing.unanswered,
                c.timing.unsynced
            ),
        );
        row(
            h,
            "Whole packets",
            &if c.packets.enabled {
                format!(
                    "on: {} copied, {} rate limited, {} ring buffer full, {} pcap files made by root on this host",
                    c.packets.copied,
                    c.packets.rate_limited,
                    c.packets.ring_buffer_full,
                    c.packets.pcaps_written
                )
            } else {
                "off".to_owned()
            },
        );
        row(
            h,
            "TCP",
            &format!(
                "{} established, {} listening, {} retransmits, {} resets in, {} out, {} listen overflows",
                c.tcp.established,
                c.tcp.listening,
                c.tcp.retransmits_sampled,
                c.tcp.resets_in,
                c.tcp.resets_out,
                c.tcp.host.listen_overflows
            ),
        );
    }
    h.push_str("</table><p>Names, routes, paths and addresses: <code>iohr agent capture status --tables</code> on this host. Packets never reach the agent: root makes pcap files with <code>iohr-capture pcap</code>.</p>");
}

/// The HTML page. Every value is escaped: job targets come from the platform.
#[must_use]
pub fn render_html(s: &Snapshot) -> String {
    let mut h = String::with_capacity(4096);
    let state = if s.revoked {
        "revoked"
    } else if s.connected {
        "connected"
    } else {
        "not connected"
    };
    let _ = write!(
        h,
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>iohr-agent</title>\
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1b1b1f;background:#fff}}\
@media(prefers-color-scheme:dark){{body{{color:#e8e8ec;background:#141417}}td,th{{border-color:#333}}}}\
table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;padding:.25rem .5rem;border-bottom:1px solid #ddd}}code{{font-size:90%}}</style>\
<h1>iohr-agent</h1><p><b>{}</b>{}</p><table>",
        esc(state),
        s.connected_since
            .as_deref()
            .map(|t| format!(" since {}", esc(t)))
            .unwrap_or_default()
    );
    let row = |h: &mut String, k: &str, v: &str| {
        let _ = write!(h, "<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(v));
    };
    row(&mut h, "Version", &s.agent.version);
    row(
        &mut h,
        "Agent",
        s.agent.agent_id.as_deref().unwrap_or("not enrolled"),
    );
    row(&mut h, "Name", &s.agent.name);
    row(&mut h, "Environment", &s.agent.environment);
    row(
        &mut h,
        "Policy",
        &format!("{} ({})", s.policy.hash, s.policy.path),
    );
    row(&mut h, "Bound domains", &s.policy.domains.join(", "));
    row(&mut h, "Accepts", &s.policy.capabilities.join(", "));
    row(
        &mut h,
        "Declared checks",
        &match &s.policy.checks_hash {
            Some(hash) => format!("{} ({hash}, {})", s.policy.checks, s.policy.checks_path),
            None => format!("none (no {})", s.policy.checks_path),
        },
    );
    if let Some(e) = &s.last_error {
        row(&mut h, "Last error", e);
    }
    h.push_str("</table><h2>Sent to the platform</h2><p>Counts and kinds only. Results carry timings, status codes and error classes, never request or response bodies.</p><table>");
    row(&mut h, "Hello (one per session)", &s.sent.hello.to_string());
    row(&mut h, "Heartbeats", &s.sent.heartbeat.to_string());
    row(&mut h, "Results ok", &s.sent.results_ok.to_string());
    row(&mut h, "Results failed", &s.sent.results_failed.to_string());
    row(&mut h, "Refusals", &s.sent.results_refused.to_string());
    row(&mut h, "Jobs received", &s.received.jobs.to_string());
    h.push_str("</table><h2>Jobs in the last day</h2><table><tr><th>Finished</th><th>Kind</th><th>Surface</th><th>Target host</th><th>Verdict</th><th>ms</th></tr>");
    for j in s.recent_jobs.iter().rev() {
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&j.at),
            esc(&j.kind),
            esc(j.surface.as_deref().unwrap_or("")),
            esc(j.target_host.as_deref().unwrap_or("")),
            esc(&j.verdict),
            j.latency_ms
        );
    }
    h.push_str("</table>");
    if let Some(t) = &s.capture {
        traffic(&mut h, t);
    }
    if let Some(x) = &s.host {
        let _ = write!(
            h,
            "<h2>Host</h2><p>Sampled on this machine; only hwmon check results leave it.</p><table><tr><td>sensors</td><td>{}</td></tr><tr><td>samples in the window</td><td>{}</td></tr><tr><td>last sample</td><td>{} ({} µs; slowest {} µs)</td></tr>{}</table>",
            x.sensors,
            x.samples,
            esc(&x.last_sample_at),
            x.last_cost_us,
            x.max_cost_us,
            x.chipset_millicelsius.map_or_else(String::new, |c| format!(
                "<tr><td>chipset</td><td>{}.{} °C</td></tr>",
                c / 1000,
                (c % 1000).abs() / 100
            ))
        );
    }
    let _ = write!(
        h,
        "<h2>How to stop it</h2><p>{}</p><p><a href=/status.json>status.json</a></p></html>",
        esc(&s.stop)
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AgentInfo, JobRecord, PolicyInfo};

    #[test]
    fn escapes_everything_from_the_platform() {
        let st = AgentState::new(AgentInfo::default(), PolicyInfo::default(), "stop".into());
        st.result_sent(
            JobRecord {
                at: crate::enroll::now_rfc3339(),
                kind: "check".into(),
                surface: Some("http".into()),
                target_host: Some("<script>alert(1)</script>".into()),
                verdict: "ok".into(),
                latency_ms: 1,
            },
            crate::protocol::ResultStatus::Ok,
        );
        let html = render_html(&st.snapshot());
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn host_header_rules() {
        let local: SocketAddr = "127.0.0.1:7790".parse().unwrap();
        assert!(host_allowed(Some("127.0.0.1:7790"), Some(local)));
        assert!(host_allowed(Some("localhost:7790"), Some(local)));
        assert!(host_allowed(Some("[::1]:7790"), Some(local)));
        assert!(!host_allowed(Some("evil.example:7790"), Some(local)));
        assert!(!host_allowed(None, Some(local)));
    }

    #[tokio::test]
    async fn serves_json_and_refuses_writes() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let st = Arc::new(AgentState::new(
            AgentInfo {
                name: "a".into(),
                ..AgentInfo::default()
            },
            PolicyInfo::default(),
            "stop".into(),
        ));
        let (_tx, rx) = watch::channel(false);
        tokio::spawn(serve(l, st, rx));
        let get = |req: String| async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(req.as_bytes()).await.unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).await.unwrap();
            out
        };
        let r = get(format!("GET /status.json HTTP/1.1\r\nHost: {addr}\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        assert!(r.contains("\"connected\": false"));
        let r = get(format!("POST / HTTP/1.1\r\nHost: {addr}\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 405"));
        let r = get("GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n".into()).await;
        assert!(r.starts_with("HTTP/1.1 421"));
    }
}
