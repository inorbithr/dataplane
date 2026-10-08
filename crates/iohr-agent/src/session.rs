//! The outbound session: one WebSocket to the platform, hello and heartbeats up, jobs
//! down, results up. When it drops, every running job is stopped and nothing new starts
//! until it is back; reconnects back off exponentially with full jitter.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use url::Url;

use crate::agent::Agent;
use crate::error::{Error, Result};
use crate::executor::{Admission, Executor, Finished};
use crate::protocol::{AgentFrame, ServerFrame};

/// How long connecting and the welcome may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest frame accepted from the platform.
const MAX_FRAME: usize = 256 * 1024;
/// A session that lasted this long resets the backoff.
const STABLE: Duration = Duration::from_secs(60);

/// How a session ended.
#[derive(Debug)]
pub enum SessionEnd {
    /// Asked to stop.
    Shutdown,
    /// The platform closed it or it dropped.
    Closed,
    /// The platform revoked this agent.
    Revoked(String),
}

/// `wss://<api>/v1/agents/session` (or `ws://` for a loopback test API).
///
/// # Errors
/// When the API URL cannot carry a WebSocket.
pub fn session_url(api: &Url) -> Result<Url> {
    let mut url = api
        .join("v1/agents/session")
        .map_err(|e| Error::Session(e.to_string()))?;
    let scheme = if api.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|()| Error::Session("cannot use the API URL for a WebSocket".into()))?;
    Ok(url)
}

/// Exponential backoff with full jitter.
#[derive(Debug)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    /// Between `min` and `max` milliseconds.
    #[must_use]
    pub fn new(min_ms: u64, max_ms: u64) -> Self {
        Self {
            min: Duration::from_millis(min_ms),
            max: Duration::from_millis(max_ms),
            attempt: 0,
        }
    }

    /// The next delay: uniform in `[0, min(max, min * 2^attempt)]`, at least 10 ms.
    pub fn next_delay(&mut self) -> Duration {
        let ceiling = self
            .min
            .saturating_mul(1u32 << self.attempt.min(16))
            .min(self.max);
        self.attempt = self.attempt.saturating_add(1);
        let mut r = [0u8; 8];
        let _ = getrandom::fill(&mut r);
        let frac = u64::from_le_bytes(r);
        let ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        let jittered = if ms == 0 { 0 } else { frac % (ms + 1) };
        Duration::from_millis(jittered.max(10))
    }

    /// Back to the first step.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Runs sessions until shutdown or revocation.
///
/// # Errors
/// [`Error::Revoked`] when the platform revoked the agent.
pub async fn run(agent: Arc<Agent>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let mut backoff = Backoff::new(
        agent.config.session.backoff_min_ms,
        agent.config.session.backoff_max_ms,
    );
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let began = Instant::now();
        let end = once(&agent, &mut shutdown).await;
        match end {
            Ok(SessionEnd::Shutdown) => {
                agent.state.disconnected(None);
                return Ok(());
            }
            Ok(SessionEnd::Revoked(reason)) => {
                agent.state.revoked();
                tracing::error!(%reason, "the platform revoked this agent; stopping");
                return Err(Error::Revoked(reason));
            }
            Ok(SessionEnd::Closed) => {
                tracing::warn!("session closed by the platform; reconnecting");
                agent.state.disconnected(Some("session closed".into()));
            }
            Err(e) => {
                tracing::warn!(error = %e, "session failed; reconnecting");
                agent.state.disconnected(Some(e.to_string()));
            }
        }
        if began.elapsed() >= STABLE {
            backoff.reset();
        }
        let delay = backoff.next_delay();
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            _ = shutdown.changed() => return Ok(()),
        }
    }
}

#[allow(clippy::too_many_lines)] // one select loop reads best in one place
async fn once(agent: &Arc<Agent>, shutdown: &mut watch::Receiver<bool>) -> Result<SessionEnd> {
    let token = agent.tokens.access_token().await?;
    let url = session_url(&agent.config.api)?;
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|e| Error::Session(e.to_string()))?;
    let mut bearer = http::HeaderValue::from_str(&format!("Bearer {}", token.as_str()))
        .map_err(|_| Error::Session("access token is not a valid header value".into()))?;
    bearer.set_sensitive(true);
    request
        .headers_mut()
        .insert(http::header::AUTHORIZATION, bearer);
    request.headers_mut().insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static(concat!("iohr-agent/", env!("CARGO_PKG_VERSION"))),
    );
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME))
        .max_frame_size(Some(MAX_FRAME));
    let connector =
        tokio_tungstenite::Connector::Rustls(Arc::new(agent.tls.client_config(&[b"http/1.1"])));
    let connect = tokio_tungstenite::connect_async_tls_with_config(
        request,
        Some(ws_config),
        true,
        Some(connector),
    );
    // The upgrade request carries no body: its headers are the access token and the
    // user agent. Recorded like every other message before it leaves.
    agent.ledger_record(crate::ledger::Record {
        kind: "session_open",
        payload: b"",
        rule: "contract.session",
        destination: url.as_str(),
        job_id: None,
    })?;
    let (ws, _) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, connect).await {
        Err(_) => return Err(Error::Session("connecting timed out".into())),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(resp))) => {
            if resp.status() == http::StatusCode::UNAUTHORIZED {
                agent.tokens.invalidate().await;
            }
            return Err(Error::Session(format!(
                "the platform refused the session: {}",
                resp.status().as_u16()
            )));
        }
        Ok(Err(e)) => return Err(Error::Session(format!("connecting failed: {e}"))),
        Ok(Ok(pair)) => pair,
    };
    drop(token);
    let (mut sink, mut stream) = ws.split();

    let mut capabilities = agent.executor.capabilities();
    if let Some(policy) = agent.policy.capture() {
        // Only the capability strings travel: what this host can show, never what it saw.
        let info = crate::capture::check(&policy, crate::capture::HELLO_TIMEOUT).await;
        if info.state != "answering" {
            tracing::info!(state = %info.state, reason = info.reason.as_deref().unwrap_or(""), "capture companion not announced");
        }
        capabilities.extend(info.capabilities.iter().cloned());
        agent.state.capture_checked(info);
    }
    let hello = AgentFrame::Hello {
        agent_version: env!("CARGO_PKG_VERSION").into(),
        policy_hash: agent.policy_hash.clone(),
        capabilities,
        domains: agent.policy.domains.bound.clone(),
        agent_time: now_utc_seconds(),
        checks_hash: agent.shared_checks.as_ref().map(|(_, h)| h.clone()),
        checks: agent.shared_checks.as_ref().map(|(w, _)| w.clone()),
        metadata: agent.config.metadata.reported().map(Box::new),
        hostname: agent
            .policy
            .share()
            .hostname
            .then(crate::host::sysfs::host_name),
    };
    send(agent, &mut sink, &hello, "contract.hello", None).await?;

    let welcome = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        while let Some(msg) = stream.next().await {
            match msg.map_err(|e| Error::Session(e.to_string()))? {
                Message::Text(t) => {
                    return match serde_json::from_str::<ServerFrame>(t.as_str()) {
                        Ok(ServerFrame::Welcome {
                            agent_id,
                            heartbeat_secs,
                            ..
                        }) => Ok(Ok((agent_id, heartbeat_secs))),
                        Ok(ServerFrame::Revoked { reason }) => {
                            Ok(Err(reason.unwrap_or_else(|| "revoked".into())))
                        }
                        _ => Err(Error::Session("expected welcome".into())),
                    };
                }
                Message::Close(_) => return Err(Error::Session("closed before welcome".into())),
                _ => {}
            }
        }
        Err(Error::Session("closed before welcome".into()))
    })
    .await
    .map_err(|_| Error::Session("no welcome in time".into()))??;
    let (agent_id, heartbeat_secs) = match welcome {
        Ok(w) => w,
        Err(reason) => return Ok(SessionEnd::Revoked(reason)),
    };
    if agent_id != agent.enrollment.agent_id {
        tracing::warn!(expected = %agent.enrollment.agent_id, got = %agent_id, "welcome names another agent id");
    }
    agent.state.connected(&agent_id);
    tracing::info!(agent_id = %agent_id, "connected to the platform");

    let beat = Duration::from_secs(heartbeat_secs.clamp(1, 300));
    let idle_limit = beat * 3;
    let mut heartbeat = tokio::time::interval_at(tokio::time::Instant::now() + beat, beat);
    let mut seq = 0u64;
    let mut last_seen = tokio::time::Instant::now();
    let (tx, mut rx) = mpsc::channel::<Finished>(64);
    let mut running: HashMap<String, tokio::task::AbortHandle> = HashMap::new();
    let mut tasks = JoinSet::new();

    // Dropping `tasks` at any return aborts every running job: no work without a session.
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tasks.abort_all();
                let _ = sink.send(Message::Close(None)).await;
                return Ok(SessionEnd::Shutdown);
            }
            _ = heartbeat.tick() => {
                seq += 1;
                send(agent, &mut sink, &AgentFrame::Heartbeat { seq }, "contract.heartbeat", None).await?;
                agent.state.heartbeat();
                // The contract has no frame from the platform between jobs; a WebSocket
                // ping makes any server answer with a pong, so a half-open connection is
                // noticed within three heartbeats.
                sink.send(Message::Ping(bytes::Bytes::new()))
                    .await
                    .map_err(|e| Error::Session(format!("send failed: {e}")))?;
                agent.state.ping();
            }
            Some(mut done) = rx.recv() => {
                agent.executor.prepare_for_platform(&mut done);
                running.remove(&done.result.job_id);
                agent.state.job_finished();
                let status = done.result.status;
                let rule = result_rule(&done);
                let id = done.result.job_id.clone();
                send(agent, &mut sink, &AgentFrame::Result(done.result), &rule, Some(&id)).await?;
                agent.state.result_sent(done.record, status);
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            () = tokio::time::sleep_until(last_seen + idle_limit) => {
                return Err(Error::Session(format!("nothing from the platform for {}s", idle_limit.as_secs())));
            }
            msg = stream.next() => {
                last_seen = tokio::time::Instant::now();
                let Some(msg) = msg else { return Ok(SessionEnd::Closed) };
                match msg.map_err(|e| Error::Session(e.to_string()))? {
                    Message::Text(t) => match serde_json::from_str::<ServerFrame>(t.as_str()) {
                        Ok(ServerFrame::Job(job)) => {
                            agent.state.job_received();
                            match agent.executor.admit(&job) {
                                Admission::Refuse(reason) => {
                                    let mut done = Executor::refused(&job, reason);
                                    agent.executor.prepare_for_platform(&mut done);
                                    let status = done.result.status;
                                    let id = done.result.job_id.clone();
                                    send(agent, &mut sink, &AgentFrame::Result(done.result), "contract.refusal", Some(&id)).await?;
                                    agent.state.result_sent(done.record, status);
                                }
                                Admission::Run(admitted) => {
                                    let exec = Arc::clone(&agent.executor);
                                    let tx = tx.clone();
                                    let id = job.job_id.clone();
                                    let handle = tasks.spawn(async move {
                                        let done = exec.execute(id, *admitted).await;
                                        let _ = tx.send(done).await;
                                    });
                                    running.insert(job.job_id, handle);
                                    agent.state.job_started();
                                }
                            }
                        }
                        Ok(ServerFrame::Cancel { job_id }) => {
                            agent.state.cancel_received();
                            if let Some(h) = running.remove(&job_id) {
                                h.abort();
                                tracing::info!(%job_id, "job cancelled by the platform");
                            }
                        }
                        Ok(ServerFrame::Revoked { reason }) => {
                            tasks.abort_all();
                            return Ok(SessionEnd::Revoked(reason.unwrap_or_else(|| "revoked".into())));
                        }
                        Ok(ServerFrame::Welcome { .. } | ServerFrame::Unknown) => {}
                        Err(e) => tracing::warn!(error = %e, "ignoring a frame this agent does not understand"),
                    },
                    Message::Close(_) => return Ok(SessionEnd::Closed),
                    _ => {}
                }
            }
        }
    }
}

/// Now, RFC 3339 UTC to the second (`2026-10-03T21:00:00Z`).
fn now_utc_seconds() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// The rule that let a result leave: the surface the policy turned on, or the contract's
/// duty to answer every job (a refusal, or a run the policy then refused).
fn result_rule(done: &crate::executor::Finished) -> String {
    match (done.result.status, &done.record.surface) {
        (crate::protocol::ResultStatus::Refused, _) | (_, None) => "contract.refusal".into(),
        (_, Some(s)) => format!("work.surfaces.{s}"),
    }
}

/// Serialises a frame, records it in the egress ledger, then sends it: a frame the
/// ledger could not record is not sent.
async fn send<S>(
    agent: &Agent,
    sink: &mut S,
    frame: &AgentFrame,
    rule: &str,
    job_id: Option<&str>,
) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let text = serde_json::to_string(frame).map_err(|e| Error::Session(e.to_string()))?;
    let kind = match frame {
        AgentFrame::Hello { .. } => "hello",
        AgentFrame::Heartbeat { .. } => "heartbeat",
        AgentFrame::Result(_) => "result",
    };
    agent.ledger_record(crate::ledger::Record {
        kind,
        payload: text.as_bytes(),
        rule,
        destination: agent.session_destination.as_str(),
        job_id,
    })?;
    sink.send(Message::text(text))
        .await
        .map_err(|e| Error::Session(format!("send failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_time_is_utc_seconds() {
        let t = now_utc_seconds();
        assert!(t.ends_with('Z') && t.len() == 20, "{t}");
    }

    #[test]
    fn urls() {
        let u = session_url(&Url::parse("https://api.inorbit.hr").unwrap()).unwrap();
        assert_eq!(u.as_str(), "wss://api.inorbit.hr/v1/agents/session");
        let u = session_url(&Url::parse("http://127.0.0.1:8080/").unwrap()).unwrap();
        assert_eq!(u.as_str(), "ws://127.0.0.1:8080/v1/agents/session");
    }

    #[test]
    fn backoff_grows_and_stays_bounded() {
        let mut b = Backoff::new(100, 1_000);
        for _ in 0..50 {
            let d = b.next_delay();
            assert!(d <= Duration::from_millis(1_000));
        }
        b.reset();
        assert!(b.next_delay() <= Duration::from_millis(100));
    }
}
