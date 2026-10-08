//! The session's JSON text frames (shared contract v1, RFC 0029).

use serde::{Deserialize, Serialize};

use crate::checks::CheckDetail;

/// Frames the agent sends.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentFrame {
    /// First frame of every session.
    Hello {
        /// This binary's version.
        agent_version: String,
        /// `sha256:` of the local policy.
        policy_hash: String,
        /// What this agent will accept, after the policy (`check:http`, …).
        capabilities: Vec<String>,
        /// The policy's bound domains.
        domains: Vec<String>,
        /// This machine's clock, RFC 3339 UTC (the platform measures skew).
        agent_time: String,
        /// `sha256:` over the canonical JSON of `checks`; absent without a checks file.
        #[serde(skip_serializing_if = "Option::is_none")]
        checks_hash: Option<String>,
        /// The declared checks, normalized (RFC 0040.1); absent without a checks file.
        #[serde(skip_serializing_if = "Option::is_none")]
        checks: Option<Vec<serde_json::Value>>,
        /// The reported subset of `[metadata]` (RFC 0088): where it runs, who owns it,
        /// what binds it. Absent when nothing is set or `metadata.report = false`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        metadata: Option<Box<crate::metadata::Reported>>,
    },
    /// Keep-alive.
    Heartbeat {
        /// Increments per session.
        seq: u64,
    },
    /// The outcome of a job.
    Result(JobResult),
}

/// `ok`, `failed` or `refused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    /// The work ran and passed.
    Ok,
    /// The work ran and failed.
    Failed,
    /// The local policy refused the work; nothing was attempted.
    Refused,
}

impl ResultStatus {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Refused => "refused",
        }
    }
}

/// Why a job was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// Shown in the console.
    pub reason: String,
}

/// A job's outcome.
#[derive(Debug, Clone, Serialize)]
pub struct JobResult {
    /// The job.
    pub job_id: String,
    /// Outcome.
    pub status: ResultStatus,
    /// RFC 3339.
    pub started_at: String,
    /// RFC 3339.
    pub finished_at: String,
    /// Timings and classes, never content.
    pub detail: CheckDetail,
    /// Present when refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
}

/// Frames the platform sends.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    /// The answer to hello.
    Welcome {
        /// This agent.
        agent_id: String,
        /// Heartbeat interval.
        #[serde(default = "default_heartbeat")]
        heartbeat_secs: u64,
        /// The platform's clock.
        #[serde(default)]
        server_time: Option<String>,
    },
    /// Work.
    Job(Job),
    /// Stop a job.
    Cancel {
        /// The job.
        job_id: String,
    },
    /// This agent is revoked; stop and do not reconnect.
    Revoked {
        /// Why.
        #[serde(default)]
        reason: Option<String>,
    },
    /// A frame this version does not know; ignored.
    #[serde(other)]
    Unknown,
}

fn default_heartbeat() -> u64 {
    15
}

/// A job.
#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    /// Its id.
    pub job_id: String,
    /// `check` (others are refused by this version).
    pub kind: String,
    /// Kind-specific.
    #[serde(default)]
    pub spec: serde_json::Value,
    /// The platform's deadline; cut to the policy's ceiling.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wire_forms() {
        let hello = AgentFrame::Hello {
            agent_version: "0.1.0".into(),
            policy_hash: "sha256:00".into(),
            capabilities: vec!["check:http".into()],
            domains: vec!["example.com".into()],
            agent_time: "2026-10-03T21:00:00Z".into(),
            checks_hash: None,
            checks: None,
            metadata: None,
        };
        assert_eq!(
            serde_json::to_value(&hello).unwrap(),
            json!({"type": "hello", "agent_version": "0.1.0", "policy_hash": "sha256:00",
                   "capabilities": ["check:http"], "domains": ["example.com"],
                   "agent_time": "2026-10-03T21:00:00Z"})
        );
        let hello = AgentFrame::Hello {
            agent_version: "0.1.0".into(),
            policy_hash: "sha256:00".into(),
            capabilities: vec![],
            domains: vec![],
            agent_time: "t".into(),
            checks_hash: Some("sha256:11".into()),
            checks: Some(vec![]),
            metadata: None,
        };
        let v = serde_json::to_value(&hello).unwrap();
        assert_eq!(v["checks_hash"], "sha256:11");
        assert_eq!(v["checks"], json!([]));
        let hb = serde_json::to_value(AgentFrame::Heartbeat { seq: 3 }).unwrap();
        assert_eq!(hb, json!({"type": "heartbeat", "seq": 3}));
        let r = AgentFrame::Result(JobResult {
            job_id: "j".into(),
            status: ResultStatus::Refused,
            started_at: "t0".into(),
            finished_at: "t1".into(),
            detail: CheckDetail::default(),
            refusal: Some(Refusal {
                reason: "no".into(),
            }),
        });
        let v = serde_json::to_value(r).unwrap();
        assert_eq!(v["type"], "result");
        assert_eq!(v["status"], "refused");
        assert_eq!(v["refusal"]["reason"], "no");
    }

    #[test]
    fn server_frames() {
        let f: ServerFrame = serde_json::from_value(json!({"type": "welcome", "agent_id": "agt_1", "heartbeat_secs": 15, "server_time": "x"})).unwrap();
        assert!(matches!(
            f,
            ServerFrame::Welcome {
                heartbeat_secs: 15,
                ..
            }
        ));
        let f: ServerFrame = serde_json::from_value(
            json!({"type": "job", "job_id": "j", "kind": "check", "spec": {}, "deadline_ms": 5000}),
        )
        .unwrap();
        assert!(matches!(
            f,
            ServerFrame::Job(Job {
                deadline_ms: Some(5000),
                ..
            })
        ));
        let f: ServerFrame =
            serde_json::from_value(json!({"type": "something_new", "x": 1})).unwrap();
        assert!(matches!(f, ServerFrame::Unknown));
        let f: ServerFrame =
            serde_json::from_value(json!({"type": "revoked", "reason": "by owner"})).unwrap();
        assert!(matches!(f, ServerFrame::Revoked { .. }));
    }
}
