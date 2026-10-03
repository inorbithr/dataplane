//! One error type for the agent. Messages name what failed and where, never a secret's
//! value, a token or a response body.

use std::path::PathBuf;

/// Everything that can stop a command.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration file is missing, unreadable or invalid.
    #[error("configuration: {0}")]
    Config(String),
    /// The policy file is missing, unreadable or invalid.
    #[error("policy: {0}")]
    Policy(String),
    /// The checks file (`checks.toml`) is unreadable or invalid.
    #[error("checks: {0}")]
    Checks(String),
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        source: std::io::Error,
    },
    /// The agent key could not be made, read or used.
    #[error("key: {0}")]
    Key(String),
    /// Enrollment failed.
    #[error("enrollment: {0}")]
    Enroll(String),
    /// An access token could not be obtained.
    #[error("token: {0}")]
    Token(String),
    /// The platform or the iohr token socket answered with an error.
    #[error("platform: {0}")]
    Platform(String),
    /// A secret reference could not be resolved. Carries the reference, never the value.
    #[error("secret {reference}: {reason}")]
    Secret {
        /// The reference as written (`vault:…`, `k8s:…`).
        reference: String,
        /// Why it failed.
        reason: String,
    },
    /// The session with the platform failed.
    #[error("session: {0}")]
    Session(String),
    /// The platform revoked this agent.
    #[error("the platform revoked this agent: {0}")]
    Revoked(String),
    /// Telemetry could not be set up.
    #[error("telemetry: {0}")]
    Telemetry(String),
    /// TLS could not be set up.
    #[error("tls: {0}")]
    Tls(String),
}

impl Error {
    /// An I/O error on a path.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Result with the agent's error.
pub type Result<T, E = Error> = std::result::Result<T, E>;
