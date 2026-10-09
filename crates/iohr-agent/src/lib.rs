//! `iohr-agent`: the InOrbit data plane (RFC 0029). It dials out to the platform over one
//! WebSocket, enforces a local policy on every job, runs surface checks in the company's
//! own network, and reports timings and verdicts, never content.
//!
//! The binary is a thin wrapper over [`cli::main`]; the modules are public so the
//! integration tests can drive an agent against a fake control plane.

pub mod admin;
pub mod agent;
pub mod atlas;
pub mod capture;
pub mod checks;
pub mod checks_file;
pub mod cli;
pub mod config;
pub mod enroll;
pub mod error;
pub mod executor;
pub mod extsock;
pub mod host;
pub mod inventory;
pub mod keys;
pub mod ledger;
pub mod logbuf;
pub mod metadata;
pub mod platform;
pub mod policy;
pub mod protocol;
pub mod redact;
pub mod secrets;
pub mod session;
pub mod share;
pub mod state;
pub mod telemetry;
pub mod tls;
pub mod token;
pub mod x509;

pub use error::{Error, Result};
