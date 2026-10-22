//! The WebAssembly extension host (slice 1): runs signed WASI 0.2 components inside
//! the agent, under fuel, memory and deadline limits, and hands them only the host
//! interfaces (`wit/host.wit`) their manifest declares and the machine's policy grants.
//!
//! Slice 1 is the host as a library: [`Package`] reads and verifies a package,
//! [`Host::load`] checks its imports and instantiates it, [`Loaded::init`] and
//! [`Loaded::tick`] call it. The agent supplies the sensor readings and takes the trail
//! events through [`Sensors`] and [`Trail`]; wiring it into the agent's lock and
//! scheduler is the next slice.

mod host;
pub mod limits;
pub mod manifest;
pub mod package;

pub use host::{Event, Host, Loaded, Reading, Sensors, Trail};
pub use limits::{Limits, LimitsHandle};
pub use manifest::{Capability, Manifest};
pub use package::{Package, Signature, Trust};

/// Why a package was refused or a call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// `extension.toml` is not valid.
    #[error("manifest: {0}")]
    Manifest(String),
    /// The signature is missing, untrusted or does not match.
    #[error("signature: {0}")]
    Signature(String),
    /// A package file could not be read.
    #[error("io: {0}")]
    Io(String),
    /// The engine could not start.
    #[error("engine: {0}")]
    Engine(String),
    /// The component is not valid or imports something the host does not offer.
    #[error("component: {0}")]
    Component(String),
    /// The component imports a host interface its manifest or the policy does not allow.
    #[error("capability: {0}")]
    Capability(String),
    /// A call ran past a limit (`fuel`, `deadline` or `memory`).
    #[error("limit: {0}")]
    Limit(&'static str),
    /// The guest trapped; it is stopped.
    #[error("trap: {0}")]
    Trap(String),
    /// `init` or `tick` returned an error.
    #[error("extension: {0}")]
    Guest(String),
}
