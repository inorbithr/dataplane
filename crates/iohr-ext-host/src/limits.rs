//! The sandbox's bounds. The engine-wide ones are fixed when the [`crate::Host`] is
//! built (the gate evaluator's profile, core `crates/gate-eval`); the per-call ones
//! live in a [`LimitsHandle`] every call reads, so an operator tunes them while
//! extensions run.

use std::sync::{Arc, PoisonError, RwLock};

/// How often the epoch ticker advances, in milliseconds.
pub const EPOCH_TICK_MS: u64 = 10;
/// Largest component file the host compiles.
pub const MAX_COMPONENT_BYTES: usize = 8 * 1024 * 1024;
/// Largest manifest file.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Wasm stack per call.
pub const MAX_WASM_STACK: usize = 512 * 1024;
/// Address space reserved per linear memory up front.
pub const MEMORY_RESERVATION: u64 = 16 * 1024 * 1024;
/// Table elements per table.
pub const MAX_TABLE_ELEMENTS: usize = 10_000;
/// Core instances, memories and tables a component may create (a WASI 0.2
/// component is several core modules glued together).
pub const MAX_INSTANCES: usize = 32;
/// See [`MAX_INSTANCES`].
pub const MAX_MEMORIES: usize = 4;
/// See [`MAX_INSTANCES`].
pub const MAX_TABLES: usize = 16;
/// Longest log line kept, in bytes.
pub const MAX_LOG_BYTES: usize = 1024;
/// Longest name (event, attribute key, sensor, config key), in bytes.
pub const MAX_NAME: usize = 128;
/// Longest attribute value, in bytes.
pub const MAX_VALUE: usize = 1024;
/// Most attributes on one trail event.
pub const MAX_ATTRS: usize = 32;
/// Longest tick interval an extension may ask for (an hour).
pub const MAX_INTERVAL_MS: u32 = 3_600_000;

/// The per-call bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Fuel (roughly, wasm instructions) one `init` or `tick` may burn.
    pub fuel: u64,
    /// Wall time one call may take, in milliseconds (epoch deadline).
    pub deadline_ms: u64,
    /// Linear memory an extension may hold in all, in bytes.
    pub memory_bytes: u64,
    /// Shortest tick interval, in milliseconds.
    pub min_interval_ms: u32,
    /// Trail events one call may emit.
    pub trail_per_call: u32,
    /// Log lines one call may write.
    pub log_per_call: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            fuel: 10_000_000,
            deadline_ms: 2_000,
            memory_bytes: 16 * 1024 * 1024,
            min_interval_ms: 1_000,
            trail_per_call: 64,
            log_per_call: 64,
        }
    }
}

impl Limits {
    /// The epoch ticks a call may run, at least one.
    #[must_use]
    pub fn deadline_ticks(&self) -> u64 {
        self.deadline_ms.div_ceil(EPOCH_TICK_MS).max(1)
    }

    /// `ms` within `[min_interval_ms, MAX_INTERVAL_MS]`.
    #[must_use]
    pub fn clamp_interval(&self, ms: u32) -> u32 {
        ms.clamp(self.min_interval_ms.min(MAX_INTERVAL_MS), MAX_INTERVAL_MS)
    }
}

/// Shared, live limits: every call reads them, [`LimitsHandle::set`] changes them
/// for the next call of every running extension.
#[derive(Debug, Clone, Default)]
pub struct LimitsHandle(Arc<RwLock<Limits>>);

impl LimitsHandle {
    /// A handle holding `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self(Arc::new(RwLock::new(limits)))
    }

    /// The current limits.
    #[must_use]
    pub fn get(&self) -> Limits {
        *self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the limits; running calls keep theirs, the next call reads these.
    pub fn set(&self, limits: Limits) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = limits;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadlines_round_up_to_a_tick_and_intervals_clamp() {
        let l = Limits {
            deadline_ms: 15,
            ..Limits::default()
        };
        assert_eq!(l.deadline_ticks(), 2);
        assert_eq!(
            Limits {
                deadline_ms: 0,
                ..l
            }
            .deadline_ticks(),
            1
        );
        assert_eq!(l.clamp_interval(10), 1_000);
        assert_eq!(l.clamp_interval(u32::MAX), MAX_INTERVAL_MS);
    }

    #[test]
    fn a_handle_change_is_seen_by_every_clone() {
        let h = LimitsHandle::new(Limits::default());
        let other = h.clone();
        h.set(Limits {
            fuel: 7,
            ..Limits::default()
        });
        assert_eq!(other.get().fuel, 7);
    }
}
