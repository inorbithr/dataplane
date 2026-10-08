//! Time: intervals and observation time with uncertainty (ADRs 0004, 0014 in
//! inorbithr/core).
//!
//! An [`Interval`] is half-open and, once closed, never changes: the bitemporal records
//! Atlas keeps (valid time and recorded time) are built from two of them in Atlas core.
//!
//! Observation time is not just a wall clock: clocks drift and hosts reboot. An
//! observed time carries the wall reading, the boot it was read in, and the clock's
//! uncertainty, so two events can be ordered only when their uncertainty windows do
//! not overlap.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

/// An instant, always UTC.
pub type Timestamp = DateTime<Utc>;

/// A half-open interval `[from, to)`. `to == None` means "still open".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    from: Timestamp,
    to: Option<Timestamp>,
}

/// An interval whose end is not after its start.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("interval ends at {to} before it starts at {from}")]
pub struct EmptyInterval {
    /// The start.
    pub from: Timestamp,
    /// The end, not after the start.
    pub to: Timestamp,
}

impl Interval {
    /// An interval still open at its end.
    #[must_use]
    pub const fn open(from: Timestamp) -> Self {
        Self { from, to: None }
    }

    /// A closed interval `[from, to)`.
    ///
    /// # Errors
    /// `to` is not strictly after `from`: an empty interval would be a record that
    /// never held, which the store refuses.
    pub fn closed(from: Timestamp, to: Timestamp) -> Result<Self, EmptyInterval> {
        if to <= from {
            return Err(EmptyInterval { from, to });
        }
        Ok(Self { from, to: Some(to) })
    }

    /// The start.
    #[must_use]
    pub const fn from(&self) -> Timestamp {
        self.from
    }

    /// The end, or `None` while open.
    #[must_use]
    pub const fn to(&self) -> Option<Timestamp> {
        self.to
    }

    /// Whether `t` lies in `[from, to)`.
    #[must_use]
    pub fn contains(&self, t: Timestamp) -> bool {
        t >= self.from && self.to.is_none_or(|to| t < to)
    }

    /// This interval closed at `at`.
    ///
    /// # Errors
    /// The interval is already closed, or `at` is not after its start.
    pub fn close_at(self, at: Timestamp) -> Result<Self, CloseError> {
        if self.to.is_some() {
            return Err(CloseError::AlreadyClosed);
        }
        Self::closed(self.from, at).map_err(CloseError::Empty)
    }
}

/// Why an interval could not be closed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CloseError {
    /// Already closed: a closed record is history and never changes.
    #[error("the interval is already closed")]
    AlreadyClosed,
    /// Closing it here would leave it empty.
    #[error(transparent)]
    Empty(EmptyInterval),
}

/// Which clock produced a reading, and how far it may be off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockQuality {
    /// The clock source, e.g. `ntp`, `ptp`, `rtc`, `unknown`.
    pub source: String,
    /// The worst-case error, both ways.
    pub uncertainty: TimeDelta,
}

/// When an observer saw something, as precisely as it can say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedTime {
    /// The wall-clock reading.
    pub wall: Timestamp,
    /// The boot the reading was taken in (a reboot resets monotonic clocks).
    pub boot_id: String,
    /// Monotonic nanoseconds since that boot, when the observer has one.
    pub monotonic_ns: Option<u64>,
    /// The clock and its uncertainty.
    pub clock: ClockQuality,
}

/// How two observations order in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalOrder {
    /// The first certainly happened before the second.
    Before,
    /// The first certainly happened after the second.
    After,
    /// The clocks cannot tell: correlated, but not ordered.
    Unresolved,
}

impl ObservedTime {
    /// How `self` orders against `other`.
    ///
    /// Within one boot, monotonic readings decide exactly. Otherwise the wall readings
    /// decide only when their uncertainty windows do not overlap; when they overlap the
    /// order is unresolved, never guessed.
    #[must_use]
    pub fn order(&self, other: &Self) -> TemporalOrder {
        if self.boot_id == other.boot_id
            && let (Some(a), Some(b)) = (self.monotonic_ns, other.monotonic_ns)
        {
            return match a.cmp(&b) {
                std::cmp::Ordering::Less => TemporalOrder::Before,
                std::cmp::Ordering::Greater => TemporalOrder::After,
                std::cmp::Ordering::Equal => TemporalOrder::Unresolved,
            };
        }
        let a_late = self.wall + self.clock.uncertainty;
        let b_early = other.wall - other.clock.uncertainty;
        if a_late < b_early {
            return TemporalOrder::Before;
        }
        let a_early = self.wall - self.clock.uncertainty;
        let b_late = other.wall + other.clock.uncertainty;
        if b_late < a_early {
            return TemporalOrder::After;
        }
        TemporalOrder::Unresolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use proptest::prelude::*;

    fn at(s: i64) -> Timestamp {
        Utc.timestamp_opt(1_800_000_000 + s, 0).unwrap()
    }

    fn observed(wall_s: i64, boot: &str, mono: Option<u64>, unc_ms: i64) -> ObservedTime {
        ObservedTime {
            wall: at(wall_s),
            boot_id: boot.to_owned(),
            monotonic_ns: mono,
            clock: ClockQuality {
                source: "ntp".into(),
                uncertainty: TimeDelta::milliseconds(unc_ms),
            },
        }
    }

    #[test]
    fn empty_and_reversed_intervals_are_refused() {
        assert!(Interval::closed(at(5), at(5)).is_err());
        assert!(Interval::closed(at(5), at(4)).is_err());
        assert!(Interval::closed(at(5), at(6)).is_ok());
    }

    #[test]
    fn a_closed_interval_never_changes() {
        let i = Interval::closed(at(0), at(10)).unwrap();
        assert_eq!(i.close_at(at(20)), Err(CloseError::AlreadyClosed));
    }

    #[test]
    fn same_boot_orders_by_monotonic_even_when_wall_clocks_disagree() {
        let a = observed(100, "b1", Some(5), 0);
        let b = observed(50, "b1", Some(9), 0);
        assert_eq!(a.order(&b), TemporalOrder::Before);
    }

    #[test]
    fn overlapping_uncertainty_is_unresolved_not_guessed() {
        let a = observed(100, "h1", None, 500);
        let b = observed(100, "h2", None, 500);
        assert_eq!(a.order(&b), TemporalOrder::Unresolved);
        let far = observed(102, "h2", None, 500);
        assert_eq!(a.order(&far), TemporalOrder::Before);
        assert_eq!(far.order(&a), TemporalOrder::After);
    }

    proptest! {
        // Ordering is antisymmetric: if a is before b, b is after a; unresolved both ways.
        #[test]
        fn order_is_antisymmetric(wa in 0i64..1000, wb in 0i64..1000, ua in 0i64..3000, ub in 0i64..3000,
                                  same_boot in any::<bool>(), ma in proptest::option::of(0u64..1000), mb in proptest::option::of(0u64..1000)) {
            let a = observed(wa, "b1", ma, ua);
            let b = observed(wb, if same_boot { "b1" } else { "b2" }, mb, ub);
            let expected = match a.order(&b) {
                TemporalOrder::Before => TemporalOrder::After,
                TemporalOrder::After => TemporalOrder::Before,
                TemporalOrder::Unresolved => TemporalOrder::Unresolved,
            };
            prop_assert_eq!(b.order(&a), expected);
        }

        #[test]
        fn contains_matches_half_open_bounds(from in 0i64..100, len in 1i64..100, t in -10i64..220) {
            let i = Interval::closed(at(from), at(from + len)).unwrap();
            prop_assert_eq!(i.contains(at(t)), t >= from && t < from + len);
        }
    }
}
