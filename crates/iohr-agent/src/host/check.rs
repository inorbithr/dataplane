//! The `hwmon` check: a sensor against thresholds from `checks.toml`, judged on the
//! sampler's window, so a spike between two platform runs is not missed. The level is
//! the worst since the previous run (at most the window): `crit` fails the check (the
//! platform's monitor goes down after `fail_after` and can open an incident), `warn`
//! passes with the level in the result, so the platform can show it.

use std::time::Duration;

use serde::Serialize;

use super::hwmon::{Kind, SensorRef};
use super::sampler::Sampler;

/// How far back the rate looks.
pub const RATE_OVER: Duration = Duration::from_secs(120);
/// Without a previous run, how far back the level looks.
pub const FIRST_LOOK: Duration = Duration::from_secs(60);

/// A declared hwmon check's thresholds, in the sensor's raw unit (milli-degrees for a
/// temperature); rates per minute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwmonSpec {
    /// The sensor.
    pub sensor: SensorRef,
    /// Warn at or past this.
    pub warn: Option<i64>,
    /// Fail at or past this.
    pub crit: Option<i64>,
    /// Warn when rising (or, `below`, falling) at least this fast.
    pub rate_warn: Option<i64>,
    /// Fail when rising (or falling) at least this fast.
    pub rate_crit: Option<i64>,
    /// Thresholds are lower bounds (a fan that stops).
    pub below: bool,
}

/// A level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Inside the thresholds.
    Ok,
    /// Past `warn` or `rate_warn`.
    Warn,
    /// Past `crit` or `rate_crit`.
    Crit,
}

/// What a hwmon check reports: numbers and a level, nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reading {
    /// The sensor's key (`asusec/temp/Chipset`).
    pub sensor: String,
    /// The raw unit (`millicelsius`).
    pub unit: &'static str,
    /// The newest value.
    pub value: i64,
    /// The worst value since the previous run.
    pub peak: i64,
    /// Change per minute over the last two minutes, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_per_min: Option<i64>,
    /// The level.
    pub level: Level,
    /// Samples the judgement used.
    pub samples: u32,
}

/// Why there is no reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoReading {
    /// The sensor is not on this host (or the name is ambiguous).
    Missing(String),
    /// The sampler has no value for it yet.
    NotSampled,
}

fn past(v: i64, t: Option<i64>, below: bool) -> bool {
    t.is_some_and(|t| if below { v <= t } else { v >= t })
}

/// Judges `spec` on the window, looking back to `since_ms` (the previous run), or
/// [`FIRST_LOOK`] when there was none.
///
/// # Errors
/// No reading for the sensor.
pub fn judge(
    s: &Sampler,
    chips: &[super::hwmon::Chip],
    spec: &HwmonSpec,
    since_ms: Option<u64>,
) -> Result<Reading, NoReading> {
    let (chip, sensor) = spec.sensor.find(chips).map_err(NoReading::Missing)?;
    let key = chip.key(sensor);
    let value = s.latest(&key).ok_or(NoReading::NotSampled)?;
    let now = s.now_ms().unwrap_or(0);
    let first = u64::try_from(FIRST_LOOK.as_millis()).unwrap_or(0);
    let since = since_ms
        .unwrap_or_else(|| now.saturating_sub(first))
        .min(now);
    let peak = s.extreme_since(&key, since, spec.below).unwrap_or(value);
    let samples = u32::try_from(
        s.samples()
            .iter()
            .filter(|x| x.at_ms >= since && x.values.contains_key(&key))
            .count(),
    )
    .unwrap_or(u32::MAX);
    let rate = s.rate_per_min(&key, RATE_OVER);
    let signed_rate = rate.map(|r| if spec.below { -r } else { r });
    let level = if past(peak, spec.crit, spec.below)
        || signed_rate.is_some_and(|r| past(r, spec.rate_crit, false))
    {
        Level::Crit
    } else if past(peak, spec.warn, spec.below)
        || signed_rate.is_some_and(|r| past(r, spec.rate_warn, false))
    {
        Level::Warn
    } else {
        Level::Ok
    };
    Ok(Reading {
        sensor: key,
        unit: sensor.kind.unit(),
        value,
        peak,
        rate_per_min: rate,
        level,
        samples,
    })
}

/// `100` or `100.5` (°C, V, A, W, RPM) to the raw unit.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)] // bounded by the file rules
pub fn to_raw(kind: Kind, human: f64) -> i64 {
    (human * kind.scale() as f64).round() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::hwmon;
    use crate::host::sampler::tests::sample;
    use crate::host::sysfs::Root;

    fn spec(warn: i64, crit: i64) -> HwmonSpec {
        HwmonSpec {
            sensor: SensorRef::parse("asusec/Chipset", Kind::Temp).unwrap(),
            warn: Some(warn),
            crit: Some(crit),
            rate_warn: Some(2_000),
            rate_crit: None,
            below: false,
        }
    }

    #[test]
    fn the_trx40_chipset_is_warn_at_107_and_crit_at_108() {
        let root = Root::at(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/host/trx40/root"),
        );
        let chips = hwmon::read(&root);
        let mut s = Sampler::new(root, Duration::from_secs(600));
        s.tick();
        let r = judge(&s, &chips, &spec(100_000, 108_000), None).unwrap();
        assert_eq!((r.value, r.level), (107_000, Level::Warn));
        assert_eq!(r.rate_per_min, None, "one sample: no rate");
        let r = judge(&s, &chips, &spec(100_000, 107_000), None).unwrap();
        assert_eq!(r.level, Level::Crit);
        let mut missing = spec(1, 2);
        missing.sensor = SensorRef::parse("asusec/Nope", Kind::Temp).unwrap();
        assert!(matches!(
            judge(&s, &chips, &missing, None),
            Err(NoReading::Missing(_))
        ));
    }

    #[test]
    fn a_spike_between_runs_and_a_fast_rise_are_seen() {
        let root = Root::at(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/host/trx40/root"),
        );
        let chips = hwmon::read(&root);
        let mut s = Sampler::new(root, Duration::from_secs(600));
        let k = "asusec/temp/Chipset";
        // Flat at 99, one 10 s spike to 109, back to 99.
        for (i, v) in [99, 99, 109, 99, 99, 99, 99].iter().enumerate() {
            s.push(sample(
                u64::try_from(i).unwrap() * 10_000,
                k,
                v * 1_000,
                "d",
                0,
            ));
        }
        let r = judge(&s, &chips, &spec(100_000, 108_000), Some(0)).unwrap();
        assert_eq!((r.value, r.peak, r.level), (99_000, 109_000, Level::Crit));
        // Since a later run, the spike is no longer in view.
        let r = judge(&s, &chips, &spec(100_000, 108_000), Some(30_000)).unwrap();
        assert_eq!(r.level, Level::Ok);
        // Rising 3 °C a minute warns below the threshold.
        let mut s2 = Sampler::new(
            Root::at(std::path::Path::new("/nonexistent")),
            Duration::from_secs(600),
        );
        for i in 0..7i64 {
            s2.push(sample(
                u64::try_from(i).unwrap() * 10_000,
                k,
                90_000 + i * 500,
                "d",
                0,
            ));
        }
        let r = judge(&s2, &chips, &spec(100_000, 108_000), None).unwrap();
        assert_eq!((r.rate_per_min, r.level), (Some(3_000), Level::Warn));
    }

    #[test]
    fn a_stopped_fan_with_below() {
        let root = Root::at(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/host/trx40/root"),
        );
        let chips = hwmon::read(&root);
        let mut s = Sampler::new(root, Duration::from_secs(600));
        s.push(sample(0, "asusec/fan/Chipset", 0, "d", 0));
        let spec = HwmonSpec {
            sensor: SensorRef::parse("asusec/Chipset", Kind::Fan).unwrap(),
            warn: Some(3_000),
            crit: Some(1_000),
            rate_warn: None,
            rate_crit: None,
            below: true,
        };
        assert_eq!(judge(&s, &chips, &spec, None).unwrap().level, Level::Crit);
        assert_eq!(to_raw(Kind::Temp, 100.5), 100_500);
    }
}
