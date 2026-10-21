//! The agent's own probes as sensor readings (PRD 0152 slice 2, `[sensors]`).
//!
//! Each tick turns the host summary (`host::summary`) into a few `signal` frames: the
//! one-minute load, memory used, the fullest disk and the hottest temperature. Every
//! frame carries the host id (the agent's id) so the platform can tell hosts apart.
//! Values only; no mount names, no sensor labels.

use serde_json::Value;

use crate::actions::{Level, Signal};

/// The template name every probe reports under.
pub const TEMPLATE: &str = "host-probe";

/// Sensor names, stable and published.
pub const LOAD: &str = "host.load_1m";
/// Memory used, percent.
pub const MEMORY: &str = "host.memory_used_percent";
/// The fullest disk, percent used.
pub const DISK: &str = "host.disk_used_percent_max";
/// The hottest temperature, degrees Celsius.
pub const TEMPERATURE: &str = "host.temperature_c_max";

fn level(value: f64, warn: f64, crit: f64) -> Level {
    if value >= crit {
        Level::Crit
    } else if value >= warn {
        Level::Warn
    } else {
        Level::Ok
    }
}

/// The readings in `summary`, tagged with `host` and `at`. A probe the host lacks gives
/// no frame.
#[must_use]
pub fn signals(summary: &Value, host: &str, at: &str) -> Vec<Signal> {
    let mut out = Vec::new();
    let mut push = |sensor: &str, v: Option<f64>, warn: f64, crit: f64| {
        if let Some(v) = v.filter(|v| v.is_finite()) {
            out.push(Signal {
                sensor: sensor.into(),
                template: TEMPLATE.into(),
                value: Some(v),
                level: level(v, warn, crit),
                series: 1,
                at: at.into(),
                host: Some(host.into()),
            });
        }
    };
    let cpus = summary.get("cpus").and_then(Value::as_f64).unwrap_or(1.0).max(1.0);
    push(
        LOAD,
        summary.get("load_1m").and_then(Value::as_f64),
        cpus,
        cpus * 2.0,
    );
    push(
        MEMORY,
        summary.get("memory_used_percent").and_then(Value::as_f64),
        85.0,
        95.0,
    );
    let disk = summary
        .get("disks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|d| d.get("used_percent").and_then(Value::as_f64))
        .fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))));
    push(DISK, disk, 85.0, 95.0);
    let temp = summary
        .get("temperatures")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| t.get("celsius").and_then(Value::as_f64))
        .fold(None, |m: Option<f64>, v| Some(m.map_or(v, |m| m.max(v))));
    push(TEMPERATURE, temp, 80.0, 90.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn readings_carry_the_host_id_and_the_worst_disk() {
        let s = json!({"load_1m": 9.0, "cpus": 4, "memory_used_percent": 50.0,
            "disks": [{"mount": "/", "used_percent": 40.0}, {"mount": "/data", "used_percent": 97.0}],
            "temperatures": [{"sensor": "cpu", "celsius": 61.5}]});
        let v = signals(&s, "agt_01TEST", "2026-10-21T00:00:00Z");
        assert_eq!(v.len(), 4);
        assert!(v.iter().all(|x| x.host.as_deref() == Some("agt_01TEST")));
        let by = |n: &str| v.iter().find(|x| x.sensor == n).unwrap();
        assert_eq!(by(LOAD).level, Level::Crit);
        assert_eq!(by(DISK).value, Some(97.0));
        assert_eq!(by(DISK).level, Level::Crit);
        assert_eq!(by(TEMPERATURE).level, Level::Ok);
    }

    #[test]
    fn a_host_without_probes_gives_nothing() {
        assert!(signals(&json!({}), "agt_x", "t").is_empty());
    }
}
