//! `host.pressure`: pressure stall information (PSI) for cpu, io and memory, load,
//! memory and swap, and OOM kills. All from `/proc`, unprivileged.
//!
//! How it can fail: PSI needs a kernel built with it (`/proc/pressure` missing → not
//! observed); the kernel log is often restricted (`kernel.dmesg_restrict`), so OOM
//! events come from the `oom_kill` counter in `/proc/vmstat`, which every user can
//! read, and the log is used only when readable.

use std::collections::BTreeMap;

use serde::Serialize;

use super::sysfs::Root;

/// One PSI line (`some` or `full`): averages in hundredths of a percent, total in µs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Psi {
    /// 10 s average, hundredths of a percent (`avg10=1.25` is 125).
    pub avg10: i64,
    /// 60 s average.
    pub avg60: i64,
    /// 300 s average.
    pub avg300: i64,
    /// Total stall time, µs.
    pub total_us: i64,
}

/// What `/proc` says about pressure.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Pressure {
    /// `cpu/some`, `io/full`, ... ; empty when the kernel has no PSI.
    pub psi: BTreeMap<String, Psi>,
    /// Load averages ×100 (1, 5, 15 minutes).
    pub load: Option<[i64; 3]>,
    /// From `/proc/meminfo`, KiB.
    pub mem_total_kib: Option<i64>,
    /// KiB.
    pub mem_available_kib: Option<i64>,
    /// KiB.
    pub swap_total_kib: Option<i64>,
    /// KiB.
    pub swap_free_kib: Option<i64>,
    /// `oom_kill` from `/proc/vmstat`: processes the OOM killer ended since boot.
    pub oom_kills: Option<i64>,
    /// Why PSI was not observed, when it was not.
    pub psi_not_observed: Option<String>,
}

fn hundredths(s: &str) -> i64 {
    let (i, f) = s.split_once('.').unwrap_or((s, "0"));
    let i: i64 = i.parse().unwrap_or(0);
    let mut f: String = f.chars().take(2).collect();
    while f.len() < 2 {
        f.push('0');
    }
    i * 100 + f.parse::<i64>().unwrap_or(0)
}

/// Parses one `/proc/pressure/*` file.
#[must_use]
pub fn parse_psi(text: &str) -> BTreeMap<String, Psi> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(kind) = parts.next() else { continue };
        let mut p = Psi::default();
        for kv in parts {
            match kv.split_once('=') {
                Some(("avg10", v)) => p.avg10 = hundredths(v),
                Some(("avg60", v)) => p.avg60 = hundredths(v),
                Some(("avg300", v)) => p.avg300 = hundredths(v),
                Some(("total", v)) => p.total_us = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        out.insert(kind.to_owned(), p);
    }
    out
}

/// Reads it.
#[must_use]
pub fn read(root: &Root) -> Pressure {
    let mut p = Pressure::default();
    for res in ["cpu", "io", "memory"] {
        match root.text(&format!("/proc/pressure/{res}")) {
            Ok(t) => {
                for (k, v) in parse_psi(&t) {
                    p.psi.insert(format!("{res}/{k}"), v);
                }
            }
            Err(e) => {
                p.psi_not_observed = Some(format!("/proc/pressure/{res}: {}", e.as_str()));
            }
        }
    }
    if let Some(l) = root.read("/proc/loadavg") {
        let v: Vec<i64> = l.split_whitespace().take(3).map(hundredths).collect();
        if let [a, b, c] = v.as_slice() {
            p.load = Some([*a, *b, *c]);
        }
    }
    if let Some(m) = root.read("/proc/meminfo") {
        for line in m.lines() {
            let mut it = line.split_whitespace();
            let (Some(k), Some(v)) = (it.next(), it.next()) else {
                continue;
            };
            let v = v.parse().ok();
            match k {
                "MemTotal:" => p.mem_total_kib = v,
                "MemAvailable:" => p.mem_available_kib = v,
                "SwapTotal:" => p.swap_total_kib = v,
                "SwapFree:" => p.swap_free_kib = v,
                _ => {}
            }
        }
    }
    if let Some(v) = root.read("/proc/vmstat") {
        p.oom_kills = v
            .lines()
            .find_map(|l| l.strip_prefix("oom_kill "))
            .and_then(|n| n.trim().parse().ok());
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn psi_and_the_fixture() {
        let m = parse_psi(
            "some avg10=1.25 avg60=0.50 avg300=0.07 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        );
        assert_eq!(m["some"].avg10, 125);
        assert_eq!(m["some"].avg300, 7);
        assert_eq!(m["some"].total_us, 123);
        let p = read(&Root::at(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/host/trx40/root"),
        ));
        assert!(p.psi.contains_key("io/full"));
        assert!(p.psi_not_observed.is_none());
        assert!(p.load.is_some());
        assert!(p.mem_total_kib.unwrap() > 100_000_000, "a 128 GiB host");
    }
}
