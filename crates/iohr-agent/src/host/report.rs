//! A short human report of one host reading (`atlas observe host --report`): what a
//! person checking a hot machine looks at first. The evidence records carry the same
//! facts; this is a view, never a source.

#![allow(clippy::cast_precision_loss)] // display and statistics only

use std::fmt::Write as _;

use super::Snapshot;
use super::derive::{Finding, chipset_sensor};
use super::hwmon::Kind;
use super::sampler::Sampler;

fn temp(v: i64) -> String {
    format!("{:.1} °C", v as f64 / 1000.0)
}

fn speed(mts: Option<u32>) -> String {
    mts.map_or_else(
        || "?".into(),
        |s| format!("{:.1} GT/s", f64::from(s) / 1000.0),
    )
}

/// The report.
#[must_use]
#[allow(clippy::too_many_lines)] // one section after another
pub fn text(snap: &Snapshot, findings: &[Finding], window: Option<&Sampler>) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "host {} (kernel {}), read in {} ms{}",
        snap.host,
        snap.kernel.as_deref().unwrap_or("?"),
        snap.read_us / 1000,
        window.map_or_else(String::new, |w| format!(
            ", {} samples (each read in {} µs at most)",
            w.samples().len(),
            w.max_cost.as_micros()
        ))
    );

    let _ = writeln!(o, "\nsensors");
    if let Some((chip, s)) = chipset_sensor(&snap.hwmon) {
        let key = chip.key(s);
        let rate = window
            .and_then(|w| w.rate_per_min(&key, super::check::RATE_OVER))
            .map_or_else(String::new, |r| {
                format!(", {:+.1} °C/min", r as f64 / 1000.0)
            });
        let peak = window
            .and_then(|w| w.extreme_since(&key, 0, false))
            .map_or_else(String::new, |p| format!(", window max {}", temp(p)));
        let _ = writeln!(
            o,
            "  {key}: {}{peak}{rate}",
            s.input.map_or_else(|| "no reading".into(), temp)
        );
        if let Some(fan) = chip
            .sensors
            .iter()
            .find(|f| f.kind == Kind::Fan && f.label.eq_ignore_ascii_case("chipset"))
        {
            let _ = writeln!(
                o,
                "  {}: {} RPM",
                chip.key(fan),
                fan.input.unwrap_or_default()
            );
        }
    }
    let mut hottest: Vec<(String, i64, Option<i64>)> = snap
        .hwmon
        .iter()
        .flat_map(|c| {
            c.sensors
                .iter()
                .filter(|s| {
                    s.kind == Kind::Temp && s.plausible && !s.label.eq_ignore_ascii_case("chipset")
                })
                .filter_map(move |s| Some((c.key(s), s.input?, s.thresholds.get("max").copied())))
        })
        .collect();
    hottest.sort_by_key(|(_, v, _)| -v);
    for (k, v, max) in hottest.iter().take(8) {
        let _ = writeln!(
            o,
            "  {k}: {}{}",
            temp(*v),
            max.map_or_else(String::new, |m| format!(" (max {})", temp(m)))
        );
    }

    let t = &snap.pcie;
    let _ = writeln!(
        o,
        "\npcie (ASPM policy {}; per-link ASPM {})",
        t.aspm_policy.as_deref().unwrap_or("?"),
        if t.config_readable {
            "from config space"
        } else {
            "not observed: needs CAP_SYS_ADMIN"
        }
    );
    for up in t.chipset_uplinks() {
        let l = up.link.as_ref();
        let _ = writeln!(
            o,
            "  chipset uplink {} ({}) under {}: {} x{} (max {} x{}), ASPM {}",
            up.addr,
            up.chipset_uplink.as_deref().unwrap_or(""),
            up.parent.as_deref().unwrap_or("?"),
            speed(l.and_then(|l| l.speed_mts)),
            l.and_then(|l| l.width).unwrap_or(0),
            speed(l.and_then(|l| l.capable_speed_mts)),
            l.and_then(|l| l.capable_width).unwrap_or(0),
            up.aspm.enabled.as_deref().unwrap_or("not observed")
        );
        for d in t.behind(&up.addr) {
            if d.is_bridge() {
                continue;
            }
            let nvme = snap
                .storage
                .controllers
                .iter()
                .find(|c| c.pci.as_deref() == Some(d.addr.as_str()))
                .map(|c| format!(" = {}", c.name))
                .unwrap_or_default();
            let net: Vec<String> = d
                .net
                .iter()
                .map(|(n, s)| {
                    format!(
                        " = {n} at {}",
                        s.map_or_else(|| "link down".into(), |s| format!("{s} Mb/s"))
                    )
                })
                .collect();
            let link = d.link.as_ref().map_or_else(String::new, |l| {
                let mut x = format!(" [{} x{}", speed(l.speed_mts), l.width.unwrap_or(0));
                if l.downgraded {
                    x.push_str(", downgraded");
                }
                if l.limited_by_port {
                    let _ = write!(x, ", device x{} limited by port", l.max_width.unwrap_or(0));
                }
                x.push(']');
                x
            });
            let _ = writeln!(o, "    {} {}{nvme}{}{link}", d.addr, d.name(), net.join(""));
        }
    }
    let down: Vec<String> = t
        .devices
        .values()
        .filter(|d| d.link.as_ref().is_some_and(|l| l.downgraded))
        .map(|d| d.addr.clone())
        .collect();
    if !down.is_empty() {
        let _ = writeln!(o, "  links trained below both ends: {}", down.join(", "));
    }

    let _ = writeln!(o, "\nstorage");
    for m in &snap.storage.mounts {
        let roles: Vec<&str> = m.roles.iter().map(|r| r.as_str()).collect();
        let behind: Vec<String> = m
            .pci
            .iter()
            .map(|p| match t.uplink_of(p) {
                Some(u) => format!("{p} behind {}", u.addr),
                None => format!("{p} CPU lanes"),
            })
            .collect();
        let _ = writeln!(
            o,
            "  {} [{}] {} on {} ({})",
            m.mountpoint,
            roles.join("+"),
            m.device,
            m.disks.join("+"),
            behind.join(", ")
        );
    }
    for d in &snap.storage.disks {
        if let Some(md) = &d.md {
            let _ = writeln!(
                o,
                "  {} {} members {} {}",
                d.name,
                md.level.as_deref().unwrap_or("?"),
                md.members.join(","),
                md.mdstat.as_deref().unwrap_or("")
            );
        }
    }
    if let Some(why) = &snap.storage.smart_not_observed {
        let _ = writeln!(o, "  SMART not observed: {why}");
    }

    let p = &snap.pressure;
    let psi = |k: &str| {
        p.psi
            .get(k)
            .map_or_else(|| "?".into(), |x| format!("{:.2}%", x.avg10 as f64 / 100.0))
    };
    let _ = writeln!(
        o,
        "\npressure: psi avg10 cpu {} io {} (full {}) memory {}; load {}; available {} GiB; OOM kills {}",
        psi("cpu/some"),
        psi("io/some"),
        psi("io/full"),
        psi("memory/some"),
        p.load
            .map_or_else(|| "?".into(), |l| format!("{:.2}", l[0] as f64 / 100.0)),
        p.mem_available_kib
            .map_or_else(|| "?".into(), |m| format!("{:.1}", m as f64 / 1_048_576.0)),
        p.oom_kills.map_or_else(|| "?".into(), |n| n.to_string()),
    );

    let b = &snap.boot;
    let _ = writeln!(
        o,
        "\nboots: this one up {} min; {} earlier boot(s) read, {} without a shutdown record{}",
        b.uptime_secs.unwrap_or(0) / 60,
        b.boots.len().saturating_sub(1),
        b.unclean().len(),
        b.journal_not_observed
            .as_ref()
            .map_or_else(String::new, |w| format!(" (journal not observed: {w})"))
    );
    for x in b.unclean() {
        let when = x
            .last
            .and_then(|l| chrono::DateTime::from_timestamp(l, 0))
            .map_or_else(|| "?".into(), |t| t.to_rfc3339());
        let _ = writeln!(o, "  {} last entry {when}", x.boot_id);
    }
    for w in &b.watchdogs {
        let _ = writeln!(
            o,
            "  watchdog {} ({}): bootstatus {}",
            w.name,
            w.identity.as_deref().unwrap_or("?"),
            w.bootstatus
                .map_or_else(|| "?".into(), |s| format!("{s:#x}"))
        );
    }

    let _ = writeln!(o, "\nfindings");
    for f in findings {
        let _ = writeln!(o, "  [{}] {}: {}", f.verdict.as_str(), f.check, f.reason);
    }
    o
}
