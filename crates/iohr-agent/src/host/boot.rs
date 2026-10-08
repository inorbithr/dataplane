//! `host.boot`: this boot (id, start), earlier boots and whether each ended with a
//! recorded shutdown, and the watchdog's boot status.
//!
//! Sources, each reported for what it is:
//! - `/proc/sys/kernel/random/boot_id` and `/proc/uptime` (always readable);
//! - `/var/log/wtmp` reboot and shutdown records (readable by everyone on most
//!   distributions; some no longer write them);
//! - the systemd journal, only when the policy allows it (`[host] journal = true`): the
//!   agent then runs `journalctl --list-boots` and, for each earlier boot, reads its last
//!   entries for the shutdown markers (`systemd-shutdown`, "Journal stopped"). This is
//!   the only program the host observers run, with a fixed argument list, a cleared
//!   environment, a timeout and a size bound;
//! - `/sys/class/watchdog/*/bootstatus` (`0x20`, card reset, means the watchdog rebooted
//!   the machine).
//!
//! "No shutdown record" is what the evidence says. It is not proof of a crash: a journal
//! can lose its last writes on a clean power-off too. The verdict names the record, not
//! the cause.

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::sysfs::Root;

/// How long `journalctl` may run, per call.
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(10);
/// The most bytes read from one `journalctl` call.
const JOURNAL_MAX: usize = 1024 * 1024;
/// Earlier boots inspected for a shutdown record.
pub const BOOTS_INSPECTED: usize = 10;
/// The journal's "Journal stopped" message id (`SD_MESSAGE_JOURNAL_STOP`).
const JOURNAL_STOP: &str = "d93fb3c9c24d451a97cea615ce59c00b";

/// How a boot ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ending {
    /// The running boot.
    Running,
    /// Its last entries include a shutdown record.
    ShutdownRecorded,
    /// Its last entries hold no shutdown record (a hang, a reset, a power cut, or a lost
    /// tail of the journal).
    NoShutdownRecord,
    /// Not determined.
    Unknown,
}

impl Ending {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::ShutdownRecorded => "shutdown_recorded",
            Self::NoShutdownRecord => "no_shutdown_record",
            Self::Unknown => "unknown",
        }
    }
}

/// One boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Boot {
    /// The kernel's boot id (32 hex digits).
    pub boot_id: String,
    /// First entry, Unix seconds.
    pub first: Option<i64>,
    /// Last entry, Unix seconds.
    pub last: Option<i64>,
    /// How it ended.
    pub ending: Ending,
}

/// A wtmp record of interest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WtmpEvent {
    /// `true` for a boot ("reboot"), `false` for a shutdown.
    pub boot: bool,
    /// Unix seconds.
    pub at: i64,
}

/// One watchdog device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Watchdog {
    /// `watchdog0`.
    pub name: String,
    /// The driver's identity (`SP5100 TCO timer`).
    pub identity: Option<String>,
    /// `bootstatus` (0 normal; 0x20 the watchdog reset the machine).
    pub bootstatus: Option<i64>,
    /// `active` / `inactive`.
    pub state: Option<String>,
    /// Seconds.
    pub timeout: Option<i64>,
}

/// What was found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BootHistory {
    /// This boot's id.
    pub boot_id: Option<String>,
    /// Seconds since boot.
    pub uptime_secs: Option<i64>,
    /// Earlier boots, newest first, then the running one first of all (from the journal).
    pub boots: Vec<Boot>,
    /// Why the journal was not read, when it was not.
    pub journal_not_observed: Option<String>,
    /// wtmp boot and shutdown records, oldest first.
    pub wtmp: Vec<WtmpEvent>,
    /// Why wtmp was not read, when it was not.
    pub wtmp_not_observed: Option<String>,
    /// Watchdogs.
    pub watchdogs: Vec<Watchdog>,
}

impl BootHistory {
    /// Earlier boots without a shutdown record.
    #[must_use]
    pub fn unclean(&self) -> Vec<&Boot> {
        self.boots
            .iter()
            .filter(|b| b.ending == Ending::NoShutdownRecord)
            .collect()
    }
}

/// Parses wtmp: `struct utmp` records of 384 bytes (`x86_64` and `aarch64` glibc). Only the
/// type, the user field's `reboot`/`shutdown` and the time are read; terminal, host and
/// address fields are never looked at.
#[must_use]
pub fn parse_wtmp(bytes: &[u8]) -> Vec<WtmpEvent> {
    const SIZE: usize = 384;
    let mut out = Vec::new();
    for rec in bytes.as_chunks::<SIZE>().0 {
        let kind = i16::from_le_bytes([rec[0], rec[1]]);
        let user = &rec[44..76];
        let user = &user[..user.iter().position(|b| *b == 0).unwrap_or(user.len())];
        let at = i64::from(i32::from_le_bytes([rec[340], rec[341], rec[342], rec[343]]));
        match (kind, user) {
            (2, b"reboot") => out.push(WtmpEvent { boot: true, at }),
            (1, b"shutdown") => out.push(WtmpEvent { boot: false, at }),
            _ => {}
        }
    }
    out
}

/// Runs a program with fixed arguments, an empty environment, a timeout and an output
/// bound. `None` if it is missing, fails, or runs too long.
fn run_bounded(program: &str, args: &[&str]) -> Result<String, String> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(JOURNAL_MAX as u64).read_to_end(&mut buf);
        buf
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = reader.join().unwrap_or_default();
                if !status.success() {
                    return Err(format!("{program} exited with {status}"));
                }
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            Ok(None) if started.elapsed() > JOURNAL_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program} ran longer than {JOURNAL_TIMEOUT:?}"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("{program}: {e}")),
        }
    }
}

#[derive(Deserialize)]
struct ListedBoot {
    boot_id: String,
    #[serde(default)]
    first_entry: Option<i64>,
    #[serde(default)]
    last_entry: Option<i64>,
}

/// Whether a boot's last journal entries (JSON lines) hold a shutdown record.
#[must_use]
pub fn has_shutdown_record(json_lines: &str) -> bool {
    json_lines.lines().any(|l| {
        serde_json::from_str::<serde_json::Value>(l).is_ok_and(|v| {
            v.get("SYSLOG_IDENTIFIER").and_then(|s| s.as_str()) == Some("systemd-shutdown")
                || v.get("MESSAGE_ID").and_then(|s| s.as_str()) == Some(JOURNAL_STOP)
        })
    })
}

fn journalctl() -> Option<&'static str> {
    ["/usr/bin/journalctl", "/bin/journalctl"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
}

fn read_journal(current: Option<&str>) -> Result<Vec<Boot>, String> {
    let program = journalctl().ok_or("journalctl is not installed")?;
    let listed = run_bounded(program, &["--list-boots", "-o", "json", "-q", "--no-pager"])?;
    let listed: Vec<ListedBoot> = serde_json::from_str(listed.trim())
        .map_err(|e| format!("journalctl --list-boots: not JSON: {e}"))?;
    let mut boots = Vec::new();
    for b in listed.iter().rev().take(BOOTS_INSPECTED + 1) {
        if !(b.boot_id.len() == 32 && b.boot_id.bytes().all(|c| c.is_ascii_hexdigit())) {
            continue;
        }
        let running = current.is_some_and(|c| c.replace('-', "") == b.boot_id);
        let ending = if running {
            Ending::Running
        } else {
            match run_bounded(
                program,
                &[
                    "-b",
                    &b.boot_id,
                    "-n",
                    "60",
                    "-q",
                    "--no-pager",
                    "-o",
                    "json",
                    "--output-fields=MESSAGE_ID,SYSLOG_IDENTIFIER",
                ],
            ) {
                Ok(t) if has_shutdown_record(&t) => Ending::ShutdownRecorded,
                Ok(_) => Ending::NoShutdownRecord,
                Err(_) => Ending::Unknown,
            }
        };
        boots.push(Boot {
            boot_id: b.boot_id.clone(),
            first: b.first_entry.map(|us| us / 1_000_000),
            last: b.last_entry.map(|us| us / 1_000_000),
            ending,
        });
    }
    Ok(boots)
}

/// Reads it. `journal` is the policy's permission to run `journalctl`.
#[must_use]
pub fn read(root: &Root, journal: bool) -> BootHistory {
    let mut h = BootHistory {
        boot_id: root.read("/proc/sys/kernel/random/boot_id"),
        uptime_secs: root
            .read("/proc/uptime")
            .and_then(|u| u.split_whitespace().next()?.split('.').next()?.parse().ok()),
        ..BootHistory::default()
    };
    match root.bytes("/var/log/wtmp") {
        Ok(b) => h.wtmp = parse_wtmp(&b),
        Err(e) => h.wtmp_not_observed = Some(format!("/var/log/wtmp: {}", e.as_str())),
    }
    for w in root.list("/sys/class/watchdog") {
        let base = format!("/sys/class/watchdog/{w}");
        h.watchdogs.push(Watchdog {
            identity: root.read(&format!("{base}/identity")),
            bootstatus: root.int(&format!("{base}/bootstatus")),
            state: root.read(&format!("{base}/state")),
            timeout: root.int(&format!("{base}/timeout")),
            name: w,
        });
    }
    if !journal {
        h.journal_not_observed =
            Some("the policy does not allow reading the journal ([host] journal)".into());
    } else if !root.is_host() {
        h.journal_not_observed = Some("the journal is read only on the running host".into());
    } else {
        match read_journal(h.boot_id.as_deref()) {
            Ok(b) => h.boots = b,
            Err(e) => h.journal_not_observed = Some(e),
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(kind: i16, user: &str, at: i32) -> Vec<u8> {
        let mut r = vec![0u8; 384];
        r[0..2].copy_from_slice(&kind.to_le_bytes());
        r[44..44 + user.len()].copy_from_slice(user.as_bytes());
        r[340..344].copy_from_slice(&at.to_le_bytes());
        r
    }

    #[test]
    fn wtmp_boots_and_shutdowns_only() {
        let mut b = rec(2, "reboot", 100);
        b.extend(rec(7, "nevio", 150)); // a login: never read
        b.extend(rec(1, "shutdown", 200));
        b.extend(rec(2, "reboot", 300));
        b.extend(rec(2, "reboot", 400)); // no shutdown before it
        let e = parse_wtmp(&b);
        assert_eq!(e.len(), 4);
        assert!(e[0].boot && !e[1].boot);
        assert_eq!(e[3].at, 400);
    }

    #[test]
    fn shutdown_markers() {
        assert!(has_shutdown_record(
            "{\"SYSLOG_IDENTIFIER\":\"systemd-shutdown\"}\n"
        ));
        assert!(has_shutdown_record(&format!(
            "{{\"MESSAGE_ID\":\"{JOURNAL_STOP}\"}}"
        )));
        assert!(!has_shutdown_record(
            "{\"SYSLOG_IDENTIFIER\":\"iohr\"}\n{\"SYSLOG_IDENTIFIER\":\"kernel\"}"
        ));
    }

    #[test]
    fn the_journal_is_never_read_without_the_policy_or_off_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let h = read(&Root::at(dir.path()), false);
        assert!(h.journal_not_observed.unwrap().contains("policy"));
        let h = read(&Root::at(dir.path()), true);
        assert!(h.journal_not_observed.unwrap().contains("running host"));
        assert!(h.wtmp_not_observed.is_some());
    }
}
