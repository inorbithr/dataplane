//! What the hello tells the platform about this agent's checks and host (`[share]` in the
//! policy; RFC 0100 D11 and D13 in inorbithr/core). By default a declared check leaves as
//! its key, a label and a keyed hash of its target: the platform can schedule it, show it
//! and tell when its target changes, but never learns the URL, host or address. The host
//! name stays here unless the policy says otherwise.
//!
//! The hash is HMAC-SHA256 under a key that never leaves this machine
//! (`<state_dir>/share.key`, 0600), so the platform cannot test guesses ("is it
//! `db.internal:5432`?") against it.

use std::fmt::Write as _;
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::checks_file::{DeclaredCheck, RefuseBy, canonical_json};
use crate::error::{Error, Result};
use crate::policy::{SharePolicy, TargetShare};

/// The key file in the state directory.
pub const KEY_FILE: &str = "share.key";

/// The key target hashes are made with: read from `<state_dir>/share.key`, made on first
/// use (32 random bytes, 0600). Kept across restarts so a target's hash stays the same.
///
/// # Errors
/// When the file cannot be read or written.
pub fn key(state_dir: &Path) -> Result<Vec<u8>> {
    let path = state_dir.join(KEY_FILE);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let bytes = unhex(text.trim());
        if bytes.len() == 32 {
            return Ok(bytes);
        }
        return Err(Error::Config(format!(
            "{} is not a share key (64 hex characters)",
            path.display()
        )));
    }
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| Error::Config(format!("random: {e}")))?;
    std::fs::create_dir_all(state_dir).map_err(|e| Error::io(state_dir, e))?;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(&path).map_err(|e| Error::io(&path, e))?;
    std::io::Write::write_all(&mut f, hex(&raw).as_bytes()).map_err(|e| Error::io(&path, e))?;
    Ok(raw.to_vec())
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn unhex(s: &str) -> Vec<u8> {
    if !s.len().is_multiple_of(2) {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map_while(|i| s.get(i..i + 2).and_then(|p| u8::from_str_radix(p, 16).ok()))
        .collect()
}

/// HMAC-SHA256 (RFC 2104).
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// `hmac-sha256:<hex>` of a check's target (its canonical wire form) under `key`.
#[must_use]
pub fn target_hash(c: &DeclaredCheck, key: &[u8]) -> String {
    let target = c.to_wire().get("target").cloned().unwrap_or(Value::Null);
    format!(
        "hmac-sha256:{}",
        hex(&hmac_sha256(key, canonical_json(&target).as_bytes()))
    )
}

/// The label a check is shown by when its target is not shared.
#[must_use]
pub fn label(c: &DeclaredCheck) -> &str {
    c.label.as_deref().unwrap_or(&c.key)
}

/// How a check's target actually leaves: a refusal the platform must make needs the
/// target, whatever the level.
#[must_use]
pub fn level_for(c: &DeclaredCheck, level: TargetShare) -> TargetShare {
    if c.refuse_by == Some(RefuseBy::Platform) {
        TargetShare::Full
    } else {
        level
    }
}

/// One declared check as the hello carries it under `level`: `target` only when `full`;
/// otherwise `label`, and with `hash` also `target_hash`. `target_shared` names the level.
/// Below `full` the secret reference a check's header is read from (`auth`) stays here
/// too; `uses_secret: true` says there is one.
#[must_use]
pub fn wire(c: &DeclaredCheck, level: TargetShare, key: &[u8]) -> Value {
    let mut w = c.to_wire();
    let level = level_for(c, level);
    if let Some(o) = w.as_object_mut() {
        o.insert("target_shared".into(), json!(level.as_str()));
        o.insert("label".into(), json!(label(c)));
        match level {
            TargetShare::Full => {}
            TargetShare::Hash | TargetShare::Label if o.remove("auth").is_some() => {
                o.insert("uses_secret".into(), json!(true));
                if level == TargetShare::Hash {
                    o.insert("target_hash".into(), json!(target_hash(c, key)));
                }
                o.remove("target");
            }
            TargetShare::Hash => {
                o.remove("target");
                o.insert("target_hash".into(), json!(target_hash(c, key)));
            }
            TargetShare::Label => {
                o.remove("target");
            }
        }
    }
    w
}

/// Every host, address and URL of a check's target, to scrub from what leaves.
#[must_use]
pub fn target_strings(c: &DeclaredCheck) -> Vec<String> {
    let mut out = Vec::new();
    match &c.spec.target {
        crate::checks::Target::Url { url } => {
            out.push(url.to_string());
            if let Some(h) = url.host_str() {
                out.push(h.to_owned());
            }
        }
        crate::checks::Target::HostPort { host, port, .. } => {
            out.push(format!("{host}:{port}"));
            out.push(host.clone());
        }
        crate::checks::Target::Sensor { sensor } => out.push(sensor.clone()),
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.len()));
    out
}

/// A refusal reason with the target taken out: its host, URL and any address in it
/// become `the target of "<label>"`. The full reason stays on the local page.
#[must_use]
pub fn scrub(reason: &str, c: &DeclaredCheck) -> String {
    let with = format!("the target of {:?}", label(c));
    let mut s = reason.to_owned();
    for t in target_strings(c) {
        if !t.is_empty() {
            s = s.replace(&t, &with);
        }
    }
    // Addresses the name resolved to.
    s.split(|ch: char| ch.is_whitespace() || ch == ',')
        .map(|w| {
            let bare =
                w.trim_matches(|ch: char| matches!(ch, '(' | ')' | ';' | ':' | '.' | '[' | ']'));
            if !bare.is_empty() && bare.parse::<std::net::IpAddr>().is_ok() {
                w.replace(bare, "an address it resolved to")
            } else {
                w.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The `[share]` block written when a policy has none.
const BLOCK_COMMENT: &str =
    "# What the hello tells the platform about your declared checks: \"hash\" (a label and a
# keyed hash; the URL, host or address stays here), \"label\" (the label only) or \"full\"
# (the target itself). Every message that leaves is in the agent's ledger either way.
# Set from the agent's local page or `iohr agent share`.
";

/// A table header (`[x]`, `[[x]]`): where a section ends.
fn is_header(line: &str) -> bool {
    line.trim_start().starts_with('[')
}

fn key_of(line: &str) -> Option<&str> {
    let t = line.trim_start();
    if t.starts_with('#') {
        return None;
    }
    t.split_once('=').map(|(k, _)| k.trim().trim_matches('"'))
}

fn value_line(key: &str, share: &SharePolicy) -> String {
    match key {
        "targets" => format!("targets = \"{}\"", share.targets.as_str()),
        _ => format!("hostname = {}", share.hostname),
    }
}

/// `text` (a policy file) with its `[share]` set to `share`: only the two keys change,
/// in place; comments, order and every other line stay as they are. A file without the
/// section gets one at the end, with a comment saying what it does.
///
/// # Errors
/// When the result would not be a valid policy, or would not say `share` (the section is
/// written in a form this edit does not touch, such as inline tables).
pub fn edit_policy_text(text: &str, share: &SharePolicy) -> Result<String> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let start = lines
        .iter()
        .position(|l| l.trim_start().starts_with("[share]"));
    let out = match start {
        None => {
            let mut out = text.to_owned();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            if !out.is_empty() && !out.ends_with("\n\n") {
                out.push('\n');
            }
            out.push_str("[share]\n");
            out.push_str(BLOCK_COMMENT);
            out.push_str(&value_line("targets", share));
            out.push('\n');
            out.push_str(&value_line("hostname", share));
            out.push('\n');
            out
        }
        Some(start) => {
            let end = lines
                .iter()
                .enumerate()
                .skip(start + 1)
                .find(|(_, l)| is_header(l))
                .map_or(lines.len(), |(i, _)| i);
            let mut seen = (false, false);
            let mut body: Vec<String> = Vec::new();
            for l in lines.get(start + 1..end).unwrap_or_default() {
                match key_of(l) {
                    Some(k @ ("targets" | "hostname")) => {
                        let eol = if l.ends_with('\n') { "\n" } else { "" };
                        // A comment after the value is kept.
                        let comment = l
                            .split_once('#')
                            .filter(|(v, _)| v.matches('"').count() % 2 == 0)
                            .map(|(_, c)| format!(" #{}", c.trim_end_matches('\n')))
                            .unwrap_or_default();
                        let indent: String = l.chars().take_while(|c| c.is_whitespace()).collect();
                        body.push(format!("{indent}{}{comment}{eol}", value_line(k, share)));
                        if k == "targets" {
                            seen.0 = true;
                        } else {
                            seen.1 = true;
                        }
                    }
                    _ => body.push((*l).to_owned()),
                }
            }
            // Missing keys go after the last non-blank line of the section.
            let at = body
                .iter()
                .rposition(|l| !l.trim().is_empty())
                .map_or(0, |i| i + 1);
            let mut add = Vec::new();
            if !seen.0 {
                add.push(format!("{}\n", value_line("targets", share)));
            }
            if !seen.1 {
                add.push(format!("{}\n", value_line("hostname", share)));
            }
            if at > 0
                && !body.get(at - 1).is_some_and(|l| l.ends_with('\n'))
                && let Some(l) = body.get_mut(at - 1)
            {
                l.push('\n');
            }
            for (n, a) in add.into_iter().enumerate() {
                body.insert(at + n, a);
            }
            let mut out: String = lines.get(..=start).unwrap_or_default().concat();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&body.concat());
            out.push_str(&lines.get(end..).unwrap_or_default().concat());
            out
        }
    };
    let p = crate::policy::Policy::from_toml(&out)?;
    if p.share() != *share {
        return Err(Error::Policy(
            "[share] is written in a form this edit cannot change (an inline table?); edit policy.toml by hand".into(),
        ));
    }
    Ok(out)
}

/// Sets `[share]` in the policy file at `path`, atomically (a temporary file in the same
/// directory, with the same permissions, renamed over it). Unchanged when already so.
///
/// # Errors
/// When the file cannot be read or written (a policy owned by root needs
/// `sudo iohr agent share …`), or the result is not a valid policy.
pub fn write_policy(path: &Path, share: &SharePolicy) -> Result<bool> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let out = edit_policy_text(&text, share)?;
    if out == text {
        return Ok(false);
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.share-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("policy.toml"),
        std::process::id()
    ));
    let perms = std::fs::metadata(path)
        .map_err(|e| Error::io(path, e))?
        .permissions();
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        std::io::Write::write_all(&mut f, out.as_bytes())?;
        f.sync_all()?;
        std::fs::set_permissions(&tmp, perms.clone())?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::io(path, e)
    })?;
    Ok(true)
}

/// What the next hello would carry under `share`: each declared check as it would leave,
/// and the host name when it would.
#[must_use]
pub fn preview(
    checks: Option<&crate::checks_file::DeclaredChecks>,
    share: &SharePolicy,
    key: &[u8],
) -> Value {
    let checks: Vec<Value> = checks
        .map(|c| {
            c.entries
                .iter()
                .map(|e| wire(e, share.targets, key))
                .collect()
        })
        .unwrap_or_default();
    let mut v = json!({ "checks": checks });
    if share.hostname {
        v["hostname"] = json!(crate::host::sysfs::host_name());
    }
    v
}

/// What the agent last ran with, kept to tell when `[share]` changed.
pub const LAST_FILE: &str = "share.last";

/// Records a change of `[share]` in the egress ledger: the agent compares what it starts
/// with to what it last ran with (`<state_dir>/share.last`), so a change from the page,
/// from `iohr agent share` or by hand is on the record. Local: nothing is sent.
///
/// # Errors
/// When the ledger cannot record it.
pub fn note_change(
    state_dir: &Path,
    share: &SharePolicy,
    ledger: Option<&crate::ledger::Ledger>,
) -> Result<bool> {
    let now = canonical_json(&json!(share));
    let path = state_dir.join(LAST_FILE);
    let before = std::fs::read_to_string(&path).ok();
    if before.as_deref() == Some(now.as_str()) {
        return Ok(false);
    }
    if let Some(l) = ledger {
        let payload = canonical_json(&json!({
            "from": before.as_deref().and_then(|b| serde_json::from_str::<Value>(b).ok()),
            "to": json!(share),
        }));
        l.record(crate::ledger::Record {
            kind: "share_set",
            payload: payload.as_bytes(),
            rule: "operator.policy.share",
            destination: "local: policy.toml [share] (nothing sent)",
            job_id: None,
        })?;
    }
    std::fs::write(&path, &now).map_err(|e| Error::io(&path, e))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks_file::DeclaredChecks;

    const CHECKS: &str = r#"
[[check]]
name = "db"
label = "orders database"
surface = "tcp"
target = "db.internal.example:5432"
every = "60s"

[[check]]
name = "api"
target = "https://api.internal.example/healthz?x=1"
every = "60s"
auth = "vault:kv/prod/api#token"

[[refuse]]
name = "outside"
surface = "http"
target = "https://elsewhere.example/"
by = "platform"
every = "5m"
"#;

    #[test]
    fn hmac_matches_rfc_4231() {
        // RFC 4231 test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn each_level_sends_only_what_it_says() {
        let checks = DeclaredChecks::from_toml(CHECKS).unwrap();
        let key = [7u8; 32];
        for level in [TargetShare::Label, TargetShare::Hash, TargetShare::Full] {
            let w: Vec<Value> = checks
                .entries
                .iter()
                .map(|c| wire(c, level, &key))
                .collect();
            let text = serde_json::to_string(&w).unwrap();
            let shows = |s: &str| text.contains(s);
            assert_eq!(
                shows("db.internal.example"),
                level == TargetShare::Full,
                "{level:?}: {text}"
            );
            assert_eq!(
                shows("api.internal.example"),
                level == TargetShare::Full,
                "{level:?}"
            );
            assert_eq!(
                shows("hmac-sha256:"),
                level == TargetShare::Hash,
                "{level:?}"
            );
            assert!(shows("\"label\":\"orders database\"") && shows("\"label\":\"api\""));
            assert_eq!(
                shows("vault:kv/prod"),
                level == TargetShare::Full,
                "{level:?}"
            );
            assert_eq!(
                shows("\"uses_secret\":true"),
                level != TargetShare::Full,
                "{level:?}"
            );
            // A refusal the platform must make keeps its target at every level.
            assert!(shows("elsewhere.example"), "{level:?}");
            assert_eq!(w[0]["target_shared"], level.as_str());
            assert_eq!(w[2]["target_shared"], "full");
        }
    }

    #[test]
    fn the_hash_is_keyed_and_stable() {
        let checks = DeclaredChecks::from_toml(CHECKS).unwrap();
        let db = &checks.entries[0];
        assert_eq!(target_hash(db, &[1; 32]), target_hash(db, &[1; 32]));
        assert_ne!(target_hash(db, &[1; 32]), target_hash(db, &[2; 32]));
        // Not the plain SHA-256 a platform could compute from a guess.
        let plain = crate::ledger::sha256_hex(canonical_json(&db.to_wire()["target"]).as_bytes());
        assert!(!target_hash(db, &[1; 32]).ends_with(plain.trim_start_matches("sha256:")));
    }

    #[test]
    fn the_key_is_made_once_and_kept_private() {
        let d = tempfile::tempdir().unwrap();
        let a = key(d.path()).unwrap();
        assert_eq!(a, key(d.path()).unwrap());
        assert_eq!(a.len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(d.path().join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn refusal_reasons_lose_the_target() {
        let checks = DeclaredChecks::from_toml(CHECKS).unwrap();
        let db = &checks.entries[0];
        let r = scrub(
            "db.internal.example is neither named in networks.allow nor inside a bound domain",
            db,
        );
        assert!(!r.contains("db.internal"), "{r}");
        assert!(r.contains("the target of \"orders database\""), "{r}");
        let r = scrub("10.1.2.3 is in networks.deny", db);
        assert!(!r.contains("10.1.2.3"), "{r}");
        let r = scrub("fd00::1 is not in networks.allow", db);
        assert!(!r.contains("fd00::1"), "{r}");
    }

    const POLICY: &str = "# The policy.\nenvironment = \"staging\"\n\n[networks]\n# who we reach\nallow = [\"10.0.0.0/8\"]\n";

    #[test]
    fn a_policy_without_share_gets_one_and_keeps_everything_else() {
        let want = SharePolicy {
            targets: TargetShare::Full,
            hostname: true,
            host: false,
        };
        let out = edit_policy_text(POLICY, &want).unwrap();
        assert!(out.starts_with(POLICY), "{out}");
        assert!(
            out.contains("[share]\n# What the hello tells")
                && out.ends_with("targets = \"full\"\nhostname = true\n"),
            "{out}"
        );
        assert_eq!(
            crate::policy::Policy::from_toml(&out).unwrap().share(),
            want
        );
        // Applying the same again changes nothing.
        assert_eq!(edit_policy_text(&out, &want).unwrap(), out);
    }

    #[test]
    fn an_existing_share_changes_in_place_with_its_comments() {
        let text = format!(
            "{POLICY}\n[share]\n# mine\ntargets = \"hash\" # chosen at setup\n  hostname = false\n\n[ceilings]\nmax_job_ms = 5000\n"
        );
        let want = SharePolicy {
            targets: TargetShare::Label,
            hostname: true,
            host: false,
        };
        let out = edit_policy_text(&text, &want).unwrap();
        assert_eq!(
            out,
            format!(
                "{POLICY}\n[share]\n# mine\ntargets = \"label\" # chosen at setup\n  hostname = true\n\n[ceilings]\nmax_job_ms = 5000\n"
            )
        );
        // A section with one key gets the other after it.
        let text = format!("{POLICY}[share]\ntargets = \"hash\"\n[ceilings]\nmax_job_ms = 5000\n");
        let out = edit_policy_text(&text, &want).unwrap();
        assert!(
            out.contains("[share]\ntargets = \"label\"\nhostname = true\n[ceilings]"),
            "{out}"
        );
        assert_eq!(
            crate::policy::Policy::from_toml(&out)
                .unwrap()
                .ceilings
                .max_job_ms,
            5000
        );
    }

    #[test]
    fn the_file_is_written_atomically_with_its_permissions() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("policy.toml");
        std::fs::write(&path, POLICY).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let want = SharePolicy {
            targets: TargetShare::Full,
            hostname: false,
            host: false,
        };
        assert!(write_policy(&path, &want).unwrap());
        assert!(!write_policy(&path, &want).unwrap(), "already so");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            1,
            "no temporary file left"
        );
        // A broken file is refused, not overwritten.
        std::fs::write(&path, "environment = 1\n").unwrap();
        assert!(write_policy(&path, &want).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "environment = 1\n");
    }

    #[test]
    fn a_change_is_noted_once_in_the_ledger() {
        let d = tempfile::tempdir().unwrap();
        let l = crate::ledger::Ledger::open(
            &d.path().join("ledger"),
            crate::ledger::LedgerConfig::default(),
            "sha256:00",
        )
        .unwrap();
        let a = SharePolicy::default();
        assert!(
            note_change(d.path(), &a, Some(&l)).unwrap(),
            "the first run is on the record"
        );
        assert!(!note_change(d.path(), &a, Some(&l)).unwrap());
        let b = SharePolicy {
            targets: TargetShare::Full,
            hostname: true,
            host: false,
        };
        assert!(note_change(d.path(), &b, Some(&l)).unwrap());
        let kinds: Vec<String> = l.recent(10).into_iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["share_set", "share_set"]);
        assert!(crate::ledger::verify(&d.path().join("ledger")).ok());
    }
}
