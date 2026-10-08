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
use crate::policy::TargetShare;

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
}
