//! Setting up this machine: the Claude Code entry that points at the door and the launchd
//! job that keeps the door running. Neither holds a secret: the entry runs `mcp headers`,
//! which reads the local secret from the keychain each time.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Value, json};

use super::{LaunchdArgs, RegisterArgs, out, write_state};
use crate::error::{Error, Result};

/// The launchd label; the same as the Python bridge's, so one job replaces the other.
pub(super) const LABEL: &str = "hr.inorbit.mcp-bridge";

fn program(p: Option<&PathBuf>) -> Result<PathBuf> {
    match p {
        Some(p) => Ok(p.clone()),
        None => std::env::current_exe().map_err(|e| Error::Config(format!("this program: {e}"))),
    }
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Adds or updates the `inorbit` server in `doc`; true when it changed.
pub(crate) fn set_entry(doc: &mut Value, url: &str, helper: &str) -> bool {
    let want = json!({"type": "http", "url": url, "headersHelper": helper});
    if !doc.is_object() {
        *doc = json!({});
    }
    let servers = doc
        .as_object_mut()
        .map(|o| o.entry("mcpServers").or_insert_with(|| json!({})));
    let Some(servers) = servers.filter(|s| s.is_object()) else {
        return false;
    };
    if servers.get("inorbit") == Some(&want) {
        return false;
    }
    servers["inorbit"] = want;
    true
}

/// `mcp register`.
///
/// # Errors
/// The file is not JSON or could not be written.
pub(super) fn register(a: &RegisterArgs) -> Result<ExitCode> {
    let cfg = a.door.config()?;
    let file = match &a.file {
        Some(f) => f.clone(),
        None => {
            PathBuf::from(std::env::var_os("HOME").ok_or_else(|| Error::Config("no HOME".into()))?)
                .join(".claude.json")
        }
    };
    let prog = program(a.program.as_ref())?;
    let helper = format!("{} mcp headers", prog.display());
    let url = format!("http://{}/mcp", cfg.listen);
    let raw = match std::fs::read(&file) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::Config(format!("{}: {e}", file.display()))),
    };
    let mut doc: Value = match &raw {
        Some(b) => serde_json::from_slice(b)
            .map_err(|_| Error::Config(format!("{} is not JSON; left alone", file.display())))?,
        None => json!({}),
    };
    if !set_entry(&mut doc, &url, &helper) {
        out("inorbit entry already points at the door");
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(b) = &raw {
        backup(&file, b)?;
    }
    let bytes = serde_json::to_vec_pretty(&doc).map_err(|e| Error::Config(e.to_string()))?;
    write_state(&file, &bytes).map_err(|e| Error::Config(format!("{}: {e}", file.display())))?;
    out(&format!("inorbit entry set in {}", file.display()));
    Ok(ExitCode::SUCCESS)
}

fn backup(file: &Path, bytes: &[u8]) -> Result<()> {
    let bak = file.with_extension("json.bak-mcp-door");
    write_state(&bak, bytes).map_err(|e| Error::Config(format!("{}: {e}", bak.display())))
}

/// The launchd job for `mcp serve`.
///
/// # Errors
/// No home folder to put the log in.
pub(super) fn launchd_plist(a: &LaunchdArgs) -> Result<String> {
    let prog = program(a.program.as_ref())?;
    let home = std::env::var("HOME").map_err(|_| Error::Config("no HOME".into()))?;
    let log = format!("{home}/.inorbit/logs/mcp-bridge.out");
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".into());
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{prog}</string>
    <string>mcp</string>
    <string>serve</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>{path}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>"#,
        prog = xml(&prog.display().to_string()),
        path = xml(&path),
        log = xml(&log),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_is_set_once_and_other_servers_stay() {
        let mut d = json!({"mcpServers": {"other": {"type": "stdio"}}, "x": 1});
        assert!(set_entry(&mut d, "http://127.0.0.1:1/mcp", "p mcp headers"));
        assert!(!set_entry(
            &mut d,
            "http://127.0.0.1:1/mcp",
            "p mcp headers"
        ));
        assert_eq!(d["mcpServers"]["other"]["type"], "stdio");
        assert_eq!(d["mcpServers"]["inorbit"]["headersHelper"], "p mcp headers");
        assert_eq!(d["x"], 1);
    }
}
