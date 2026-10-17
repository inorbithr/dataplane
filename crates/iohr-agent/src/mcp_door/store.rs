//! Where the door's secrets live: the macOS keychain, through the `security` tool, with the
//! value on its standard input (never an argument, which any local process can read in the
//! process list). The item names and the stored format are the ones the first, Python
//! bridge used, so switching to the agent needs no new sign-in.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The secret store.
#[derive(Debug)]
pub enum Store {
    /// The macOS keychain.
    Keychain,
    /// In memory, for tests.
    Memory(Mutex<HashMap<String, String>>),
}

/// The account every item is filed under.
#[cfg(target_os = "macos")]
const ACCOUNT: &str = "inorbit";

/// Decodes a stored value: base64, or the raw text when it is not base64.
#[must_use]
pub fn decode(stored: &str) -> Zeroizing<String> {
    let s = stored.trim();
    match STANDARD
        .decode(s)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
    {
        Some(v) => Zeroizing::new(v),
        None => Zeroizing::new(s.to_owned()),
    }
}

impl Store {
    /// A store that keeps nothing past the process.
    #[must_use]
    pub fn memory() -> Self {
        Self::Memory(Mutex::new(HashMap::new()))
    }

    /// Reads an item.
    ///
    /// # Errors
    /// The keychain could not be asked (not on macOS, or the tool failed to run).
    pub async fn get(&self, item: &str) -> Result<Option<Zeroizing<String>>> {
        match self {
            Self::Memory(m) => Ok(m
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(item)
                .map(|v| decode(v))),
            Self::Keychain => keychain::get(item).await,
        }
    }

    /// Writes an item.
    ///
    /// # Errors
    /// The keychain refused or could not be run.
    pub async fn set(&self, item: &str, value: &str) -> Result<()> {
        match self {
            Self::Memory(m) => {
                m.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(item.to_owned(), STANDARD.encode(value));
                Ok(())
            }
            Self::Keychain => keychain::set(item, value).await,
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn check_item(item: &str) -> Result<()> {
    if item.is_empty() || item.contains(['"', '\n', '\r', '\\']) {
        return Err(Error::Key("keychain item name is not allowed".into()));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod keychain {
    use std::process::Stdio;
    use std::time::Duration;

    use tokio::io::AsyncWriteExt as _;
    use tokio::process::Command;

    use super::{ACCOUNT, Result, STANDARD, check_item, decode};
    use crate::error::Error;
    use base64::Engine as _;
    use zeroize::Zeroizing;

    const TOOL: &str = "/usr/bin/security";
    const LIMIT: Duration = Duration::from_secs(10);

    pub(super) async fn get(item: &str) -> Result<Option<Zeroizing<String>>> {
        check_item(item)?;
        let run = Command::new(TOOL)
            .args(["find-generic-password", "-s", item, "-a", ACCOUNT, "-w"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output();
        let out = tokio::time::timeout(LIMIT, run)
            .await
            .map_err(|_| Error::Key("the keychain did not answer in time".into()))?
            .map_err(|e| Error::Key(format!("cannot run security: {e}")))?;
        if !out.status.success() {
            // Exit 44 is "item not found"; anything else (locked, denied) reads as absent
            // too, and the sign-in flow then asks the person.
            return Ok(None);
        }
        let text = Zeroizing::new(String::from_utf8_lossy(&out.stdout).into_owned());
        if text.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(decode(&text)))
    }

    pub(super) async fn set(item: &str, value: &str) -> Result<()> {
        check_item(item)?;
        let encoded = Zeroizing::new(STANDARD.encode(value));
        let line = Zeroizing::new(format!(
            "add-generic-password -U -s \"{item}\" -a {ACCOUNT} -w \"{}\"\n",
            encoded.as_str()
        ));
        let mut child = Command::new(TOOL)
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::Key(format!("cannot run security: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(line.as_bytes())
                .await
                .map_err(|e| Error::Key(format!("cannot write to security: {e}")))?;
        }
        let status = tokio::time::timeout(LIMIT, child.wait())
            .await
            .map_err(|_| Error::Key("the keychain did not answer in time".into()))?
            .map_err(|e| Error::Key(format!("security: {e}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Key("the keychain refused the write".into()))
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod keychain {
    use super::{Error, Result, Zeroizing};

    // Async to match the macOS implementation the caller awaits.
    #[allow(clippy::unused_async)]
    pub(super) async fn get(_item: &str) -> Result<Option<Zeroizing<String>>> {
        Err(Error::Key(
            "the MCP door keeps its sign-in in the macOS keychain; this host is not macOS".into(),
        ))
    }

    #[allow(clippy::unused_async)]
    pub(super) async fn set(_item: &str, _value: &str) -> Result<()> {
        Err(Error::Key(
            "the MCP door keeps its sign-in in the macOS keychain; this host is not macOS".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_reads_base64_and_falls_back_to_raw() {
        assert_eq!(decode(&STANDARD.encode("{\"a\":1}")).as_str(), "{\"a\":1}");
        assert_eq!(decode("{\"a\":1}").as_str(), "{\"a\":1}");
    }

    #[tokio::test]
    async fn memory_round_trip() {
        let s = Store::memory();
        assert!(s.get("x").await.unwrap().is_none());
        s.set("x", "secret value").await.unwrap();
        assert_eq!(s.get("x").await.unwrap().unwrap().as_str(), "secret value");
    }

    #[test]
    fn item_names_with_quotes_are_refused() {
        assert!(check_item("ok-item").is_ok());
        assert!(check_item("a\"b").is_err());
        assert!(check_item("a\nb").is_err());
    }
}
