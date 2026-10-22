//! `extension.toml`: who the extension is, what it may import, its settings.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::limits::{MAX_NAME, MAX_VALUE};

/// The WIT package every host interface lives in.
pub const PACKAGE: &str = "iohr:ext";
/// Its version.
pub const PACKAGE_VERSION: &str = "0.1.0";

/// A host interface an extension imports. Each is declared in the manifest and
/// granted by the machine's policy; the component may import only those.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// `iohr:ext/log`.
    Log,
    /// `iohr:ext/config`.
    Config,
    /// `iohr:ext/timer`.
    Timer,
    /// `iohr:ext/sensor`.
    Sensor,
    /// `iohr:ext/trail`.
    Trail,
}

impl Capability {
    /// Every capability slice 1 offers.
    pub const ALL: [Self; 5] = [
        Self::Log,
        Self::Config,
        Self::Timer,
        Self::Sensor,
        Self::Trail,
    ];

    /// The WIT interface name, `log`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Config => "config",
            Self::Timer => "timer",
            Self::Sensor => "sensor",
            Self::Trail => "trail",
        }
    }

    /// The capability a component import names (`iohr:ext/sensor@0.1.0`), if it is
    /// one of ours.
    #[must_use]
    pub fn from_import(import: &str) -> Option<Self> {
        let rest = import.strip_prefix(PACKAGE)?.strip_prefix('/')?;
        let (iface, version) = rest.split_once('@')?;
        if version != PACKAGE_VERSION {
            return None;
        }
        Self::ALL.into_iter().find(|c| c.name() == iface)
    }
}

/// `extension.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// `publisher/name`, lower case.
    pub id: String,
    /// Shown name.
    pub name: String,
    /// The extension's own version.
    pub version: String,
    /// One line on what it does.
    #[serde(default)]
    pub summary: String,
    /// The host interfaces it imports.
    #[serde(default)]
    pub capabilities: BTreeSet<Capability>,
    /// Default settings, read through `iohr:ext/config`.
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

impl Manifest {
    /// Parses and checks a manifest.
    ///
    /// # Errors
    /// [`Error::Manifest`] when it is not valid TOML or a field is out of bounds.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let m: Self = toml::from_str(text).map_err(|e| Error::Manifest(e.message().into()))?;
        m.check()?;
        Ok(m)
    }

    /// The publisher part of the id.
    #[must_use]
    pub fn publisher(&self) -> &str {
        self.id.split_once('/').map_or("", |(p, _)| p)
    }

    fn check(&self) -> Result<(), Error> {
        if !is_id(&self.id) {
            return Err(Error::Manifest(format!(
                "id {:?} must be publisher/name in a-z 0-9 -",
                shown(&self.id)
            )));
        }
        if self.name.is_empty() || self.name.len() > MAX_NAME {
            return Err(Error::Manifest("name must be 1 to 128 bytes".into()));
        }
        if self.version.is_empty()
            || self.version.len() > 64
            || !self
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
        {
            return Err(Error::Manifest(
                "version must be a semver-like string".into(),
            ));
        }
        if self.summary.len() > MAX_VALUE {
            return Err(Error::Manifest("summary is over 1 KiB".into()));
        }
        if self.config.len() > 64
            || self
                .config
                .iter()
                .any(|(k, v)| k.is_empty() || k.len() > MAX_NAME || v.len() > MAX_VALUE)
        {
            return Err(Error::Manifest(
                "config holds at most 64 keys of 128 bytes, values of 1 KiB".into(),
            ));
        }
        Ok(())
    }
}

/// `publisher/name`: two parts of 1 to 64 `a-z 0-9 -`.
#[must_use]
pub fn is_id(id: &str) -> bool {
    let part = |s: &str| {
        (1..=64).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    id.split_once('/').is_some_and(|(p, n)| part(p) && part(n))
}

/// At most 64 printable characters of an untrusted string, for an error.
pub(crate) fn shown(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_parses_and_bad_ids_are_refused() {
        let m = Manifest::parse(
            r#"
            id = "acme/hello-sensor"
            name = "Hello sensor"
            version = "0.1.0"
            capabilities = ["log", "sensor"]
            [config]
            greeting = "hi"
            "#,
        )
        .unwrap();
        assert_eq!(m.publisher(), "acme");
        assert!(m.capabilities.contains(&Capability::Sensor));
        for bad in ["Acme/x", "acme", "acme/", "a/b/c", "acme/x y"] {
            let t = format!("id = {bad:?}\nname = \"n\"\nversion = \"1\"");
            assert!(Manifest::parse(&t).is_err(), "{bad}");
        }
        assert!(
            Manifest::parse("id = \"a/b\"\nname = \"n\"\nversion = \"1\"\nnet = true").is_err()
        );
    }

    #[test]
    fn imports_map_to_capabilities_only_at_our_version() {
        assert_eq!(
            Capability::from_import("iohr:ext/trail@0.1.0"),
            Some(Capability::Trail)
        );
        assert_eq!(Capability::from_import("iohr:ext/trail@0.2.0"), None);
        assert_eq!(Capability::from_import("iohr:ext/http@0.1.0"), None);
        assert_eq!(Capability::from_import("wasi:cli/stdout@0.2.0"), None);
    }
}
