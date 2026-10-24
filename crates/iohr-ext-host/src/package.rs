//! A package on disk (`extension.toml`, `extension.wasm`, `extension.sig`) and its
//! signature (ADR 0060's third yes is the lock; this is what the lock pins).
//!
//! The publisher signs, with Ed25519, the line-oriented message
//! `iohr-ext/v1\nmanifest sha256:<hex>\ncomponent sha256:<hex>\n`, so the
//! manifest's capabilities can no more be widened than the code can be swapped.
//! The machine's policy pins each publisher's keys, in the agent's `ed25519:<base64url>`
//! form, by key id (the first 16 hex digits of SHA-256 over the 32 key bytes).

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use iohr_evidence::digest::ContentDigest;
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::limits::{MAX_COMPONENT_BYTES, MAX_MANIFEST_BYTES};
use crate::manifest::Manifest;

/// The manifest's file name in a package.
pub const MANIFEST_FILE: &str = "extension.toml";
/// The component's file name.
pub const COMPONENT_FILE: &str = "extension.wasm";
/// The signature's file name.
pub const SIGNATURE_FILE: &str = "extension.sig";
/// The only signature algorithm.
pub const ALG: &str = "ed25519";

/// `sha256:<hex>` of `bytes`, the digest form the evidence crate names content by.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    ContentDigest::of_bytes(bytes).to_hex()
}

/// A key's id: the first 16 hex digits of SHA-256 over its 32 bytes (the agent's
/// `actions` key id).
#[must_use]
pub fn key_id(key: &VerifyingKey) -> String {
    ContentDigest::of_bytes(key.as_bytes()).to_hex()[7..23].to_owned()
}

/// What the publisher signs.
#[must_use]
pub fn message(manifest: &[u8], component: &[u8]) -> String {
    format!(
        "iohr-ext/v1\nmanifest {}\ncomponent {}\n",
        sha256_hex(manifest),
        sha256_hex(component)
    )
}

/// `extension.sig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Which pinned key signed.
    pub key_id: String,
    /// Always [`ALG`].
    pub alg: String,
    /// The signature, base64.
    pub sig: String,
}

/// Signs a manifest and component.
#[must_use]
pub fn sign(key: &SigningKey, manifest: &[u8], component: &[u8]) -> Signature {
    let s = key.sign(message(manifest, component).as_bytes());
    Signature {
        key_id: key_id(&key.verifying_key()),
        alg: ALG.into(),
        sig: base64::engine::general_purpose::STANDARD.encode(s.to_bytes()),
    }
}

/// The keys each publisher signs with, from the machine's policy.
#[derive(Debug, Clone, Default)]
pub struct Trust(BTreeMap<String, Vec<VerifyingKey>>);

impl Trust {
    /// No publisher trusted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusts `key` for `publisher`.
    #[must_use]
    pub fn with(mut self, publisher: &str, key: VerifyingKey) -> Self {
        self.0.entry(publisher.to_owned()).or_default().push(key);
        self
    }

    /// Checks `sig` over the two files with a key pinned for the manifest's publisher.
    ///
    /// # Errors
    /// [`Error::Signature`] when the publisher is not trusted, the key is not one of
    /// its keys, or the signature does not verify.
    pub fn verify(
        &self,
        publisher: &str,
        sig: &Signature,
        manifest: &[u8],
        component: &[u8],
    ) -> Result<(), Error> {
        if sig.alg != ALG {
            return Err(Error::Signature(
                "only ed25519 signatures are accepted".into(),
            ));
        }
        let keys = self.0.get(publisher).ok_or_else(|| {
            Error::Signature(format!(
                "publisher {publisher:?} has no pinned key in [extensions] publishers"
            ))
        })?;
        let key = keys
            .iter()
            .find(|k| key_id(k) == sig.key_id)
            .ok_or_else(|| {
                Error::Signature(format!(
                    "key {} is not pinned for {publisher:?}",
                    crate::manifest::shown(&sig.key_id)
                ))
            })?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&sig.sig)
            .map_err(|_| Error::Signature("signature is not base64".into()))?;
        let s = ed25519_dalek::Signature::from_slice(&raw)
            .map_err(|_| Error::Signature("signature is not 64 bytes".into()))?;
        key.verify_strict(message(manifest, component).as_bytes(), &s)
            .map_err(|_| Error::Signature("signature does not match the files".into()))
    }
}

/// A package whose signature verified.
#[derive(Debug, Clone)]
pub struct Package {
    /// The parsed manifest.
    pub manifest: Manifest,
    /// The component bytes.
    pub component: Vec<u8>,
    /// `sha256:<hex>` of the component, what the lock pins.
    pub digest: String,
    /// The key that signed.
    pub key_id: String,
}

impl Package {
    /// Reads a package directory and verifies it against `trust`.
    ///
    /// # Errors
    /// [`Error::Io`] when a file is missing or over its size bound, then whatever
    /// [`Package::verify`] refuses.
    pub fn open(dir: &Path, trust: &Trust) -> Result<Self, Error> {
        let manifest = read_bounded(&dir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
        let component = read_bounded(&dir.join(COMPONENT_FILE), MAX_COMPONENT_BYTES)?;
        let sig = read_bounded(&dir.join(SIGNATURE_FILE), 4096)?;
        Self::verify(&manifest, component, &sig, trust)
    }

    /// Verifies the three files' bytes against `trust`.
    ///
    /// # Errors
    /// [`Error::Manifest`] on a bad manifest, [`Error::Signature`] on a signature
    /// that is malformed, untrusted or does not match.
    pub fn verify(
        manifest: &[u8],
        component: Vec<u8>,
        sig: &[u8],
        trust: &Trust,
    ) -> Result<Self, Error> {
        let sig: Signature = serde_json::from_slice(sig)
            .map_err(|_| Error::Signature("extension.sig is not a signature".into()))?;
        let text = std::str::from_utf8(manifest)
            .map_err(|_| Error::Manifest("extension.toml is not UTF-8".into()))?;
        let m = Manifest::parse(text)?;
        trust.verify(m.publisher(), &sig, manifest, &component)?;
        Ok(Self {
            digest: sha256_hex(&component),
            manifest: m,
            component,
            key_id: sig.key_id,
        })
    }
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, Error> {
    let shown = || path.display().to_string();
    let len = std::fs::metadata(path)
        .map_err(|e| Error::Io(format!("{}: {e}", shown())))?
        .len();
    if usize::try_from(len).map_or(true, |l| l > max) {
        return Err(Error::Io(format!("{} is over {max} bytes", shown())));
    }
    std::fs::read(path).map_err(|e| Error::Io(format!("{}: {e}", shown())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = "id = \"acme/x\"\nname = \"X\"\nversion = \"1.0.0\"\n";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signed(k: &SigningKey, m: &str, c: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&sign(k, m.as_bytes(), c)).unwrap()
    }

    #[test]
    fn a_signed_package_verifies_and_any_change_is_refused() {
        let k = key(1);
        let trust = Trust::new().with("acme", k.verifying_key());
        let sig = signed(&k, MANIFEST, b"code");
        let p = Package::verify(MANIFEST.as_bytes(), b"code".to_vec(), &sig, &trust).unwrap();
        assert_eq!(p.digest, sha256_hex(b"code"));

        // The component swapped.
        let e = Package::verify(MANIFEST.as_bytes(), b"c0de".to_vec(), &sig, &trust);
        assert!(matches!(e, Err(Error::Signature(_))), "{e:?}");
        // The manifest widened.
        let wider = format!("{MANIFEST}capabilities = [\"trail\"]\n");
        let e = Package::verify(wider.as_bytes(), b"code".to_vec(), &sig, &trust);
        assert!(matches!(e, Err(Error::Signature(_))), "{e:?}");
    }

    #[test]
    fn only_the_publishers_own_pinned_keys_count() {
        let (acme, other) = (key(1), key(2));
        let sig = signed(&other, MANIFEST, b"code");
        // Pinned, but for another publisher.
        let trust = Trust::new()
            .with("acme", acme.verifying_key())
            .with("other", other.verifying_key());
        let e = Package::verify(MANIFEST.as_bytes(), b"code".to_vec(), &sig, &trust);
        assert!(matches!(e, Err(Error::Signature(_))), "{e:?}");
        // Publisher not pinned at all.
        let e = Package::verify(MANIFEST.as_bytes(), b"code".to_vec(), &sig, &Trust::new());
        assert!(matches!(e, Err(Error::Signature(_))), "{e:?}");
    }
}
