//! The agent's own key pair, made on the machine at enrollment and never sent anywhere.
//!
//! The platform's identity provider (Ory Hydra) accepts `private_key_jwt` client
//! assertions signed with RS*, PS* or ES* algorithms, so the default is an EC P-256 key
//! (ES256). Ed25519 (EdDSA) is kept for identity providers that accept it.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Which kind of key the agent makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum KeyAlg {
    /// EC P-256, signs ES256. Accepted by Hydra for `private_key_jwt`.
    #[default]
    Es256,
    /// Ed25519, signs `EdDSA`.
    Ed25519,
}

/// A private key. `Debug` never prints key material.
pub enum AgentKey {
    /// EC P-256.
    Es256(p256::ecdsa::SigningKey),
    /// Ed25519.
    Ed25519(ed25519_dalek::SigningKey),
}

impl fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentKey")
            .field("alg", &self.jws_alg())
            .field("kid", &self.kid())
            .finish_non_exhaustive()
    }
}

impl AgentKey {
    /// Makes a new key from the operating system's random source.
    ///
    /// # Errors
    /// When the random source fails.
    pub fn generate(alg: KeyAlg) -> Result<Self> {
        loop {
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed.as_mut()).map_err(|e| Error::Key(format!("random: {e}")))?;
            match alg {
                KeyAlg::Ed25519 => {
                    return Ok(Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)));
                }
                KeyAlg::Es256 => {
                    // A scalar of zero or above the group order is rejected; draw again.
                    if let Ok(k) = p256::ecdsa::SigningKey::from_slice(seed.as_ref()) {
                        return Ok(Self::Es256(k));
                    }
                }
            }
        }
    }

    /// The JWS `alg` this key signs with.
    #[must_use]
    pub fn jws_alg(&self) -> &'static str {
        match self {
            Self::Es256(_) => "ES256",
            Self::Ed25519(_) => "EdDSA",
        }
    }

    /// The public key as a JWK with `use`, `alg` and `kid` (RFC 7517, RFC 7638).
    #[must_use]
    pub fn public_jwk(&self) -> Value {
        let mut jwk = self.thumbprint_members();
        if let Value::Object(map) = &mut jwk {
            map.insert("use".into(), "sig".into());
            map.insert("alg".into(), self.jws_alg().into());
            map.insert("kid".into(), self.kid().into());
        }
        jwk
    }

    /// The RFC 7638 thumbprint of the public key, used as `kid`.
    #[must_use]
    pub fn kid(&self) -> String {
        // serde_json keeps object keys sorted, which is the canonical form RFC 7638 asks.
        let canonical = self.thumbprint_members().to_string();
        B64.encode(Sha256::digest(canonical.as_bytes()))
    }

    fn thumbprint_members(&self) -> Value {
        match self {
            Self::Es256(k) => {
                let point = k.verifying_key().to_encoded_point(false);
                let x = point.x().map(|x| B64.encode(x)).unwrap_or_default();
                let y = point.y().map(|y| B64.encode(y)).unwrap_or_default();
                json!({"crv": "P-256", "kty": "EC", "x": x, "y": y})
            }
            Self::Ed25519(k) => {
                json!({"crv": "Ed25519", "kty": "OKP", "x": B64.encode(k.verifying_key().as_bytes())})
            }
        }
    }

    /// A compact JWS over `claims`, with `alg`, `kid` and `typ: JWT` in the header.
    #[must_use]
    pub fn sign_jwt(&self, claims: &Value) -> String {
        let header = json!({"alg": self.jws_alg(), "kid": self.kid(), "typ": "JWT"});
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let sig = match self {
            Self::Es256(k) => {
                use p256::ecdsa::signature::Signer as _;
                let s: p256::ecdsa::Signature = k.sign(input.as_bytes());
                s.to_bytes().to_vec()
            }
            Self::Ed25519(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(input.as_bytes()).to_bytes().to_vec()
            }
        };
        format!("{input}.{}", B64.encode(sig))
    }

    /// PKCS#8 PEM, zeroized on drop.
    ///
    /// # Errors
    /// When encoding fails.
    pub fn to_pem(&self) -> Result<Zeroizing<String>> {
        use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
        match self {
            Self::Es256(k) => k
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| Error::Key(format!("encode: {e}"))),
            Self::Ed25519(k) => {
                use ed25519_dalek::pkcs8::EncodePrivateKey as _;
                k.to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                    .map_err(|e| Error::Key(format!("encode: {e}")))
            }
        }
    }

    /// Reads a PKCS#8 PEM key of either kind.
    ///
    /// # Errors
    /// When the PEM is neither a P-256 nor an Ed25519 key.
    pub fn from_pem(pem: &str) -> Result<Self> {
        use p256::pkcs8::DecodePrivateKey as _;
        if let Ok(k) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::Es256(k));
        }
        {
            use ed25519_dalek::pkcs8::DecodePrivateKey as _;
            if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
                return Ok(Self::Ed25519(k));
            }
        }
        Err(Error::Key(
            "not a PKCS#8 P-256 or Ed25519 private key".into(),
        ))
    }

    /// Writes the key to `path`, readable by its owner only. Refuses to replace an
    /// existing file unless `replace` is set.
    ///
    /// # Errors
    /// When the file exists (and `replace` is not set) or cannot be written.
    pub fn save(&self, path: &Path, replace: bool) -> Result<()> {
        let pem = self.to_pem()?;
        write_private(path, pem.as_bytes(), replace)
    }

    /// Reads the key at `path`. On Unix, refuses a file others can read.
    ///
    /// # Errors
    /// When the file is missing, too open or not a key.
    pub fn load(path: &Path) -> Result<Self> {
        check_private(path)?;
        let pem = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?);
        Self::from_pem(&pem)
    }
}

/// Writes `bytes` to `path` with mode 0600 (Unix), creating the parent directory with
/// mode 0700 if needed.
///
/// # Errors
/// When the file exists (and `replace` is not set) or cannot be written.
pub fn write_private(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        create_private_dir(parent)?;
    }
    let mut opts = OpenOptions::new();
    opts.write(true);
    if replace {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| Error::io(path, e))?;
    f.write_all(bytes).map_err(|e| Error::io(path, e))?;
    f.sync_all().map_err(|e| Error::io(path, e))?;
    Ok(())
}

/// Creates a directory (and parents) readable by its owner only.
///
/// # Errors
/// When it cannot be created.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(dir).map_err(|e| Error::io(dir, e))
}

/// On Unix, fails when `path` is readable or writable by group or others.
///
/// # Errors
/// When the file is missing or too open.
pub fn check_private(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path).map_err(|e| Error::io(path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(Error::Key(format!(
                "{} is accessible by other users (mode {:o}); run chmod 600 on it",
                path.display(),
                mode & 0o777
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify(jwt: &str, jwk: &Value) -> bool {
        let mut parts = jwt.rsplitn(2, '.');
        let sig = B64.decode(parts.next().unwrap()).unwrap();
        let input = parts.next().unwrap();
        match jwk["kty"].as_str().unwrap() {
            "EC" => {
                use p256::ecdsa::signature::Verifier as _;
                let x = B64.decode(jwk["x"].as_str().unwrap()).unwrap();
                let y = B64.decode(jwk["y"].as_str().unwrap()).unwrap();
                let point = p256::EncodedPoint::from_affine_coordinates(
                    x.as_slice().into(),
                    y.as_slice().into(),
                    false,
                );
                let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&point).unwrap();
                let sig = p256::ecdsa::Signature::from_slice(&sig).unwrap();
                vk.verify(input.as_bytes(), &sig).is_ok()
            }
            "OKP" => {
                let x: [u8; 32] = B64
                    .decode(jwk["x"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap();
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&x).unwrap();
                let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
                vk.verify_strict(input.as_bytes(), &sig).is_ok()
            }
            _ => false,
        }
    }

    #[test]
    fn signs_and_verifies_both_kinds() {
        for alg in [KeyAlg::Es256, KeyAlg::Ed25519] {
            let key = AgentKey::generate(alg).unwrap();
            let jwk = key.public_jwk();
            assert_eq!(jwk["use"], "sig");
            assert_eq!(jwk["kid"], key.kid());
            assert!(
                jwk.get("d").is_none(),
                "public JWK must not carry the private part"
            );
            let jwt = key.sign_jwt(&json!({"iss": "c", "exp": 1}));
            assert!(verify(&jwt, &jwk));
            let mut tampered = jwt.clone();
            tampered.insert(5, 'A');
            assert!(!verify(&tampered, &jwk));
        }
    }

    #[test]
    fn pem_round_trip_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        for alg in [KeyAlg::Es256, KeyAlg::Ed25519] {
            let path = dir.path().join(format!("k-{alg:?}/agent.key"));
            let key = AgentKey::generate(alg).unwrap();
            key.save(&path, false).unwrap();
            assert!(key.save(&path, false).is_err(), "must not replace silently");
            let back = AgentKey::load(&path).unwrap();
            assert_eq!(back.kid(), key.kid());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
                assert!(AgentKey::load(&path).is_err());
            }
        }
    }

    #[test]
    fn debug_hides_material() {
        let key = AgentKey::generate(KeyAlg::Es256).unwrap();
        let s = format!("{key:?}");
        assert!(s.contains("ES256"));
        assert!(!s.contains("PRIVATE"));
    }
}
