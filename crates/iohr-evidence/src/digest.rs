//! Content digests and canonical encoding (ADR 0013 in inorbithr/core).
//!
//! Anything whose identity is its content (an artefact's bytes, a world snapshot) is
//! named by the SHA-256 of a canonical encoding: the same content always yields the same
//! digest, whatever order it was assembled in. Canonical form is JSON produced from
//! types whose maps are `BTreeMap`s and whose sets are `BTreeSet`s, so key order is
//! fixed by the type, never by insertion.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// A SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// The digest of these bytes.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let out: [u8; 32] = Sha256::digest(bytes).into();
        Self(out)
    }

    /// The digest of a value's canonical JSON encoding.
    ///
    /// # Errors
    /// The value cannot be encoded as JSON (a map with non-string keys).
    pub fn of_canonical<T: Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        serde_json::to_vec(value).map(|bytes| Self::of_bytes(&bytes))
    }

    /// The raw 32 bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex, prefixed `sha256:`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        use fmt::Write as _;
        let mut s = String::with_capacity(7 + 64);
        s.push_str("sha256:");
        for b in self.0 {
            // Writing to a String cannot fail.
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

/// A digest in text form was not `sha256:` and 64 lower-case hex digits.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("not a sha256 digest: {0:?}")]
pub struct BadDigest(pub String);

impl TryFrom<String> for ContentDigest {
    type Error = BadDigest;

    fn try_from(text: String) -> Result<Self, BadDigest> {
        let hex = text
            .strip_prefix("sha256:")
            .ok_or_else(|| BadDigest(text.clone()))?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(BadDigest(text));
        }
        let mut out = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let hi = nibble(pair[0]);
            let lo = nibble(pair[1]);
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        // Only a..=f reach here; validated above.
        _ => c - b'a' + 10,
    }
}

impl From<ContentDigest> for String {
    fn from(d: ContentDigest) -> Self {
        d.to_hex()
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn known_vector() {
        // SHA-256 of the empty string.
        assert_eq!(
            ContentDigest::of_bytes(b"").to_hex(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn text_form_rejects_wrong_prefix_case_and_length() {
        for bad in [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "sha256:e3b0",
            "sha1:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ] {
            assert!(ContentDigest::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn text_form_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let d = ContentDigest::of_bytes(&bytes);
            let back = ContentDigest::try_from(d.to_hex()).unwrap();
            prop_assert_eq!(back, d);
        }
    }
}
