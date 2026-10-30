//! Label encodings used by the inbound (query-based) channel.
//!
//! The emulated client packs data into subdomain labels using one of these
//! encodings. Varying the encoding is how an operator tunes the *entropy*
//! signature of the generated traffic: Hex is low-entropy, Base64URL is high.

use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD, HEXLOWER_PERMISSIVE};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    /// RFC 4648 Base32, no padding. DNS-safe, case-insensitive. Default.
    Base32,
    /// Lowercase hex. Lowest entropy; good for testing entropy-threshold tuning.
    Hex,
    /// RFC 4648 Base64URL, no padding. Highest entropy of the three.
    Base64url,
}

impl Encoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Base32 => "base32",
            Encoding::Hex => "hex",
            Encoding::Base64url => "base64url",
        }
    }

    /// Decode a single label's bytes. Returns `None` on any decode error so the
    /// caller can treat an undecodable label as "no embedded payload" rather
    /// than failing the query.
    pub fn decode(self, label: &str) -> Option<Vec<u8>> {
        let bytes = label.as_bytes();
        match self {
            // Base32 alphabet is upper-case; emulated clients may send lower.
            Encoding::Base32 => BASE32_NOPAD.decode(label.to_ascii_uppercase().as_bytes()).ok(),
            Encoding::Hex => HEXLOWER_PERMISSIVE.decode(bytes).ok(),
            Encoding::Base64url => BASE64URL_NOPAD.decode(bytes).ok(),
        }
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip_is_case_insensitive() {
        let encoded = BASE32_NOPAD.encode(b"hello").to_ascii_lowercase();
        assert_eq!(Encoding::Base32.decode(&encoded), Some(b"hello".to_vec()));
    }

    #[test]
    fn hex_decodes_lowercase() {
        assert_eq!(Encoding::Hex.decode("68656c6c6f"), Some(b"hello".to_vec()));
    }

    #[test]
    fn bad_label_returns_none() {
        assert_eq!(Encoding::Base32.decode("!!!!"), None);
    }
}

impl std::str::FromStr for Encoding {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "base32" => Ok(Encoding::Base32),
            "hex" => Ok(Encoding::Hex),
            "base64url" | "base64" => Ok(Encoding::Base64url),
            other => Err(format!("unknown encoding {other:?} (expected base32|hex|base64url)")),
        }
    }
}
