//! Compact JWS parsing and signature checks with pinned algorithms (RFC 7515, RFC 7518). ring does the cryptography.
//!
//! The rules, in order: three base64url segments; the header `alg` is one the caller allows and one this crate implements (RS256, ES256, EdDSA; `none` and every HMAC are refused);
//! the key is chosen from the caller's own set by the token's `kid`, never from the token; the key's type fits the algorithm; the signature verifies over `header.payload`. Only then
//! are the claims returned: a claim of a token that failed any of this is never read.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;

use crate::error::Error;
use crate::jwk::{Jwk, JwkSet};

/// A signature algorithm the contract allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ECDSA over P-256 with SHA-256 (the signature is the raw 64 bytes `r || s`).
    Es256,
    /// Ed25519.
    EdDsa,
    /// RSASSA-PKCS1-v1_5 with SHA-256, keys of 2048 to 8192 bits (Keycloak's default realm key).
    Rs256,
}

impl Algorithm {
    /// The `alg` header value.
    fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }

    /// The algorithm for a header value, among the ones this crate implements.
    fn from_name(name: &str) -> Option<Self> {
        [Self::Es256, Self::EdDsa, Self::Rs256].into_iter().find(|a| a.name() == name)
    }
}

/// The contract's allow-list for an ID or logout token: all three algorithms. A caller may only narrow it.
pub const CONTRACT_ALGORITHMS: [Algorithm; 3] = [Algorithm::Es256, Algorithm::EdDsa, Algorithm::Rs256];

/// The JOSE header members the checks read.
#[derive(Debug, Deserialize)]
struct Header {
    /// The signing algorithm.
    alg: String,
    /// The key id.
    #[serde(default)]
    kid: String,
    /// The token type (`JWT`, `at+jwt`, `logout+jwt`).
    #[serde(default)]
    typ: String,
}

/// A token whose signature has verified: its header `typ` and its claims.
#[derive(Debug, Clone)]
pub struct Opened {
    /// The header `typ`, lower-cased ("" when absent).
    pub typ: String,
    /// The claims object.
    pub claims: serde_json::Map<String, serde_json::Value>,
}

/// The key id a token names, for a key refresh before verification (`None` when the token is malformed).
pub fn key_id(token: &str) -> Option<String> {
    let header = token.split('.').next()?;
    let h: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    Some(h.kid)
}

/// Verify the signature of `token` against `keys`, allowing only `algorithms`, and return its header type and claims.
pub fn open(token: &str, keys: &JwkSet, algorithms: &[Algorithm]) -> Result<Opened, Error> {
    let mut parts = token.split('.');
    let (Some(h64), Some(p64), Some(s64), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(Error::Malformed);
    };
    let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h64).map_err(|_| Error::Malformed)?)
        .map_err(|_| Error::Malformed)?;
    // The algorithm must be implemented here AND allowed by the caller: `none` and the HMACs are not implemented, so they can never pass.
    let alg = Algorithm::from_name(&header.alg).filter(|a| algorithms.contains(a)).ok_or(Error::Algorithm)?;
    // The key is chosen by the token's id from OUR set; a token cannot bring its own.
    let key = keys.find(&header.kid).ok_or(Error::Key)?;
    // A key stated for another algorithm is refused (an RS256 key never verifies an HMAC-style forgery).
    if key.alg.as_deref().is_some_and(|a| a != alg.name()) {
        return Err(Error::Algorithm);
    }
    let sig = URL_SAFE_NO_PAD.decode(s64).map_err(|_| Error::Malformed)?;
    // The signature covers the header and payload exactly as they were sent.
    let signed = &token[..h64.len() + 1 + p64.len()];
    verify_signature(alg, key, signed.as_bytes(), &sig)?;
    // Only now are the claims read.
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p64).map_err(|_| Error::Malformed)?)
        .map_err(|_| Error::Malformed)?;
    let serde_json::Value::Object(claims) = claims else { return Err(Error::Malformed) };
    Ok(Opened { typ: header.typ.to_ascii_lowercase(), claims })
}

/// Check `sig` over `message` with the public key `key` for `alg`; the key type must fit the algorithm.
fn verify_signature(alg: Algorithm, key: &Jwk, message: &[u8], sig: &[u8]) -> Result<(), Error> {
    let decode = |s: &str| URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::Key);
    match alg {
        Algorithm::Rs256 => {
            if key.kty != "RSA" {
                return Err(Error::Key);
            }
            let (n, e) = (decode(&key.n)?, decode(&key.e)?);
            RsaPublicKeyComponents { n: &n, e: &e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, sig)
                .map_err(|_| Error::Signature)
        }
        Algorithm::Es256 => {
            if key.kty != "EC" || key.crv != "P-256" {
                return Err(Error::Key);
            }
            // The uncompressed point ring wants: 0x04 || x || y, each coordinate exactly 32 bytes.
            let (x, y) = (decode(&key.x)?, decode(&key.y)?);
            if x.len() != 32 || y.len() != 32 {
                return Err(Error::Key);
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(message, sig)
                .map_err(|_| Error::Signature)
        }
        Algorithm::EdDsa => {
            if key.kty != "OKP" || key.crv != "Ed25519" {
                return Err(Error::Key);
            }
            UnparsedPublicKey::new(&signature::ED25519, decode(&key.x)?)
                .verify(message, sig)
                .map_err(|_| Error::Signature)
        }
    }
}

/// Unit tests for signature checks.
#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing::{Signer, Suite};

    /// Both algorithms verify their own tokens and return the claims and the header type.
    #[test]
    fn signed_tokens_open() {
        for suite in [Suite::Rs256, Suite::Es256] {
            let s = Signer::new(suite, "k1");
            let opened =
                open(&s.sign_with_typ(&json!({ "sub": "u" }), "JWT"), &s.jwks(), &CONTRACT_ALGORITHMS).expect("opens");
            assert_eq!(opened.typ, "jwt");
            assert_eq!(opened.claims["sub"], "u");
            assert_eq!(key_id(&s.sign(&json!({}))).as_deref(), Some("k1"));
        }
    }

    /// `none`, an HMAC, an algorithm the caller did not allow, a mismatched key type, a tampered payload, an unknown key id and a malformed token are all refused.
    #[test]
    fn forgeries_and_misuse_are_refused() {
        let s = Signer::new(Suite::Es256, "k1");
        let keys = s.jwks();
        let good = s.sign(&json!({ "sub": "u" }));
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(json!({"alg":"none","kid":"k1"}).to_string()),
            URL_SAFE_NO_PAD.encode(json!({"sub":"admin"}).to_string())
        );
        assert_eq!(open(&none, &keys, &CONTRACT_ALGORITHMS).unwrap_err(), Error::Algorithm);
        assert_eq!(
            open(&s.sign_header(&json!({"alg":"HS256","kid":"k1"}), &json!({})), &keys, &CONTRACT_ALGORITHMS)
                .unwrap_err(),
            Error::Algorithm
        );
        // The caller narrowed the list to RS256: an ES256 token is refused though the crate implements it.
        assert_eq!(open(&good, &keys, &[Algorithm::Rs256]).unwrap_err(), Error::Algorithm);
        // The header says RS256 but the key at that id is an EC key: the key type does not fit.
        assert_eq!(
            open(&s.sign_header(&json!({"alg":"RS256","kid":"k1"}), &json!({})), &keys, &CONTRACT_ALGORITHMS)
                .unwrap_err(),
            Error::Algorithm
        );
        let parts: Vec<&str> = good.split('.').collect();
        let tampered =
            format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(json!({"sub":"admin"}).to_string()), parts[2]);
        assert_eq!(open(&tampered, &keys, &CONTRACT_ALGORITHMS).unwrap_err(), Error::Signature);
        assert_eq!(
            open(&good, &Signer::new(Suite::Es256, "other").jwks(), &CONTRACT_ALGORITHMS).unwrap_err(),
            Error::Key
        );
        assert_eq!(open("a.b", &keys, &CONTRACT_ALGORITHMS).unwrap_err(), Error::Malformed);
        assert_eq!(open("a.b.c.d", &keys, &CONTRACT_ALGORITHMS).unwrap_err(), Error::Malformed);
    }

    /// A key marked for encryption is never used to verify.
    #[test]
    fn a_key_for_encryption_is_skipped() {
        let s = Signer::new(Suite::Es256, "k1");
        let mut keys = s.jwks();
        keys.keys[0].use_ = Some("enc".into());
        assert_eq!(open(&s.sign(&json!({})), &keys, &CONTRACT_ALGORITHMS).unwrap_err(), Error::Key);
    }
}
