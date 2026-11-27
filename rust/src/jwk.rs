//! JSON Web Keys and key sets (RFC 7517), parsed with the limits the contract sets and only for the key types it allows.

use serde::Deserialize;

use crate::error::Error;

/// The largest key set document that is read (contract section 1: 64 KiB here, the consoles' existing cap).
pub const MAX_JWKS_BYTES: usize = 64 * 1024;
/// The most keys a set may hold.
pub const MAX_KEYS: usize = 32;

/// One public key of a set. Only the members the checks use are read; a private member is never accepted or kept.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// The key id a token names in its header.
    #[serde(default)]
    pub kid: String,
    /// The key type: `RSA`, `EC` or `OKP`.
    #[serde(default)]
    pub kty: String,
    /// The algorithm the key is for, when the provider says (a key stated for another algorithm is refused).
    #[serde(default)]
    pub alg: Option<String>,
    /// The intended use (`sig`), when stated; a key for encryption is never used to verify.
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    /// RSA modulus, base64url.
    #[serde(default)]
    pub n: String,
    /// RSA public exponent, base64url.
    #[serde(default)]
    pub e: String,
    /// The curve of an EC or OKP key (`P-256`, `Ed25519`).
    #[serde(default)]
    pub crv: String,
    /// The x coordinate (EC) or the public key (OKP), base64url.
    #[serde(default)]
    pub x: String,
    /// The y coordinate of an EC key, base64url.
    #[serde(default)]
    pub y: String,
}

/// A set of keys as the provider publishes it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct JwkSet {
    /// The keys.
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Parse a key set document: at most [`MAX_JWKS_BYTES`], a JSON object with a `keys` array of at most [`MAX_KEYS`] entries.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.len() > MAX_JWKS_BYTES {
            return Err(Error::Malformed);
        }
        let set: Self = serde_json::from_slice(body).map_err(|_| Error::Malformed)?;
        if set.keys.len() > MAX_KEYS {
            return Err(Error::Malformed);
        }
        Ok(set)
    }

    /// The signing key with this id, if the set has one (a key marked for another use is skipped).
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid && k.use_.as_deref().is_none_or(|u| u == "sig"))
    }
}
