//! The one-time values of an authorization request: `state`, `nonce`, and the PKCE (RFC 7636) verifier with its S256 challenge. All come from the operating system's random source (ring).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};

/// The random bytes in a PKCE verifier (RFC 7636 asks for 32 octets of entropy: a 43-character verifier).
const VERIFIER_BYTES: usize = 32;
/// The random bytes in `state` and `nonce`.
const TOKEN_BYTES: usize = 24;

/// `n` random bytes from the operating system, base64url without padding.
pub fn random_token(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    // The system source cannot fail in practice; if it ever does, signing in must stop, not continue with a predictable value.
    SystemRandom::new().fill(&mut bytes).expect("the system random source failed");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The S256 challenge of a verifier: `BASE64URL(SHA256(verifier))`.
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()))
}

/// The values of one authorization request.
#[derive(Debug, Clone)]
pub struct Pending {
    /// Binds the response to this browser's request (checked against the pending login before anything else).
    pub state: String,
    /// Binds the ID token to this request.
    pub nonce: String,
    /// The PKCE verifier, kept server-side and sent only in the token request.
    pub verifier: String,
}

impl Pending {
    /// Fresh values for one login.
    pub fn new() -> Self {
        Self {
            state: random_token(TOKEN_BYTES),
            nonce: random_token(TOKEN_BYTES),
            verifier: random_token(VERIFIER_BYTES),
        }
    }

    /// The challenge to send in the authorization request (method S256).
    pub fn challenge(&self) -> String {
        challenge(&self.verifier)
    }
}

impl Default for Pending {
    /// Fresh values, as [`Pending::new`].
    fn default() -> Self {
        Self::new()
    }
}

/// Unit tests: RFC 7636's own vector, and the shape of the random values.
#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B: this verifier has this challenge.
    #[test]
    fn rfc_7636_vector() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    /// The verifier is 43 characters of the unreserved alphabet, and no two logins share any value.
    #[test]
    fn values_are_random_and_well_formed() {
        let (a, b) = (Pending::new(), Pending::new());
        assert_eq!(a.verifier.len(), 43);
        assert!(a.verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(
            (a.state.clone(), a.nonce.clone(), a.verifier.clone()),
            (b.state.clone(), b.nonce.clone(), b.verifier.clone())
        );
        assert_ne!(a.state, a.nonce);
        assert_eq!(a.challenge(), challenge(&a.verifier));
    }
}
