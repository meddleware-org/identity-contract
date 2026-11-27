//! Throw-away keys and token signing for tests: an RSA key (the shared test key) and a freshly generated P-256 key. Nothing signed here is trusted by any production key set.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

use crate::jwk::{Jwk, JwkSet};
use crate::testkey::{TEST_KEY_E, TEST_KEY_N, TEST_KEY_PKCS8_B64};

/// Which algorithm a [`Signer`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// RS256 with the shared test key.
    Rs256,
    /// ES256 with a key generated for this signer.
    Es256,
}

/// A signer: a key, its id, and the key set that holds its public half.
pub struct Signer {
    /// The algorithm.
    suite: Suite,
    /// The key id.
    kid: String,
    /// The ES256 key pair (for [`Suite::Es256`]).
    ec: Option<EcdsaKeyPair>,
}

impl Signer {
    /// A signer for `suite` under the key id `kid`.
    pub fn new(suite: Suite, kid: &str) -> Self {
        let ec = (suite == Suite::Es256).then(|| {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("generate");
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).expect("pkcs8")
        });
        Self { suite, kid: kid.into(), ec }
    }

    /// The key set holding this signer's public key.
    pub fn jwks(&self) -> JwkSet {
        let jwk = match (&self.suite, &self.ec) {
            (Suite::Rs256, _) => Jwk {
                kid: self.kid.clone(),
                kty: "RSA".into(),
                alg: Some("RS256".into()),
                use_: Some("sig".into()),
                n: TEST_KEY_N.into(),
                e: TEST_KEY_E.into(),
                crv: String::new(),
                x: String::new(),
                y: String::new(),
            },
            (Suite::Es256, Some(ec)) => {
                // The uncompressed point: 0x04 || x || y.
                let point = ec.public_key().as_ref();
                Jwk {
                    kid: self.kid.clone(),
                    kty: "EC".into(),
                    alg: Some("ES256".into()),
                    use_: Some("sig".into()),
                    n: String::new(),
                    e: String::new(),
                    crv: "P-256".into(),
                    x: URL_SAFE_NO_PAD.encode(&point[1..33]),
                    y: URL_SAFE_NO_PAD.encode(&point[33..65]),
                }
            }
            (Suite::Es256, None) => unreachable!("an ES256 signer always has a key"),
        };
        JwkSet { keys: vec![jwk] }
    }

    /// Sign `claims` with a header of this signer's algorithm and key id and the given `typ`.
    pub fn sign_with_typ(&self, claims: &serde_json::Value, typ: &str) -> String {
        let alg = if self.suite == Suite::Rs256 { "RS256" } else { "ES256" };
        self.sign_header(&serde_json::json!({ "alg": alg, "kid": self.kid, "typ": typ }), claims)
    }

    /// Sign `claims` as a plain `JWT`.
    pub fn sign(&self, claims: &serde_json::Value) -> String {
        self.sign_with_typ(claims, "JWT")
    }

    /// Sign `claims` under an arbitrary header (to build tokens whose header lies about the algorithm); the signature is made with this signer's real key.
    pub fn sign_header(&self, header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let input =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
        let sig = match (&self.suite, &self.ec) {
            (Suite::Rs256, _) => {
                let der = STANDARD.decode(TEST_KEY_PKCS8_B64).expect("test key");
                let key = RsaKeyPair::from_pkcs8(&der).expect("pkcs8");
                let mut sig = vec![0; key.public().modulus_len()];
                key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut sig).expect("sign");
                sig
            }
            (Suite::Es256, Some(ec)) => {
                ec.sign(&SystemRandom::new(), input.as_bytes()).expect("sign").as_ref().to_vec()
            }
            (Suite::Es256, None) => unreachable!("an ES256 signer always has a key"),
        };
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }
}
