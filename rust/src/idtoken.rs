//! The ID token of a console sign-in (OpenID Connect Core 3.1.3.7; contract section 3), verified after the code exchange.
//!
//! Checks, in order: the signature (jwt.rs, pinned algorithms); the header `typ` is absent or `JWT` (an access token, `at+jwt`, is refused); `iss` is exactly the configured issuer; `aud`
//! contains the client id and, with several audiences or an `azp`, `azp` is the client; `exp` has not passed, `iat` is not in the future and `nbf` (when present) has begun, each with a
//! bounded skew; `sub` is present; the `nonce` is the one of this authorization request (without one a replayed response would be accepted); and when assurance is required, `acr` is one of
//! the accepted values. `amr` is not required (the reference provider emits none): the assurance is `acr`.

use serde_json::Value;

use crate::error::Error;
use crate::jwk::JwkSet;
use crate::jwt::{self, CONTRACT_ALGORITHMS};

/// The clock difference tolerated, in seconds.
pub const SKEW_SECS: i64 = 60;

/// What the caller knows about the sign-in the token answers.
#[derive(Debug, Clone)]
pub struct IdOptions<'a> {
    /// The configured issuer.
    pub issuer: &'a str,
    /// This application's client id.
    pub client_id: &'a str,
    /// The `nonce` sent in the authorization request (must be non-empty).
    pub nonce: &'a str,
    /// The `acr` values that satisfy the requirement (for the consoles: `phr`); empty means none is required.
    pub accepted_acr: &'a [&'a str],
    /// The current time, Unix seconds.
    pub now: i64,
}

/// The verified identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdClaims {
    /// The subject: the provider's stable, opaque user id.
    pub subject: String,
    /// The provider session id, which a back-channel logout names (empty when the provider sent none).
    pub session_id: String,
    /// The authentication context class reached (empty when absent).
    pub acr: String,
    /// When the token expires (Unix seconds).
    pub expires_at: i64,
    /// When the person authenticated (Unix seconds), when the provider says.
    pub auth_time: Option<i64>,
    /// The preferred username, when sent (for display only, never for authorisation).
    pub username: String,
}

/// A string claim.
fn string<'a>(claims: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a str> {
    claims.get(name).and_then(Value::as_str)
}

/// An integer time claim.
fn time(claims: &serde_json::Map<String, Value>, name: &str) -> Option<i64> {
    claims.get(name).and_then(Value::as_i64)
}

/// The audiences of a token: one string or a list of strings.
pub(crate) fn audiences(claims: &serde_json::Map<String, Value>) -> Result<Vec<&str>, Error> {
    match claims.get("aud") {
        Some(Value::String(a)) => Ok(vec![a.as_str()]),
        Some(Value::Array(list)) => list.iter().map(|v| v.as_str().ok_or(Error::Claim)).collect(),
        _ => Err(Error::Claim),
    }
}

/// Verify an ID token against `keys` for the sign-in described by `o`.
pub fn verify_id_token(token: &str, keys: &JwkSet, o: &IdOptions<'_>) -> Result<IdClaims, Error> {
    let opened = jwt::open(token, keys, &CONTRACT_ALGORITHMS)?;
    // An ID token is a statement for the client, never an access token: refuse one that says it is for APIs.
    if !opened.typ.is_empty() && opened.typ != "jwt" {
        return Err(Error::Type);
    }
    let c = &opened.claims;
    if string(c, "iss") != Some(o.issuer) {
        return Err(Error::Issuer);
    }
    let subject =
        string(c, "sub").filter(|s| !s.trim().is_empty() && s.chars().count() <= 512).ok_or(Error::Claim)?.to_owned();
    let aud = audiences(c)?;
    if !aud.contains(&o.client_id) {
        return Err(Error::Audience);
    }
    // With several audiences, or an authorized party, the party must be this client.
    if (aud.len() > 1 || c.contains_key("azp")) && string(c, "azp") != Some(o.client_id) {
        return Err(Error::Audience);
    }
    let (Some(exp), Some(iat)) = (time(c, "exp"), time(c, "iat")) else { return Err(Error::Claim) };
    if o.now > exp + SKEW_SECS || iat > o.now + SKEW_SECS {
        return Err(Error::Expired);
    }
    if let Some(nbf) = c.get("nbf") {
        let nbf = nbf.as_i64().ok_or(Error::Claim)?;
        if nbf > o.now + SKEW_SECS {
            return Err(Error::Expired);
        }
    }
    // The nonce ties the token to this request; without a nonce a replayed response would be accepted.
    if o.nonce.is_empty() {
        return Err(Error::Claim);
    }
    if string(c, "nonce") != Some(o.nonce) {
        return Err(Error::Binding);
    }
    let acr = string(c, "acr").unwrap_or("").to_owned();
    if !o.accepted_acr.is_empty() && !o.accepted_acr.contains(&acr.as_str()) {
        return Err(Error::Binding);
    }
    Ok(IdClaims {
        subject,
        session_id: string(c, "sid").unwrap_or("").to_owned(),
        acr,
        expires_at: exp,
        auth_time: time(c, "auth_time"),
        username: string(c, "preferred_username").unwrap_or("").chars().take(200).collect(),
    })
}

/// Unit tests: vectors for every refusal, in both RS256 and ES256.
#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing::{Signer, Suite};

    /// The issuer the tests trust.
    const ISS: &str = "https://accounts.example.org/realms/meddleware";
    /// The client id.
    const CLIENT: &str = "hub-console";
    /// The nonce of the pretend authorization request.
    const NONCE: &str = "n-123";
    /// The pretend current time.
    const NOW: i64 = 1_800_000_000;

    /// Valid claims: right issuer, audience, nonce, `phr`, valid now.
    fn claims() -> serde_json::Value {
        json!({ "iss": ISS, "aud": CLIENT, "sub": "u-1", "sid": "s-1", "exp": NOW + 600, "iat": NOW - 5, "nonce": NONCE, "acr": "phr", "preferred_username": "op", "auth_time": NOW - 5 })
    }

    /// The options of the pretend sign-in.
    fn options() -> IdOptions<'static> {
        IdOptions { issuer: ISS, client_id: CLIENT, nonce: NONCE, accepted_acr: &["phr"], now: NOW }
    }

    /// Run a check against every suite (RS256 and ES256 signers).
    fn each(check: impl Fn(&Signer, &JwkSet)) {
        for suite in [Suite::Rs256, Suite::Es256] {
            let signer = Signer::new(suite, "k1");
            let keys = signer.jwks();
            check(&signer, &keys);
        }
    }

    /// A valid token yields the identity.
    #[test]
    fn a_valid_token_yields_the_identity() {
        each(|s, keys| {
            let id = verify_id_token(&s.sign(&claims()), keys, &options()).expect("valid");
            assert_eq!(
                id,
                IdClaims {
                    subject: "u-1".into(),
                    session_id: "s-1".into(),
                    acr: "phr".into(),
                    expires_at: NOW + 600,
                    auth_time: Some(NOW - 5),
                    username: "op".into()
                }
            );
        });
    }

    /// Each defect is refused with its reason.
    #[test]
    fn every_defect_is_refused() {
        each(|s, keys| {
            let try_with = |edit: &dyn Fn(&mut serde_json::Value)| {
                let mut c = claims();
                edit(&mut c);
                verify_id_token(&s.sign(&c), keys, &options())
            };
            assert_eq!(try_with(&|c| c["iss"] = "https://evil".into()), Err(Error::Issuer));
            assert_eq!(try_with(&|c| c["aud"] = "other".into()), Err(Error::Audience));
            assert_eq!(
                try_with(&|c| c["aud"] = json!([CLIENT, "other"])),
                Err(Error::Audience),
                "several audiences need azp"
            );
            assert!(
                try_with(&|c| {
                    c["aud"] = json!([CLIENT, "other"]);
                    c["azp"] = CLIENT.into()
                })
                .is_ok()
            );
            assert_eq!(try_with(&|c| c["azp"] = "other".into()), Err(Error::Audience));
            assert_eq!(try_with(&|c| c["exp"] = json!(NOW - 61)), Err(Error::Expired));
            assert_eq!(try_with(&|c| c["iat"] = json!(NOW + 61)), Err(Error::Expired));
            assert_eq!(try_with(&|c| c["nbf"] = json!(NOW + 61)), Err(Error::Expired));
            assert_eq!(
                try_with(&|c| {
                    c.as_object_mut().expect("object").remove("exp");
                }),
                Err(Error::Claim)
            );
            assert_eq!(try_with(&|c| c["sub"] = " ".into()), Err(Error::Claim));
            assert_eq!(try_with(&|c| c["nonce"] = "other".into()), Err(Error::Binding));
            assert_eq!(
                try_with(&|c| {
                    c.as_object_mut().expect("object").remove("nonce");
                }),
                Err(Error::Binding)
            );
            assert_eq!(
                try_with(&|c| c["acr"] = "1".into()),
                Err(Error::Binding),
                "a password-only sign-in is not enough"
            );
            assert_eq!(
                try_with(&|c| {
                    c.as_object_mut().expect("object").remove("acr");
                }),
                Err(Error::Binding)
            );
        });
    }

    /// An empty nonce in the options is a caller bug and refuses; no acr requirement accepts any acr.
    #[test]
    fn options_edge_cases() {
        each(|s, keys| {
            let token = s.sign(&claims());
            assert_eq!(verify_id_token(&token, keys, &IdOptions { nonce: "", ..options() }), Err(Error::Claim));
            assert!(verify_id_token(&token, keys, &IdOptions { accepted_acr: &[], ..options() }).is_ok());
        });
    }

    /// An access token (`at+jwt`) is not an ID token; a token with the wrong algorithm or key is refused.
    #[test]
    fn type_and_forgery_are_refused() {
        each(|s, keys| {
            assert_eq!(verify_id_token(&s.sign_with_typ(&claims(), "at+jwt"), keys, &options()), Err(Error::Type));
            assert!(verify_id_token(&s.sign_with_typ(&claims(), "JWT"), keys, &options()).is_ok());
            let other = Signer::new(Suite::Es256, "k1");
            let forged = other.sign(&claims());
            // The same key id, a different key: the signature cannot verify (or the key type does not fit).
            assert!(verify_id_token(&forged, &Signer::new(Suite::Rs256, "k1").jwks(), &options()).is_err());
            assert_eq!(verify_id_token("a.b", keys, &options()), Err(Error::Malformed));
        });
    }
}
