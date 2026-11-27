//! The back-channel logout token (OpenID Connect Back-Channel Logout 1.0, section 2.6; contract section 3): the provider's request to end a session, which the console acts on once.
//!
//! Checks: the signature; the header `typ` is `logout+jwt`; `iss` is the configured issuer; `aud` contains the client id; `iat` is recent and `exp` has not passed; there is no `nonce` (a token
//! with one is an ID token in disguise); the `events` claim has the back-channel logout member; at least one of `sub` and `sid` is present; `jti` is present and has not been seen. A missing
//! replay cache is not an option here: this crate keeps one ([`ReplayCache`]).

use std::collections::HashMap;

use serde_json::Value;

use crate::error::Error;
use crate::idtoken::{SKEW_SECS, audiences};
use crate::jwk::JwkSet;
use crate::jwt::{self, CONTRACT_ALGORITHMS};

/// The event member a logout token must carry.
const EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
/// The most identifiers the replay cache remembers.
const REPLAY_CAPACITY: usize = 4096;

/// What the caller knows about its own configuration.
#[derive(Debug, Clone)]
pub struct LogoutOptions<'a> {
    /// The configured issuer.
    pub issuer: &'a str,
    /// This application's client id.
    pub client_id: &'a str,
    /// The current time, Unix seconds.
    pub now: i64,
}

/// Which session to end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutClaims {
    /// The subject (empty when the token named only a session).
    pub subject: String,
    /// The provider session id (empty when the token named only a subject: then every session of the subject ends).
    pub session_id: String,
}

/// The identifiers of logout tokens already acted on, each remembered until the token would have expired, so a replayed token is refused.
#[derive(Debug, Default)]
pub struct ReplayCache {
    /// `iss|jti` to the time after which the entry can be forgotten.
    seen: HashMap<String, i64>,
}

impl ReplayCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `key` until `until`; `true` when it was already there (a replay) or when the cache is full of unexpired entries (refuse rather than forget).
    fn seen(&mut self, key: String, until: i64, now: i64) -> bool {
        self.seen.retain(|_, t| *t > now);
        if self.seen.contains_key(&key) || self.seen.len() >= REPLAY_CAPACITY {
            return true;
        }
        self.seen.insert(key, until);
        false
    }
}

/// Verify a logout token. The token is acted on once: a second submission of the same `jti` is [`Error::Replay`].
pub fn verify_logout_token(
    token: &str,
    keys: &JwkSet,
    o: &LogoutOptions<'_>,
    replay: &mut ReplayCache,
) -> Result<LogoutClaims, Error> {
    let opened = jwt::open(token, keys, &CONTRACT_ALGORITHMS)?;
    if opened.typ != "logout+jwt" {
        return Err(Error::Type);
    }
    let c = &opened.claims;
    if c.get("iss").and_then(Value::as_str) != Some(o.issuer) {
        return Err(Error::Issuer);
    }
    if !audiences(c)?.contains(&o.client_id) {
        return Err(Error::Audience);
    }
    let (Some(iat), Some(exp)) = (c.get("iat").and_then(Value::as_i64), c.get("exp").and_then(Value::as_i64)) else {
        return Err(Error::Claim);
    };
    if o.now > exp + SKEW_SECS || iat > o.now + SKEW_SECS {
        return Err(Error::Expired);
    }
    // A logout token never carries a nonce: one that does is an ID token in disguise.
    if c.contains_key("nonce") {
        return Err(Error::Claim);
    }
    if !c.get("events").and_then(Value::as_object).is_some_and(|e| e.contains_key(EVENT)) {
        return Err(Error::Claim);
    }
    let text = |name: &str| c.get(name).and_then(Value::as_str).unwrap_or("").to_owned();
    let (subject, session_id) = (text("sub"), text("sid"));
    if subject.is_empty() && session_id.is_empty() {
        return Err(Error::Claim);
    }
    let jti = text("jti");
    if jti.is_empty() {
        return Err(Error::Claim);
    }
    if replay.seen(format!("{}|{jti}", o.issuer), exp + SKEW_SECS, o.now) {
        return Err(Error::Replay);
    }
    Ok(LogoutClaims { subject, session_id })
}

/// Unit tests for the logout token.
#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing::{Signer, Suite};

    /// The issuer the tests trust.
    const ISS: &str = "https://accounts.example.org/realms/meddleware";
    /// The client id.
    const CLIENT: &str = "hub-console";
    /// The pretend current time.
    const NOW: i64 = 1_800_000_000;

    /// A valid logout token's claims.
    fn claims() -> serde_json::Value {
        json!({ "iss": ISS, "aud": CLIENT, "iat": NOW - 1, "exp": NOW + 120, "jti": "j-1", "sid": "s-1", "sub": "u-1", "events": { EVENT: {} } })
    }

    /// The options of the tests.
    fn options() -> LogoutOptions<'static> {
        LogoutOptions { issuer: ISS, client_id: CLIENT, now: NOW }
    }

    /// A valid token is accepted once and refused as a replay the second time.
    #[test]
    fn accepted_once() {
        for suite in [Suite::Rs256, Suite::Es256] {
            let s = Signer::new(suite, "k1");
            let keys = s.jwks();
            let mut replay = ReplayCache::new();
            let token = s.sign_with_typ(&claims(), "logout+jwt");
            assert_eq!(
                verify_logout_token(&token, &keys, &options(), &mut replay),
                Ok(LogoutClaims { subject: "u-1".into(), session_id: "s-1".into() })
            );
            assert_eq!(verify_logout_token(&token, &keys, &options(), &mut replay), Err(Error::Replay));
        }
    }

    /// Each defect is refused with its reason.
    #[test]
    fn every_defect_is_refused() {
        let s = Signer::new(Suite::Es256, "k1");
        let keys = s.jwks();
        let try_with = |typ: &str, edit: &dyn Fn(&mut serde_json::Value)| {
            let mut c = claims();
            edit(&mut c);
            verify_logout_token(&s.sign_with_typ(&c, typ), &keys, &options(), &mut ReplayCache::new())
        };
        assert_eq!(try_with("JWT", &|_| {}), Err(Error::Type), "an ID token is not a logout token");
        assert_eq!(try_with("logout+jwt", &|c| c["iss"] = "https://evil".into()), Err(Error::Issuer));
        assert_eq!(try_with("logout+jwt", &|c| c["aud"] = "other".into()), Err(Error::Audience));
        assert_eq!(try_with("logout+jwt", &|c| c["exp"] = json!(NOW - 61)), Err(Error::Expired));
        assert_eq!(try_with("logout+jwt", &|c| c["nonce"] = "n".into()), Err(Error::Claim));
        assert_eq!(
            try_with("logout+jwt", &|c| {
                c.as_object_mut().expect("object").remove("events");
            }),
            Err(Error::Claim)
        );
        assert_eq!(
            try_with("logout+jwt", &|c| {
                let o = c.as_object_mut().expect("object");
                o.remove("sub");
                o.remove("sid");
            }),
            Err(Error::Claim)
        );
        assert_eq!(
            try_with("logout+jwt", &|c| {
                c.as_object_mut().expect("object").remove("jti");
            }),
            Err(Error::Claim)
        );
        assert!(
            try_with("logout+jwt", &|c| {
                c.as_object_mut().expect("object").remove("sub");
            })
            .is_ok(),
            "a session id alone is enough"
        );
    }

    /// A full replay cache refuses instead of forgetting; expired entries are dropped.
    #[test]
    fn the_replay_cache_is_bounded() {
        let mut cache = ReplayCache::new();
        for i in 0..REPLAY_CAPACITY {
            assert!(!cache.seen(format!("k{i}"), NOW + 100, NOW));
        }
        assert!(cache.seen("one-more".into(), NOW + 100, NOW), "full: refuse");
        assert!(!cache.seen("later".into(), NOW + 500, NOW + 200), "the old entries have expired");
    }
}
