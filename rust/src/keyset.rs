//! The rules for a cached key set, kept apart from any HTTP code: the caller asks [`KeyCache::should_refresh`], fetches when told to, and hands the result to [`KeyCache::replace`]
//! (or tells the cache the fetch [`KeyCache::failed`]).
//!
//! Contract section 1: an unknown key id triggers one refresh, and no attempt follows another within 30 seconds whatever the tokens ask for (so a flood of tokens with random key ids
//! cannot make the service hammer the provider); a set is never trusted for more than an hour; a refresh that fails keeps the old keys (until they are an hour old).

use crate::jwk::JwkSet;

/// The shortest time between two fetch attempts.
pub const MIN_REFRESH_SECS: i64 = 30;
/// The longest a fetched set is trusted.
pub const MAX_AGE_SECS: i64 = 3600;

/// A key set, when it was fetched, and when a fetch was last attempted.
#[derive(Debug, Clone, Default)]
pub struct KeyCache {
    /// The keys, or `None` before the first successful fetch.
    set: Option<JwkSet>,
    /// When the set was fetched (Unix seconds): its age counts from here.
    fetched_at: i64,
    /// When a fetch was last attempted, successful or not (the 30-second wait counts from here); `None` before the first attempt.
    attempted_at: Option<i64>,
}

impl KeyCache {
    /// An empty cache: the first use needs a fetch.
    pub fn new() -> Self {
        Self::default()
    }

    /// The keys to verify with: the cached set while it is younger than an hour, otherwise none (the caller must fetch first).
    pub fn keys(&self, now: i64) -> Option<&JwkSet> {
        self.set.as_ref().filter(|_| now - self.fetched_at < MAX_AGE_SECS)
    }

    /// Whether to fetch the key set now. `kid_known` says whether the token's key id is in the cached set.
    pub fn should_refresh(&self, now: i64, kid_known: bool) -> bool {
        // No attempt follows another within the minimum wait, whatever the reason for wanting one.
        if self.attempted_at.is_some_and(|a| now - a < MIN_REFRESH_SECS) {
            return false;
        }
        match &self.set {
            // Never fetched: fetch.
            None => true,
            // Too old to trust: fetch whatever the token says.
            Some(_) if now - self.fetched_at >= MAX_AGE_SECS => true,
            // Young enough: only a key id the set does not have asks for a fetch.
            Some(_) => !kid_known,
        }
    }

    /// Store a freshly fetched set.
    pub fn replace(&mut self, set: JwkSet, now: i64) {
        self.set = Some(set);
        self.fetched_at = now;
        self.attempted_at = Some(now);
    }

    /// Record a failed fetch: the old keys stay (while they are young enough) and the next attempt waits the minimum time.
    pub fn failed(&mut self, now: i64) {
        self.attempted_at = Some(now);
    }
}

/// Unit tests for the refresh rules.
#[cfg(test)]
mod tests {
    use super::*;

    /// A set with one key id, to make the cache non-empty.
    fn set() -> JwkSet {
        JwkSet::parse(br#"{"keys":[{"kid":"a","kty":"RSA","n":"AQAB","e":"AQAB"}]}"#).expect("set")
    }

    /// An empty cache wants a fetch; after one, a known key id does not; an unknown one does, but not within 30 seconds.
    #[test]
    fn refresh_rules() {
        let mut c = KeyCache::new();
        assert!(c.should_refresh(1000, true));
        c.replace(set(), 1000);
        assert!(!c.should_refresh(1001, true));
        // An unknown key id right after a fetch: refused (the 30-second wait).
        assert!(!c.should_refresh(1010, false));
        assert!(c.should_refresh(1030, false));
        // A failed attempt restarts the wait but keeps the keys.
        c.failed(1030);
        assert!(!c.should_refresh(1040, false));
        assert!(c.keys(1040).is_some());
        assert!(c.should_refresh(1060, false));
    }

    /// A set older than an hour is not trusted and a fetch is wanted even for a known key id.
    #[test]
    fn a_set_older_than_an_hour_is_not_trusted() {
        let mut c = KeyCache::new();
        c.replace(set(), 0);
        assert!(c.keys(MAX_AGE_SECS - 1).is_some());
        assert!(c.keys(MAX_AGE_SECS).is_none());
        assert!(c.should_refresh(MAX_AGE_SECS, true));
        // But never faster than the minimum wait after a failed attempt.
        c.failed(MAX_AGE_SECS);
        assert!(!c.should_refresh(MAX_AGE_SECS + 5, true));
    }
}
