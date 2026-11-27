//! AuthZEN 1.0 Access Evaluation (contract section 4): the request body, the answer's reading, and the decision cache. The HTTP call itself is the caller's (it already has an HTTP client).
//!
//! Object-level decisions come from the policy decision point (OpenFGA), never from token claims. The rules this module holds: only a clear `decision: true` or `false` with HTTP 200 is an
//! answer, anything else is [`Unavailable`] (the caller answers 503, never allows); an allow is cached at most 30 seconds, a deny at most 5, and a request that carries a `context` is never cached.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;

use crate::error::Unavailable;

/// The longest an allowed decision is cached, in seconds.
pub const MAX_ALLOW_TTL_SECS: i64 = 30;
/// The longest a denied decision is cached, in seconds.
pub const MAX_DENY_TTL_SECS: i64 = 5;
/// The most decisions the cache holds.
const CAPACITY: usize = 4096;
/// The largest decision response that is read.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A subject or a resource: a type and an id as the policy model knows them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Entity {
    /// The entity type (`user`, `console`, `registry`).
    #[serde(rename = "type")]
    pub kind: String,
    /// The entity id.
    pub id: String,
}

/// The action: its name is the relation of the policy model.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Action {
    /// The action name.
    pub name: String,
}

/// One Access Evaluation request.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Request {
    /// Who asks.
    pub subject: Entity,
    /// What the action is on.
    pub resource: Entity,
    /// What is attempted.
    pub action: Action,
    /// Optional extra input for the policy; a request that carries one is never cached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

impl Request {
    /// A request without a context.
    pub fn new(subject: (&str, &str), resource: (&str, &str), action: &str) -> Self {
        Self {
            subject: Entity { kind: subject.0.into(), id: subject.1.into() },
            resource: Entity { kind: resource.0.into(), id: resource.1.into() },
            action: Action { name: action.into() },
            context: None,
        }
    }

    /// The JSON body to POST to `<base>/access/v1/evaluation`.
    pub fn body(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// The cache key, or `None` when the request carries a context (such a request is never cached).
    fn key(&self) -> Option<String> {
        self.context.is_none().then(|| {
            format!(
                "{}:{}|{}:{}|{}",
                self.subject.kind, self.subject.id, self.resource.kind, self.resource.id, self.action.name
            )
        })
    }
}

/// Read a decision response: HTTP 200 with a JSON object whose `decision` is a boolean. Anything else (an error status, a body that is not a decision, a decision that is not a boolean) is no answer.
pub fn parse_decision(status: u16, body: &[u8]) -> Result<bool, Unavailable> {
    if status != 200 || body.len() > MAX_RESPONSE_BYTES {
        return Err(Unavailable);
    }
    let v: Value = serde_json::from_slice(body).map_err(|_| Unavailable)?;
    v.get("decision").and_then(Value::as_bool).ok_or(Unavailable)
}

/// A short cache of decisions.
#[derive(Debug, Default)]
pub struct DecisionCache {
    /// Key to (decision, expiry in Unix seconds).
    entries: HashMap<String, (bool, i64)>,
}

impl DecisionCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh cached decision for the request, if there is one.
    pub fn get(&self, r: &Request, now: i64) -> Option<bool> {
        let (decision, expires) = *self.entries.get(&r.key()?)?;
        (now < expires).then_some(decision)
    }

    /// Remember a decision for the contract's time (allow 30 s, deny 5 s); a request with a context is not stored.
    pub fn put(&mut self, r: &Request, decision: bool, now: i64) {
        let Some(key) = r.key() else { return };
        // Stale entries go first; a full cache does not grow (it simply stops caching until entries expire).
        self.entries.retain(|_, (_, t)| *t > now);
        if self.entries.len() >= CAPACITY {
            return;
        }
        let ttl = if decision { MAX_ALLOW_TTL_SECS } else { MAX_DENY_TTL_SECS };
        self.entries.insert(key, (decision, now + ttl));
    }
}

/// Unit tests.
#[cfg(test)]
mod tests {
    use super::*;

    /// A request for the tests.
    fn request() -> Request {
        Request::new(("user", "u-1"), ("console", "content-hub"), "member")
    }

    /// The body is the AuthZEN shape.
    #[test]
    fn the_body_has_the_authzen_shape() {
        let v: Value = serde_json::from_slice(&request().body()).expect("json");
        assert_eq!(
            v,
            serde_json::json!({ "subject": { "type": "user", "id": "u-1" }, "resource": { "type": "console", "id": "content-hub" }, "action": { "name": "member" } })
        );
    }

    /// Only a clear boolean with HTTP 200 is an answer.
    #[test]
    fn only_a_clear_decision_is_an_answer() {
        assert_eq!(parse_decision(200, br#"{"decision":true}"#), Ok(true));
        assert_eq!(parse_decision(200, br#"{"decision":false}"#), Ok(false));
        for (status, body) in [
            (200, &br#"{"decision":"true"}"#[..]),
            (200, b"{}"),
            (200, b"not json"),
            (500, br#"{"decision":true}"#),
            (403, br#"{"decision":true}"#),
            (200, br#"{"decision":1}"#),
        ] {
            assert_eq!(parse_decision(status, body), Err(Unavailable), "{status} {}", String::from_utf8_lossy(body));
        }
        assert_eq!(parse_decision(200, &vec![b' '; MAX_RESPONSE_BYTES + 1]), Err(Unavailable));
    }

    /// An allow lives 30 seconds, a deny 5, and a request with a context is never cached.
    #[test]
    fn the_cache_follows_the_contract() {
        let mut c = DecisionCache::new();
        let r = request();
        assert_eq!(c.get(&r, 100), None);
        c.put(&r, true, 100);
        assert_eq!(c.get(&r, 129), Some(true));
        assert_eq!(c.get(&r, 130), None);
        c.put(&r, false, 200);
        assert_eq!(c.get(&r, 204), Some(false));
        assert_eq!(c.get(&r, 205), None);
        let mut with_context = r.clone();
        with_context.context = Some(serde_json::json!({ "ip": "1.2.3.4" }));
        c.put(&with_context, true, 300);
        assert_eq!(c.get(&with_context, 301), None);
    }
}
