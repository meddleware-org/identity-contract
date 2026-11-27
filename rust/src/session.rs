//! Session identifiers and cookies (contract section 3): a 256-bit random identifier, only its SHA-256 stored server-side, and a `__Host-` cookie with the exact attributes.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};

use crate::pkce::random_token;

/// The random bytes of a session identifier (256 bits).
const ID_BYTES: usize = 32;

/// A new session identifier (for the cookie) and its hash (for the store). A new one is made at every sign-in, so an identifier planted before sign-in is useless.
pub fn new_session() -> (String, String) {
    let id = random_token(ID_BYTES);
    let hash = hash_id(&id);
    (id, hash)
}

/// The value the store keeps for an identifier: `SHA-256`, base64url. A leaked store therefore does not hold usable cookies.
pub fn hash_id(id: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, id.as_bytes()))
}

/// The `Set-Cookie` value that sets the session cookie: `__Host-` prefix (so the browser enforces `Secure`, `Path=/` and no `Domain`), `Secure`, `HttpOnly`, `SameSite=Lax`, `Max-Age` in seconds.
/// Returns `None` for a name without the prefix (a cookie of this kind must never be made without it).
pub fn set_cookie(name: &str, id: &str, max_age_secs: u64) -> Option<String> {
    name.starts_with("__Host-")
        .then(|| format!("{name}={id}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}"))
}

/// The `Set-Cookie` value that clears the cookie (same attributes, empty value, `Max-Age=0`).
pub fn clear_cookie(name: &str) -> Option<String> {
    name.starts_with("__Host-").then(|| format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"))
}

/// The value of cookie `name` in a `Cookie` request header, if present.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').filter_map(|p| p.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v)
}

/// Unit tests.
#[cfg(test)]
mod tests {
    use super::*;

    /// An identifier is 43 characters (256 bits), its hash differs, and two sessions never share either.
    #[test]
    fn identifiers_are_long_random_and_hashed() {
        let (id, hash) = new_session();
        assert_eq!(id.len(), 43);
        assert_eq!(hash, hash_id(&id));
        assert_ne!(id, hash);
        assert_ne!(new_session().0, id);
    }

    /// The cookie has exactly the contract's attributes, and only a `__Host-` name is allowed.
    #[test]
    fn the_cookie_has_the_exact_attributes() {
        assert_eq!(
            set_cookie("__Host-hub-admin", "abc", 43200).as_deref(),
            Some("__Host-hub-admin=abc; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=43200")
        );
        assert_eq!(
            clear_cookie("__Host-hub-admin").as_deref(),
            Some("__Host-hub-admin=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
        );
        assert_eq!(set_cookie("hub-admin", "abc", 1), None);
        assert_eq!(clear_cookie("hub-admin"), None);
    }

    /// A cookie is found by exact name among several.
    #[test]
    fn a_cookie_is_found_by_exact_name() {
        assert_eq!(cookie_value("a=1; __Host-x=two; b=3", "__Host-x"), Some("two"));
        assert_eq!(cookie_value("a=1; __Host-xy=two", "__Host-x"), None);
        assert_eq!(cookie_value("", "a"), None);
    }
}
