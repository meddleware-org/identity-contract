//! The Rust half of the Meddleware identity contract (`docs/CONTRACT.md`): the pure verification logic the platform's two operator consoles (content-hub-service and
//! link-in-bio-service) share, so neither carries its own copy of the checks.
//!
//! Nothing here touches the network, the clock or a database: the caller fetches the discovery document and the key set, passes the current time in, and keeps the sessions. That
//! makes every rule testable with fixed vectors, and keeps this crate free of an HTTP stack. The modules:
//!
//! - [`jwk`] and [`jwt`]: key sets and signature checks with pinned algorithms (RS256, ES256, EdDSA; never `none`, never an HMAC, never one chosen by the token).
//! - [`keyset`]: the rules for a cached key set (refresh on an unknown key at most every 30 seconds, never older than an hour).
//! - [`discovery`]: the provider's discovery document, checked against the contract's section 1.
//! - [`idtoken`] and [`logout`]: the ID token of a console sign-in and the back-channel logout token (contract section 3).
//! - [`pkce`]: the one-time values of an authorization request (`state`, `nonce`, the PKCE verifier and its S256 challenge).
//! - [`authzen`]: the AuthZEN 1.0 decision request and response, and the decision cache (allow 30 s, deny 5 s, never with a context).
//! - [`session`]: session identifiers (256 random bits, only a hash stored) and the exact cookie attributes.

pub mod authzen;
pub mod discovery;
pub mod error;
pub mod idtoken;
pub mod jwk;
pub mod jwt;
pub mod keyset;
pub mod logout;
pub mod pkce;
pub mod session;
/// Throw-away keys and token signing for tests (enabled by the `testing` feature for other crates' tests; never trusted by production).
#[cfg(any(test, feature = "testing"))]
pub mod testing;
/// The throw-away RSA test key shared by the tests.
#[cfg(any(test, feature = "testing"))]
mod testkey;

pub use error::Error;
