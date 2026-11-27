//! The provider's discovery document (OpenID Connect Discovery 1.0, RFC 8414), checked against contract section 1 for a console: the fields a sign-in needs, with the values the contract states.

use serde::Deserialize;

use crate::error::Error;

/// The largest discovery document that is read.
pub const MAX_BYTES: usize = 64 * 1024;

/// The fields of the discovery document the consoles use.
#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    /// The issuer: must equal the configured one exactly.
    pub issuer: String,
    /// Where the browser is sent to sign in.
    pub authorization_endpoint: String,
    /// Where the code is exchanged (server to server).
    pub token_endpoint: String,
    /// Where the signing keys are published.
    pub jwks_uri: String,
    /// Where RP-Initiated Logout is requested.
    pub end_session_endpoint: String,
    /// The PKCE methods the provider advertises: S256 must be among them (a client that refuses `plain` is a behaviour the conformance suite proves, not this list).
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// Authorization responses carry `iss` (RFC 9207).
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    /// The provider sends back-channel logout tokens.
    #[serde(default)]
    pub backchannel_logout_supported: bool,
}

impl Discovery {
    /// Parse and check a discovery document for `issuer`. A non-`https` issuer or endpoint is refused unless `allow_insecure` (development only).
    pub fn parse(body: &[u8], issuer: &str, allow_insecure: bool) -> Result<Self, Error> {
        if body.len() > MAX_BYTES || !valid_url(issuer, allow_insecure) {
            return Err(Error::Discovery);
        }
        let d: Self = serde_json::from_slice(body).map_err(|_| Error::Discovery)?;
        // Nothing but the configured issuer is trusted to name itself.
        if d.issuer != issuer {
            return Err(Error::Discovery);
        }
        if !d.code_challenge_methods_supported.iter().any(|m| m == "S256")
            || !d.authorization_response_iss_parameter_supported
            || !d.backchannel_logout_supported
        {
            return Err(Error::Discovery);
        }
        for url in [&d.authorization_endpoint, &d.token_endpoint, &d.jwks_uri, &d.end_session_endpoint] {
            if !valid_url(url, allow_insecure) {
                return Err(Error::Discovery);
            }
        }
        Ok(d)
    }
}

/// An absolute `https` URL (or `http` when insecure is allowed) with a host and no fragment.
fn valid_url(url: &str, allow_insecure: bool) -> bool {
    let rest = url.strip_prefix("https://").or_else(|| allow_insecure.then(|| url.strip_prefix("http://")).flatten());
    rest.is_some_and(|r| !r.is_empty() && !r.starts_with('/') && !r.contains('#') && !r.contains(char::is_whitespace))
}

/// Unit tests for the discovery checks.
#[cfg(test)]
mod tests {
    use super::*;

    /// The issuer the tests use.
    const ISS: &str = "https://accounts.example.org/realms/meddleware";

    /// A document that meets the contract.
    fn good() -> serde_json::Value {
        serde_json::json!({
            "issuer": ISS, "authorization_endpoint": format!("{ISS}/protocol/openid-connect/auth"), "token_endpoint": format!("{ISS}/protocol/openid-connect/token"),
            "jwks_uri": format!("{ISS}/protocol/openid-connect/certs"), "end_session_endpoint": format!("{ISS}/protocol/openid-connect/logout"),
            "code_challenge_methods_supported": ["plain", "S256"], "authorization_response_iss_parameter_supported": true, "backchannel_logout_supported": true
        })
    }

    /// Parse a modified copy of the good document.
    fn parse_with(edit: impl FnOnce(&mut serde_json::Value), issuer: &str, insecure: bool) -> Result<Discovery, Error> {
        let mut v = good();
        edit(&mut v);
        Discovery::parse(v.to_string().as_bytes(), issuer, insecure)
    }

    /// The good document passes, and `plain` next to S256 is accepted (the provider lists it realm-wide).
    #[test]
    fn a_good_document_passes() {
        assert!(parse_with(|_| {}, ISS, false).is_ok());
    }

    /// Each rule of contract section 1 refuses on its own.
    #[test]
    fn each_rule_refuses() {
        assert_eq!(parse_with(|_| {}, "https://other.example.org", false).unwrap_err(), Error::Discovery);
        assert_eq!(
            parse_with(|v| v["issuer"] = "https://evil.example".into(), ISS, false).unwrap_err(),
            Error::Discovery
        );
        assert_eq!(
            parse_with(|v| v["code_challenge_methods_supported"] = serde_json::json!(["plain"]), ISS, false)
                .unwrap_err(),
            Error::Discovery
        );
        assert_eq!(
            parse_with(|v| v["authorization_response_iss_parameter_supported"] = false.into(), ISS, false).unwrap_err(),
            Error::Discovery
        );
        assert_eq!(
            parse_with(|v| v["backchannel_logout_supported"] = false.into(), ISS, false).unwrap_err(),
            Error::Discovery
        );
        assert_eq!(
            parse_with(
                |v| {
                    v.as_object_mut().expect("object").remove("jwks_uri");
                },
                ISS,
                false
            )
            .unwrap_err(),
            Error::Discovery
        );
        assert_eq!(
            parse_with(|v| v["token_endpoint"] = "http://accounts.example.org/token".into(), ISS, false).unwrap_err(),
            Error::Discovery
        );
        assert_eq!(Discovery::parse(b"{", ISS, false).unwrap_err(), Error::Discovery);
    }

    /// A plain-http issuer is refused unless development mode allows it.
    #[test]
    fn http_only_in_development() {
        let http = "http://localhost:8080/realms/meddleware";
        let doc = |v: &mut serde_json::Value| {
            for k in ["authorization_endpoint", "token_endpoint", "jwks_uri", "end_session_endpoint"] {
                v[k] = format!("{http}/x").into();
            }
            v["issuer"] = http.into();
        };
        assert_eq!(parse_with(doc, http, false).unwrap_err(), Error::Discovery);
        assert!(parse_with(doc, http, true).is_ok());
    }
}
