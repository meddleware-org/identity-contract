//! The ways a check refuses, named by the rule that refused (never by what the token held).

/// Why a token, a document or a decision was refused. The variants name the check, not the content: a message never carries a claim value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The input is not shaped as the format requires (segments, base64, JSON).
    #[error("malformed")]
    Malformed,
    /// The algorithm is not one the contract allows, or does not fit the key.
    #[error("algorithm not allowed")]
    Algorithm,
    /// No usable key: unknown `kid`, an unusable key, or a key of the wrong type.
    #[error("no usable signing key")]
    Key,
    /// The signature does not verify.
    #[error("bad signature")]
    Signature,
    /// The header `typ` is not the one this kind of token must have.
    #[error("wrong token type")]
    Type,
    /// The issuer is not the configured one.
    #[error("wrong issuer")]
    Issuer,
    /// The audience does not contain the client id, or `azp` is not the client.
    #[error("wrong audience")]
    Audience,
    /// The token has expired, was issued in the future, or is not valid yet.
    #[error("not valid at this time")]
    Expired,
    /// A required claim is missing or unusable.
    #[error("claim missing or unusable")]
    Claim,
    /// The token is not bound to this request (nonce) or does not carry the required assurance (acr).
    #[error("not bound or not assured")]
    Binding,
    /// A logout token was seen before.
    #[error("replayed")]
    Replay,
    /// The discovery document breaks the contract.
    #[error("discovery document refused")]
    Discovery,
}

/// A decision could not be obtained (the policy decision point is unreachable, slow, or answered with something that is not a decision): the caller answers 503 and never allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no decision")]
pub struct Unavailable;
