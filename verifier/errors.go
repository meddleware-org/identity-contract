package verifier

import "errors"

// Code names why a credential or a document was refused. It is for the service's log and for tests; it is never sent to the caller.
type Code string

// The codes. Each check has its own, so a log line says which check refused without repeating any of the token.
const (
	// CodeMalformed: the token or document is not well-formed (not three parts, bad base64url, bad JSON, wrong types).
	CodeMalformed Code = "malformed"
	// CodeAlgorithm: the algorithm is not on the pinned allow-list (never none, never an HMAC, never one taken from the token).
	CodeAlgorithm Code = "algorithm"
	// CodeType: the `typ` header is not the one this token must carry (at+jwt or dpop+jwt).
	CodeType Code = "type"
	// CodeKey: no key could be found or used for the token (unknown kid, a key of the wrong type, a refused JWKS).
	CodeKey Code = "key"
	// CodeSignature: the signature does not verify.
	CodeSignature Code = "signature"
	// CodeIssuer: the issuer is not the configured one.
	CodeIssuer Code = "issuer"
	// CodeAudience: the audience does not contain this resource server's audience.
	CodeAudience Code = "audience"
	// CodeExpired: the token is expired, not yet valid, issued in the future or lives longer than the contract allows.
	CodeExpired Code = "expired"
	// CodeClaim: a required claim is missing or has the wrong shape.
	CodeClaim Code = "claim"
	// CodeReplay: a DPoP proof (or its jti) was already seen.
	CodeReplay Code = "replay"
	// CodeBinding: the DPoP proof does not match the request or the token (htm, htu, ath, cnf.jkt, nonce).
	CodeBinding Code = "binding"
	// CodeDiscovery: the discovery document breaks a MUST of the contract.
	CodeDiscovery Code = "discovery"
)

// Error is the one error type of the package. Its text is only the Code, so wrapping it into a log line or a response cannot leak a claim.
type Error struct {
	// Code is the check that refused.
	Code Code
}

// Error returns the code, and nothing else.
func (e *Error) Error() string { return "identity: " + string(e.Code) }

// newError makes the refusal for a code.
func newError(c Code) error { return &Error{Code: c} }

// CodeOf returns the code of a verifier error, or "" when err is not one.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
