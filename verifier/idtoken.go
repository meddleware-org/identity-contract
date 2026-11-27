// ID-token and logout-token verification for a console's backend (contract section 3): the checks a relying party makes after the
// authorization-code exchange, and when the provider calls its back-channel logout endpoint.

package verifier

import (
	"context"
	"strings"
	"time"
)

// backchannelEvent is the member of a logout token's `events` claim that marks it as a back-channel logout token.
const backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"

// IDOptions configure ID-token verification.
type IDOptions struct {
	// Issuer is the configured issuer URL.
	Issuer string
	// ClientID is the console backend's client id; the token's `aud` must contain it.
	ClientID string
	// Nonce is the nonce the backend sent in the authorization request; the token must echo it exactly. It is required: a code flow without a nonce is refused.
	Nonce string
	// Keys supplies the verification keys.
	Keys *KeySet
	// Algorithms narrows the contract's allow-list; empty means ES256, EdDSA and RS256.
	Algorithms []Algorithm
	// AcceptedACR lists the `acr` values that count as the platform's phishing-resistant level; when non-empty the token's `acr` must be one of them. The strings the reference
	// provider emits are fixed by the spike (FU-0182) and written into the contract; they are configuration here, not guesses.
	AcceptedACR []string
	// RequiredAMR lists `amr` values (RFC 8176) that must all be present, for example a hardware-key value together with user verification.
	RequiredAMR []string
	// Skew is the clock tolerance; zero means 30 seconds, capped at MaxSkew.
	Skew time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// IDClaims are the verified claims of an ID token.
type IDClaims struct {
	// Subject is `sub`.
	Subject string
	// Audience is `aud` as a list.
	Audience []string
	// SessionID is `sid`, the provider's session id, which a back-channel logout names; empty when the provider sends none.
	SessionID string
	// ACR is the authentication context class reference the provider reports.
	ACR string
	// AMR lists the authentication methods (RFC 8176).
	AMR []string
	// Expiry is `exp`.
	Expiry time.Time
	// Raw holds every claim.
	Raw map[string]any
}

// openSigned parses a token and checks its algorithm, key and signature, with the typ check left to the caller. It returns the parsed token.
func openSigned(ctx context.Context, token string, keys *KeySet, algs []Algorithm) (*parsed, error) {
	p, err := parse(token)
	if err != nil {
		return nil, err
	}
	if len(algs) == 0 {
		algs = contractAlgorithms
	} else {
		algs = narrow(algs)
	}
	alg, ok := allowed(p.hdr.Alg, algs)
	if !ok {
		return nil, newError(CodeAlgorithm)
	}
	key, err := keys.Key(ctx, p.hdr.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(alg, key, p.signingInput, p.sig); err != nil {
		return nil, err
	}
	return p, nil
}

// effectiveTime returns the clock reading and the skew to use (30 seconds by default, never more than MaxSkew).
func effectiveTime(now func() time.Time, skew time.Duration) (time.Time, time.Duration) {
	t := time.Now()
	if now != nil {
		t = now()
	}
	if skew == 0 {
		skew = 30 * time.Second
	}
	return t, min(skew, MaxSkew)
}

// VerifyIDToken checks an ID token after the code exchange: a pinned algorithm and a signature from a known key, the configured issuer,
// an audience containing the client id (and `azp` equal to it when there are several), a valid time window, the echoed nonce, a subject, and
// the assurance the contract requires (`acr` among the accepted values, `amr` holding every required value). An access token presented as an ID
// token is refused by its `typ`.
func VerifyIDToken(ctx context.Context, token string, o IDOptions) (*IDClaims, error) {
	p, err := openSigned(ctx, token, o.Keys, o.Algorithms)
	if err != nil {
		return nil, err
	}
	// An ID token is an identity statement for the client, never an access token: refuse one that says it is for APIs.
	if typ := strings.ToLower(p.hdr.Typ); typ != "" && typ != "jwt" {
		return nil, newError(CodeType)
	}
	c := &IDClaims{Raw: p.claims}
	iss, ok := str(p.claims, "iss")
	if !ok || iss != o.Issuer {
		return nil, newError(CodeIssuer)
	}
	if c.Subject, ok = str(p.claims, "sub"); !ok {
		return nil, newError(CodeClaim)
	}
	if c.Audience, err = audience(p.claims["aud"]); err != nil {
		return nil, err
	}
	if !contains(c.Audience, o.ClientID) {
		return nil, newError(CodeAudience)
	}
	// With several audiences the authorized party must be the client (OpenID Connect Core 3.1.3.7).
	if azp, present := p.claims["azp"]; (len(c.Audience) > 1 || present) && azp != o.ClientID {
		return nil, newError(CodeAudience)
	}
	now, skew := effectiveTime(o.Now, o.Skew)
	exp, okE := unix(p.claims["exp"])
	iat, okI := unix(p.claims["iat"])
	if !okE || !okI {
		return nil, newError(CodeClaim)
	}
	if now.After(exp.Add(skew)) || iat.After(now.Add(skew)) {
		return nil, newError(CodeExpired)
	}
	if nbf, present := p.claims["nbf"]; present {
		t, okN := unix(nbf)
		if !okN {
			return nil, newError(CodeClaim)
		}
		if t.After(now.Add(skew)) {
			return nil, newError(CodeExpired)
		}
	}
	c.Expiry = exp
	// The nonce ties the token to this authorization request; without one a replayed response would be accepted.
	if o.Nonce == "" {
		return nil, newError(CodeClaim)
	}
	if n, _ := str(p.claims, "nonce"); n != o.Nonce {
		return nil, newError(CodeBinding)
	}
	c.SessionID, _ = str(p.claims, "sid")
	c.ACR, _ = str(p.claims, "acr")
	c.AMR = stringList(p.claims["amr"])
	if len(o.AcceptedACR) > 0 && !contains(o.AcceptedACR, c.ACR) {
		return nil, newError(CodeBinding)
	}
	for _, need := range o.RequiredAMR {
		if !contains(c.AMR, need) {
			return nil, newError(CodeBinding)
		}
	}
	return c, nil
}

// stringList reads a JSON array of strings, ignoring anything that is not one.
func stringList(v any) []string {
	a, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range a {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// LogoutOptions configure back-channel logout token verification.
type LogoutOptions struct {
	// Issuer is the configured issuer URL.
	Issuer string
	// ClientID is the console backend's client id; the token's `aud` must contain it.
	ClientID string
	// Keys supplies the verification keys.
	Keys *KeySet
	// Algorithms narrows the contract's allow-list.
	Algorithms []Algorithm
	// Skew is the clock tolerance; zero means 30 seconds, capped at MaxSkew.
	Skew time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Replay remembers logout token ids so a token is acted on once; required.
	Replay ReplayCache
}

// LogoutClaims name what the provider asked the backend to end.
type LogoutClaims struct {
	// Subject is `sub`, the user whose sessions end (empty when only a session is named).
	Subject string
	// SessionID is `sid`, the one session to end (empty when every session of the subject ends).
	SessionID string
	// JTI is the unique id of the logout token.
	JTI string
}

// VerifyLogoutToken checks an OpenID Connect Back-Channel Logout token (section 2.6): header `typ` `logout+jwt`, a pinned algorithm and a
// verified signature, the configured issuer, an audience containing the client id, a recent `iat`, an unexpired `exp`, a `jti` not seen before, the
// back-channel `events` member, at least one of `sub` and `sid`, and no `nonce` (a token with one is an ID token and is refused). The caller then
// deletes the session named by `sid` (or all of the subject's).
func VerifyLogoutToken(ctx context.Context, token string, o LogoutOptions) (*LogoutClaims, error) {
	p, err := openSigned(ctx, token, o.Keys, o.Algorithms)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(p.hdr.Typ) != "logout+jwt" {
		return nil, newError(CodeType)
	}
	iss, ok := str(p.claims, "iss")
	if !ok || iss != o.Issuer {
		return nil, newError(CodeIssuer)
	}
	aud, err := audience(p.claims["aud"])
	if err != nil {
		return nil, err
	}
	if !contains(aud, o.ClientID) {
		return nil, newError(CodeAudience)
	}
	now, skew := effectiveTime(o.Now, o.Skew)
	iat, okI := unix(p.claims["iat"])
	exp, okE := unix(p.claims["exp"])
	if !okI || !okE {
		return nil, newError(CodeClaim)
	}
	if now.After(exp.Add(skew)) || iat.After(now.Add(skew)) {
		return nil, newError(CodeExpired)
	}
	// A logout token never carries a nonce: one that does is an ID token in disguise.
	if _, present := p.claims["nonce"]; present {
		return nil, newError(CodeClaim)
	}
	events, isMap := p.claims["events"].(map[string]any)
	if _, has := events[backchannelEvent]; !isMap || !has {
		return nil, newError(CodeClaim)
	}
	c := &LogoutClaims{}
	c.Subject, _ = str(p.claims, "sub")
	c.SessionID, _ = str(p.claims, "sid")
	if c.Subject == "" && c.SessionID == "" {
		return nil, newError(CodeClaim)
	}
	if c.JTI, ok = str(p.claims, "jti"); !ok {
		return nil, newError(CodeClaim)
	}
	// A logout token is acted on once. A missing cache is a refusal: a verifier that cannot remember cannot detect a replay.
	if o.Replay == nil || o.Replay.Seen("logout|"+iss+"|"+c.JTI, exp.Add(skew), now) {
		return nil, newError(CodeReplay)
	}
	return c, nil
}
