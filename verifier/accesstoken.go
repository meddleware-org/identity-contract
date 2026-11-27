// Access-token verification (contract section 2): RFC 9068 `at+jwt` tokens, the pinned algorithm list, the required claims, audience, lifetime and clock-skew rules.

package verifier

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Lifetimes the contract allows (section 2): a machine client's token lives at most 5 minutes, a user's 15.
const (
	// MachineLifetime is the longest a machine client's access token may live.
	MachineLifetime = 5 * time.Minute
	// UserLifetime is the longest a user's access token may live.
	UserLifetime = 15 * time.Minute
	// MaxSkew is the largest clock-skew tolerance the contract allows.
	MaxSkew = 60 * time.Second
)

// Claims are the verified claims of an access token. Only a token that passed every check is returned as Claims.
type Claims struct {
	// Issuer is `iss`.
	Issuer string
	// Subject is `sub`: an opaque, stable internal identifier (never an email address or a wallet address).
	Subject string
	// Audience is `aud` as a list (a single string is a one-element list).
	Audience []string
	// ClientID is `client_id`.
	ClientID string
	// Scopes are the space-separated values of `scope`.
	Scopes []string
	// JTI is the unique token id.
	JTI string
	// IssuedAt is `iat`.
	IssuedAt time.Time
	// Expiry is `exp`.
	Expiry time.Time
	// ConfirmationJKT is `cnf.jkt` when the token is DPoP-bound, else empty.
	ConfirmationJKT string
	// Raw holds every claim, for a service that needs one the contract does not name (numbers are json.Number).
	Raw map[string]any
}

// HasScope reports whether the token carries the scope.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Options configure access-token verification. The zero value is not usable: Issuer, Audience and Keys are required.
type Options struct {
	// Issuer is the configured issuer URL; the token's `iss` must equal it.
	Issuer string
	// Audience is this resource server's one fixed audience URI; the token's `aud` must contain it.
	Audience string
	// Keys supplies the verification keys.
	Keys *KeySet
	// Algorithms is the allow-list; empty means the contract's list (ES256, EdDSA, RS256). A caller may only narrow it.
	Algorithms []Algorithm
	// MaxLifetime is the longest `exp - iat` accepted; zero means UserLifetime. A machine-only resource server passes MachineLifetime.
	MaxLifetime time.Duration
	// Skew is the clock tolerance; zero means 30 seconds, and a value above MaxSkew is capped.
	Skew time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// contractAlgorithms is the allow-list of section 2.
var contractAlgorithms = []Algorithm{ES256, EdDSA, RS256}

// VerifyAccessToken checks an RFC 9068 access token against the contract (section 2) and returns its claims:
// a JWT with header typ `at+jwt` and a pinned algorithm, a signature from a known key, the configured issuer and audience, the required
// claims (iss, sub, aud, exp, iat, jti, client_id, scope), a lifetime within the limit and a time inside the skew.
// Every refusal is an *Error with the code of the check that failed.
func VerifyAccessToken(ctx context.Context, token string, o Options) (*Claims, error) {
	p, err := parse(token)
	if err != nil {
		return nil, err
	}
	// The media type: RFC 9068 requires `at+jwt` (or the full `application/at+jwt`), which keeps an ID token from being used as an access token.
	if typ := strings.ToLower(p.hdr.Typ); typ != "at+jwt" && typ != "application/at+jwt" {
		return nil, newError(CodeType)
	}
	algs := o.Algorithms
	if len(algs) == 0 {
		algs = contractAlgorithms
	} else {
		// A caller may narrow the list but never add to it.
		algs = narrow(algs)
	}
	alg, ok := allowed(p.hdr.Alg, algs)
	if !ok {
		return nil, newError(CodeAlgorithm)
	}
	key, err := o.Keys.Key(ctx, p.hdr.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(alg, key, p.signingInput, p.sig); err != nil {
		return nil, err
	}
	c, err := claimsOf(p.claims)
	if err != nil {
		return nil, err
	}
	return c, check(c, o)
}

// narrow keeps only the algorithms that are on the contract's list.
func narrow(want []Algorithm) []Algorithm {
	var out []Algorithm
	for _, a := range want {
		if _, ok := allowed(string(a), contractAlgorithms); ok {
			out = append(out, a)
		}
	}
	return out
}

// check applies the claim rules: issuer, audience, lifetime and time.
func check(c *Claims, o Options) error {
	if c.Issuer != o.Issuer {
		return newError(CodeIssuer)
	}
	if !contains(c.Audience, o.Audience) {
		return newError(CodeAudience)
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	skew := o.Skew
	if skew == 0 {
		skew = 30 * time.Second
	}
	if skew > MaxSkew {
		skew = MaxSkew
	}
	longest := o.MaxLifetime
	if longest == 0 {
		longest = UserLifetime
	}
	// Expired (with the skew), issued in the future, or living longer than the contract allows: all one code for the log.
	if now.After(c.Expiry.Add(skew)) || c.IssuedAt.After(now.Add(skew)) || c.Expiry.Sub(c.IssuedAt) > longest || !c.Expiry.After(c.IssuedAt) {
		return newError(CodeExpired)
	}
	return nil
}

// claimsOf reads the required claims out of the payload, refusing a missing one or one of the wrong type.
func claimsOf(raw map[string]any) (*Claims, error) {
	c := &Claims{Raw: raw}
	var ok bool
	if c.Issuer, ok = str(raw, "iss"); !ok {
		return nil, newError(CodeClaim)
	}
	if c.Subject, ok = str(raw, "sub"); !ok {
		return nil, newError(CodeClaim)
	}
	if c.JTI, ok = str(raw, "jti"); !ok {
		return nil, newError(CodeClaim)
	}
	if c.ClientID, ok = str(raw, "client_id"); !ok {
		return nil, newError(CodeClaim)
	}
	scope, ok := str(raw, "scope")
	if !ok {
		return nil, newError(CodeClaim)
	}
	c.Scopes = strings.Fields(scope)
	var err error
	if c.Audience, err = audience(raw["aud"]); err != nil {
		return nil, err
	}
	exp, okE := unix(raw["exp"])
	iat, okI := unix(raw["iat"])
	if !okE || !okI {
		return nil, newError(CodeClaim)
	}
	c.Expiry, c.IssuedAt = exp, iat
	if cnf, present := raw["cnf"]; present {
		m, isMap := cnf.(map[string]any)
		if !isMap {
			return nil, newError(CodeClaim)
		}
		if j, has := m["jkt"]; has {
			s, isStr := j.(string)
			if !isStr || s == "" {
				return nil, newError(CodeClaim)
			}
			c.ConfirmationJKT = s
		}
	}
	return c, nil
}

// str reads a non-empty string claim.
func str(m map[string]any, k string) (string, bool) {
	s, ok := m[k].(string)
	return s, ok && s != ""
}

// audience reads `aud`, a string or an array of strings, and refuses an empty or mistyped value.
func audience(v any) ([]string, error) {
	switch a := v.(type) {
	case string:
		if a == "" {
			return nil, newError(CodeClaim)
		}
		return []string{a}, nil
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, newError(CodeClaim)
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, newError(CodeClaim)
		}
		return out, nil
	default:
		return nil, newError(CodeClaim)
	}
}

// unix reads a NumericDate (seconds since the epoch, an integer or a fraction) from a decoded number.
func unix(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || f <= 0 || f > 1e12 {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0).UTC(), true
}
