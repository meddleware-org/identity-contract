// DPoP proof verification (contract section 5, RFC 9449) and the replay cache that makes each proof single-use.

package verifier

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DPoPWindow is how far a proof's `iat` may be from now, either way (contract section 5: 60 seconds).
const DPoPWindow = 60 * time.Second

// ReplayCache remembers DPoP proof ids so a proof is used once.
type ReplayCache interface {
	// Seen records the key until the given time and reports whether it was already recorded and not yet expired.
	Seen(key string, until time.Time, now time.Time) bool
}

// MemoryReplayCache is a bounded in-memory ReplayCache for one process. When it is full it drops the entries that have expired and, if still
// full, refuses to record (so Seen reports true and the proof is treated as a replay): failing closed is the safe direction.
type MemoryReplayCache struct {
	// mu guards entries.
	mu sync.Mutex
	// entries maps a key to when it stops mattering.
	entries map[string]time.Time
	// max is the capacity.
	max int
}

// NewMemoryReplayCache makes a cache that holds at most capacity proof ids (a value below 1 means 10,000).
func NewMemoryReplayCache(capacity int) *MemoryReplayCache {
	if capacity < 1 {
		capacity = 10000
	}
	return &MemoryReplayCache{entries: make(map[string]time.Time), max: capacity}
}

// Seen implements ReplayCache.
func (c *MemoryReplayCache) Seen(key string, until time.Time, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.entries[key]; ok && exp.After(now) {
		return true
	}
	if len(c.entries) >= c.max {
		// Make room by dropping what has expired; if nothing has, refuse (fail closed).
		for k, exp := range c.entries {
			if !exp.After(now) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.max {
			return true
		}
	}
	c.entries[key] = until
	return false
}

// DPoPRequest is what a proof must match: the request it arrived with and the access token it accompanies.
type DPoPRequest struct {
	// Method is the HTTP method of the request.
	Method string
	// URL is the absolute URL of the request as the client addressed it (query and fragment are ignored).
	URL string
	// AccessToken is the access token string; the proof's `ath` must be its hash.
	AccessToken string
	// ConfirmationJKT is the access token's `cnf.jkt`; the proof key's thumbprint must equal it.
	ConfirmationJKT string
	// Nonce is the server nonce the provider or resource server currently requires; empty when none is required.
	Nonce string
	// Now is the time; zero means time.Now().
	Now time.Time
}

// VerifyDPoP checks an RFC 9449 proof (contract section 5) and returns the proof key's thumbprint:
// typ `dpop+jwt`, an asymmetric algorithm from the allow-list, a public `jwk` in the header whose signature verifies, `htm` and `htu` equal to the
// request, `iat` within a minute, an unseen `jti`, `ath` equal to the token's hash, the key's thumbprint equal to `cnf.jkt`, and the nonce when required.
// A token without a `cnf.jkt` where DPoP is required fails here (an empty ConfirmationJKT never matches).
func VerifyDPoP(proof string, req DPoPRequest, replay ReplayCache) (string, error) {
	p, err := parse(proof)
	if err != nil {
		return "", err
	}
	if strings.ToLower(p.hdr.Typ) != "dpop+jwt" {
		return "", newError(CodeType)
	}
	// The key to verify with travels in the proof itself: it is trusted only because the access token names its thumbprint.
	alg, ok := allowed(p.hdr.Alg, []Algorithm{ES256, EdDSA})
	if !ok || p.hdr.JWK == nil {
		return "", newError(CodeAlgorithm)
	}
	key, err := p.hdr.JWK.PublicKey()
	if err != nil {
		return "", err
	}
	if err := verifySignature(alg, key, p.signingInput, p.sig); err != nil {
		return "", err
	}
	jkt, err := p.hdr.JWK.Thumbprint()
	if err != nil {
		return "", err
	}
	// The binding: the key that signed the proof is the key the token was issued to.
	if req.ConfirmationJKT == "" || subtle.ConstantTimeCompare([]byte(jkt), []byte(req.ConfirmationJKT)) != 1 {
		return "", newError(CodeBinding)
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	if err := checkProofClaims(p.claims, req, now); err != nil {
		return "", err
	}
	jti, _ := str(p.claims, "jti")
	if replay == nil || replay.Seen(jkt+"|"+jti, now.Add(2*DPoPWindow), now) {
		return "", newError(CodeReplay)
	}
	return jkt, nil
}

// checkProofClaims verifies the proof's claims against the request: method, URL, time, token hash and nonce.
func checkProofClaims(claims map[string]any, req DPoPRequest, now time.Time) error {
	if _, ok := str(claims, "jti"); !ok {
		return newError(CodeClaim)
	}
	htm, okM := str(claims, "htm")
	htu, okU := str(claims, "htu")
	if !okM || !okU {
		return newError(CodeClaim)
	}
	if htm != req.Method || !sameURL(htu, req.URL) {
		return newError(CodeBinding)
	}
	iat, ok := unix(claims["iat"])
	if !ok {
		return newError(CodeClaim)
	}
	if d := now.Sub(iat); d > DPoPWindow || d < -DPoPWindow {
		return newError(CodeExpired)
	}
	// `ath` ties the proof to this very access token: a proof stolen for another token is useless.
	sum := sha256.Sum256([]byte(req.AccessToken))
	if ath, _ := str(claims, "ath"); subtle.ConstantTimeCompare([]byte(ath), []byte(base64.RawURLEncoding.EncodeToString(sum[:]))) != 1 {
		return newError(CodeBinding)
	}
	if req.Nonce != "" {
		if n, _ := str(claims, "nonce"); subtle.ConstantTimeCompare([]byte(n), []byte(req.Nonce)) != 1 {
			return newError(CodeBinding)
		}
	}
	return nil
}

// sameURL compares two absolute URLs by scheme, host and path only (RFC 9449 section 4.3: the query and fragment are left out).
func sameURL(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil || ua.Host == "" || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host) && ua.EscapedPath() == ub.EscapedPath()
}
