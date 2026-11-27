// Tests of DPoP verification: a good proof once, each refusal (binding, time, replay, key, algorithm), the RFC 7638 vector and the replay cache.

package verifier

import (
	"crypto/sha256"
	"testing"
	"time"
)

// dpopFixture is a DPoP-bound access token with a client key, and a way to make proofs for requests.
type dpopFixture struct {
	// key is the client's proof key.
	key *signer
	// token is the access token string the proof accompanies.
	token string
	// jkt is the key's thumbprint, which the token's `cnf.jkt` carries.
	jkt string
}

// newDPoPFixture makes a client key and its thumbprint.
func newDPoPFixture(t *testing.T) dpopFixture {
	t.Helper()
	key := newES256(t, "")
	jkt, err := key.jwk.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	return dpopFixture{key: key, token: "the.access.token", jkt: jkt}
}

// athOf is the base64url SHA-256 of the token, the proof's `ath`.
func athOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return enc(sum[:])
}

// proof makes a proof for a request with claims overridable through mod.
func (f dpopFixture) proof(t *testing.T, method, htu string, mod func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{"jti": "p-1", "htm": method, "htu": htu, "iat": epoch.Unix(), "ath": athOf(f.token)}
	if mod != nil {
		mod(claims)
	}
	jwk := f.key.jwk
	return compact(t, map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": jwk}, claims, f.key)
}

// request is the request a proof for GET https://api.example/v1/x must match.
func (f dpopFixture) request() DPoPRequest {
	return DPoPRequest{Method: "GET", URL: "https://api.example/v1/x?q=1", AccessToken: f.token, ConfirmationJKT: f.jkt, Now: epoch}
}

// TestDPoPAcceptsAGoodProofOnce: a proof verifies, returns the thumbprint, ignores the query, and cannot be used twice.
func TestDPoPAcceptsAGoodProofOnce(t *testing.T) {
	f := newDPoPFixture(t)
	cache := NewMemoryReplayCache(10)
	p := f.proof(t, "GET", "https://api.example/v1/x", nil)
	jkt, err := VerifyDPoP(p, f.request(), cache)
	if err != nil || jkt != f.jkt {
		t.Fatalf("good proof: %v (%q)", err, jkt)
	}
	_, err = VerifyDPoP(p, f.request(), cache)
	wantCode(t, err, CodeReplay)
}

// TestDPoPRefusals: each way a proof can be wrong is refused with its own code.
func TestDPoPRefusals(t *testing.T) {
	f := newDPoPFixture(t)
	other := newES256(t, "")
	req := f.request()
	cases := []struct {
		name  string
		proof string
		req   DPoPRequest
		code  Code
	}{
		{"wrong method", f.proof(t, "POST", "https://api.example/v1/x", nil), req, CodeBinding},
		{"wrong htu path", f.proof(t, "GET", "https://api.example/v1/y", nil), req, CodeBinding},
		{"wrong htu host", f.proof(t, "GET", "https://evil.example/v1/x", nil), req, CodeBinding},
		{"wrong ath", f.proof(t, "GET", "https://api.example/v1/x", func(c map[string]any) { c["ath"] = athOf("another.token") }), req, CodeBinding},
		{"missing ath", f.proof(t, "GET", "https://api.example/v1/x", func(c map[string]any) { delete(c, "ath") }), req, CodeBinding},
		{"too old", f.proof(t, "GET", "https://api.example/v1/x", func(c map[string]any) { c["iat"] = epoch.Add(-2 * time.Minute).Unix() }), req, CodeExpired},
		{"from the future", f.proof(t, "GET", "https://api.example/v1/x", func(c map[string]any) { c["iat"] = epoch.Add(2 * time.Minute).Unix() }), req, CodeExpired},
		{"missing jti", f.proof(t, "GET", "https://api.example/v1/x", func(c map[string]any) { delete(c, "jti") }), req, CodeClaim},
		{"missing htm", f.proof(t, "GET", "https://api.example/v1/x", func(c map[string]any) { delete(c, "htm") }), req, CodeClaim},
		{"missing iat", f.proof(t, "GET", "https://api.example/v1/x", func(c map[string]any) { delete(c, "iat") }), req, CodeClaim},
		{"token bound to another key", f.proof(t, "GET", "https://api.example/v1/x", nil), DPoPRequest{Method: "GET", URL: req.URL, AccessToken: f.token, ConfirmationJKT: "other-thumbprint", Now: epoch}, CodeBinding},
		{"token without cnf.jkt (a bearer token where DPoP is required)", f.proof(t, "GET", "https://api.example/v1/x", nil), DPoPRequest{Method: "GET", URL: req.URL, AccessToken: f.token, Now: epoch}, CodeBinding},
		{"nonce required but absent", f.proof(t, "GET", "https://api.example/v1/x", nil), DPoPRequest{Method: "GET", URL: req.URL, AccessToken: f.token, ConfirmationJKT: f.jkt, Nonce: "n1", Now: epoch}, CodeBinding},
		{"wrong typ", compact(t, map[string]any{"alg": "ES256", "typ": "JWT", "jwk": f.key.jwk}, map[string]any{}, f.key), req, CodeType},
		{"symmetric alg", compact(t, map[string]any{"alg": "HS256", "typ": "dpop+jwt", "jwk": f.key.jwk}, map[string]any{}, f.key), req, CodeAlgorithm},
		{"RS256 is not allowed for proofs", compact(t, map[string]any{"alg": "RS256", "typ": "dpop+jwt", "jwk": f.key.jwk}, map[string]any{}, f.key), req, CodeAlgorithm},
		{"no jwk", compact(t, map[string]any{"alg": "ES256", "typ": "dpop+jwt"}, map[string]any{}, f.key), req, CodeAlgorithm},
		{"jwk with a private member", compact(t, map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": withD(f.key.jwk)}, map[string]any{}, f.key), req, CodeKey},
		{"signed by a key that is not the header's", compact(t, map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": f.key.jwk}, map[string]any{"jti": "x"}, other), req, CodeSignature},
		{"malformed", "x.y", req, CodeMalformed},
	}
	for _, c := range cases {
		if _, err := VerifyDPoP(c.proof, c.req, NewMemoryReplayCache(10)); CodeOf(err) != c.code {
			t.Errorf("%s: code %q (%v), want %q", c.name, CodeOf(err), err, c.code)
		}
	}
	// No replay cache at all is refused: a verifier that cannot remember cannot detect a replay.
	if _, err := VerifyDPoP(f.proof(t, "GET", "https://api.example/v1/x", nil), req, nil); CodeOf(err) != CodeReplay {
		t.Errorf("nil cache: %v", err)
	}
}

// withD returns the JWK with a (fake) private member.
func withD(k JWK) JWK { k.D = "AAAA"; return k }

// TestDPoPNonce: a required nonce is accepted when the proof carries it.
func TestDPoPNonce(t *testing.T) {
	f := newDPoPFixture(t)
	p := f.proof(t, "GET", "https://api.example/v1/x", func(c map[string]any) { c["nonce"] = "n1" })
	req := f.request()
	req.Nonce = "n1"
	if _, err := VerifyDPoP(p, req, NewMemoryReplayCache(10)); err != nil {
		t.Fatal(err)
	}
}

// TestDPoPWorksWithEdDSAKeys: Ed25519 proof keys are allowed too.
func TestDPoPWorksWithEdDSAKeys(t *testing.T) {
	key := newEdDSA(t, "")
	jkt, _ := key.jwk.Thumbprint()
	tok := "t.t.t"
	claims := map[string]any{"jti": "1", "htm": "GET", "htu": "https://api.example/v1/x", "iat": epoch.Unix(), "ath": athOf(tok)}
	p := compact(t, map[string]any{"alg": "EdDSA", "typ": "dpop+jwt", "jwk": key.jwk}, claims, key)
	if _, err := VerifyDPoP(p, DPoPRequest{Method: "GET", URL: "https://api.example/v1/x", AccessToken: tok, ConfirmationJKT: jkt, Now: epoch}, NewMemoryReplayCache(0)); err != nil {
		t.Fatal(err)
	}
}

// TestThumbprintMatchesRFC7638: the RFC's own example key and its published thumbprint.
func TestThumbprintMatchesRFC7638(t *testing.T) {
	rfc := JWK{
		Kty: "RSA", E: "AQAB",
		N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	}
	got, err := rfc.Thumbprint()
	if err != nil || got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint %q (%v)", got, err)
	}
}

// TestMemoryReplayCacheFailsClosedWhenFull: a full cache with nothing expired reports a replay rather than forgetting.
func TestMemoryReplayCacheFailsClosedWhenFull(t *testing.T) {
	c := NewMemoryReplayCache(2)
	until := epoch.Add(time.Minute)
	if c.Seen("a", until, epoch) || c.Seen("b", until, epoch) {
		t.Fatal("fresh keys reported as seen")
	}
	if !c.Seen("c", until, epoch) {
		t.Fatal("a full cache must fail closed")
	}
	// Once the entries expire there is room again, and an expired key is no longer a replay.
	later := epoch.Add(2 * time.Minute)
	if c.Seen("c", later.Add(time.Minute), later) || c.Seen("a", later.Add(time.Minute), later) {
		t.Fatal("expired entries must make room")
	}
}
