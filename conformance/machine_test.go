// Conformance of machine clients (contract section 5): private_key_jwt, DPoP-bound RFC 9068 tokens, and the resource-server checks of the
// first-party verifier on what the provider really issues.

package conformance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/meddleware-org/identity-contract/verifier"
)

// tokenResponse is the part of a token endpoint answer the tests read.
type tokenResponse struct {
	// AccessToken is the issued token.
	AccessToken string `json:"access_token"`
	// TokenType is Bearer or DPoP.
	TokenType string `json:"token_type"`
	// ExpiresIn is the lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
	// Scope is the granted scope.
	Scope string `json:"scope"`
	// Error is set on a refusal.
	Error string `json:"error"`
}

// requestToken asks the token endpoint for a client-credentials token, authenticating with private_key_jwt. proof is an optional DPoP header value.
func requestToken(t *testing.T, p provider, d *verifier.Discovery, assertion, proof string) (*http.Response, tokenResponse) {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {p.client}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}, "scope": {p.scope}}
	req, err := http.NewRequest(http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var tr tokenResponse
	_ = json.Unmarshal(body, &tr)
	return resp, tr
}

// assertion signs a client assertion (RFC 7523) for the token endpoint.
func assertion(t *testing.T, p provider, aud string) string {
	t.Helper()
	k := loadKey(t, p.keyPath)
	now := time.Now().Unix()
	return signES256(t, k, map[string]any{"alg": "ES256", "typ": "JWT", "kid": p.kid},
		map[string]any{"iss": p.client, "sub": p.client, "aud": aud, "jti": b64(randomBytes(t, 12)), "iat": now, "exp": now + 60})
}

// discoverMachine returns the provider's discovery, tolerating a provider that does not yet meet section 1 (that is its own test).
func discoverMachine(t *testing.T, p provider) *verifier.Discovery {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, strings_(p.issuer)+"/.well-known/openid-configuration", nil)
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var d verifier.Discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	return &d
}

// strings trims a trailing slash from the issuer.
func strings_(s string) string { return strings.TrimRight(s, "/") }

// TestMachineClientGetsADPoPBoundRFC9068Token: the provider issues a DPoP-bound `at+jwt` for the configured audience, and the first-party verifier accepts it
// together with a proof for a request to the resource server.
func TestMachineClientGetsADPoPBoundRFC9068Token(t *testing.T) {
	p := need(t)
	if p.client == "" || p.keyPath == "" {
		t.Skip("no machine client configured")
	}
	d := discoverMachine(t, p)
	key := newDPoPKey(t)
	resp, tr := requestToken(t, p, d, assertion(t, p, p.issuer), dpopProof(t, key, "POST", d.TokenEndpoint, "", ""))
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		t.Fatalf("token request: %d %q", resp.StatusCode, tr.Error)
	}
	if !strings.EqualFold(tr.TokenType, "DPoP") {
		t.Fatalf("token_type %q, want DPoP", tr.TokenType)
	}
	fetch, err := verifier.FetchJWKS(httpClient(), d.JWKSURI, p.insecure)
	if err != nil {
		t.Fatal(err)
	}
	opts := verifier.Options{Issuer: p.issuer, Audience: p.audience, Keys: verifier.NewKeySet(fetch), MaxLifetime: verifier.MachineLifetime}
	claims, err := verifier.VerifyAccessToken(context.Background(), tr.AccessToken, opts)
	if err != nil {
		t.Fatalf("the verifier refused the provider's token (%v)", err)
	}
	if claims.ConfirmationJKT == "" || !claims.HasScope(p.scope) {
		t.Fatalf("claims lack cnf.jkt or the scope: %+v", claims)
	}
	// A proof for a request to the resource server verifies; the same proof a second time is a replay.
	cache := verifier.NewMemoryReplayCache(100)
	url := "https://" + strings.TrimPrefix(p.audience, "https://") + "/v1/upload"
	proof := dpopProof(t, key, "POST", url, tr.AccessToken, "")
	req := verifier.DPoPRequest{Method: "POST", URL: url, AccessToken: tr.AccessToken, ConfirmationJKT: claims.ConfirmationJKT}
	if _, err := verifier.VerifyDPoP(proof, req, cache); err != nil {
		t.Fatalf("proof refused (%v)", err)
	}
	if _, err := verifier.VerifyDPoP(proof, req, cache); verifier.CodeOf(err) != verifier.CodeReplay {
		t.Fatalf("replay accepted: %v", err)
	}
	// A proof from a different key does not match the token's binding.
	other := dpopProof(t, newDPoPKey(t), "POST", url, tr.AccessToken, "")
	if _, err := verifier.VerifyDPoP(other, req, cache); verifier.CodeOf(err) != verifier.CodeBinding {
		t.Fatalf("a proof from another key: %v", err)
	}
}

// TestTokenEndpointRefusesBadClientAssertions: a wrong audience, an expired assertion and a signature by another key are refused.
func TestTokenEndpointRefusesBadClientAssertions(t *testing.T) {
	p := need(t)
	if p.client == "" || p.keyPath == "" {
		t.Skip("no machine client configured")
	}
	d := discoverMachine(t, p)
	good := loadKey(t, p.keyPath)
	now := time.Now().Unix()
	claims := func(aud string, exp int64) map[string]any {
		return map[string]any{"iss": p.client, "sub": p.client, "aud": aud, "jti": b64(randomBytes(t, 12)), "iat": now, "exp": exp}
	}
	hdr := map[string]any{"alg": "ES256", "typ": "JWT", "kid": p.kid}
	cases := map[string]string{
		"wrong audience": signES256(t, good, hdr, claims("https://evil.example", now+60)),
		"expired":        signES256(t, good, hdr, claims(p.issuer, now-600)),
		"another key":    signES256(t, newDPoPKey(t), hdr, claims(p.issuer, now+60)),
	}
	for name, a := range cases {
		resp, tr := requestToken(t, p, d, a, "")
		if resp.StatusCode == http.StatusOK || tr.AccessToken != "" {
			t.Errorf("%s: the provider issued a token", name)
		}
	}
}
