// Conformance of the tokens a real browser sign-in produces (contract sections 2 and 3): the ID token of the passkey sign-in and the back-channel
// logout token of the RP-initiated logout, saved by the browser run of the spike (k8s/base/auth/tests/keycloak-spike in the workspace) and checked
// here with the first-party verifier against the provider's published keys.

package conformance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/meddleware-org/identity-contract/verifier"
)

// artifacts is the JSON file the browser run writes.
type artifacts struct {
	// Issuer, ClientID and Nonce describe the sign-in the tokens belong to.
	Issuer, ClientID, Nonce string
	// IDToken and LogoutToken are the compact JWTs the console received.
	IDToken, LogoutToken string
}

// issuedAt reads the `iat` claim of a compact JWT without verifying it; the tests use it only to pick the clock the verifier runs on.
func issuedAt(t *testing.T, token string) time.Time {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("token payload: %v", err)
	}
	var c struct {
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal([]byte(string(raw)), &c); err != nil {
		t.Fatalf("token claims: %v", err)
	}
	return time.Unix(c.Iat, 0)
}

// TestBrowserArtifacts verifies the saved ID token (a phishing-resistant sign-in: `acr` phr) and logout token. The clock is the token's own `iat`
// plus a minute, because the files are checked some time after the run; every other rule (signature, issuer, audience, nonce, `typ`, replay) is the
// ordinary one, and a second submission of the same logout token must be refused as a replay.
func TestBrowserArtifacts(t *testing.T) {
	p := need(t)
	path := os.Getenv("CONF_ARTIFACTS")
	if path == "" {
		t.Skip("CONF_ARTIFACTS is not set: run the browser part of the spike first")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var in map[string]string
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	a := artifacts{Issuer: in["issuer"], ClientID: in["clientId"], Nonce: in["nonce"], IDToken: in["idToken"], LogoutToken: in["logoutToken"]}
	d, err := verifier.FetchDiscovery(context.Background(), httpClient(), p.issuer, p.insecure)
	if err != nil {
		t.Fatalf("discovery refused (%v)", err)
	}
	fetch, err := verifier.FetchJWKS(httpClient(), d.JWKSURI, p.insecure)
	if err != nil {
		t.Fatal(err)
	}
	keys := verifier.NewKeySet(fetch)
	now := issuedAt(t, a.IDToken).Add(time.Minute)

	// The ID token: right issuer, audience and nonce, and the platform's phishing-resistant level.
	id, err := verifier.VerifyIDToken(context.Background(), a.IDToken, verifier.IDOptions{Issuer: p.issuer, ClientID: a.ClientID, Nonce: a.Nonce, Keys: keys,
		AcceptedACR: []string{"phr"}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("ID token refused (%v)", err)
	}
	if id.SessionID == "" {
		t.Error("the ID token has no sid, so a back-channel logout cannot be matched to a session")
	}
	// The same token must be refused for another nonce or another acr list.
	if _, err := verifier.VerifyIDToken(context.Background(), a.IDToken, verifier.IDOptions{Issuer: p.issuer, ClientID: a.ClientID, Nonce: "other", Keys: keys,
		Now: func() time.Time { return now }}); verifier.CodeOf(err) != verifier.CodeBinding {
		t.Errorf("a different nonce: %v", err)
	}
	if _, err := verifier.VerifyIDToken(context.Background(), a.IDToken, verifier.IDOptions{Issuer: p.issuer, ClientID: a.ClientID, Nonce: a.Nonce, Keys: keys,
		AcceptedACR: []string{"urn:other"}, Now: func() time.Time { return now }}); verifier.CodeOf(err) != verifier.CodeBinding {
		t.Errorf("an unaccepted acr: %v", err)
	}

	// The logout token: the back-channel event for the session of that ID token, accepted once and then refused as a replay.
	lo := verifier.LogoutOptions{Issuer: p.issuer, ClientID: a.ClientID, Keys: keys, Replay: verifier.NewMemoryReplayCache(16), Now: func() time.Time { return now }}
	lc, err := verifier.VerifyLogoutToken(context.Background(), a.LogoutToken, lo)
	if err != nil {
		t.Fatalf("logout token refused (%v)", err)
	}
	if lc.SessionID != id.SessionID {
		t.Errorf("logout sid %q is not the sign-in's sid %q", lc.SessionID, id.SessionID)
	}
	if _, err := verifier.VerifyLogoutToken(context.Background(), a.LogoutToken, lo); verifier.CodeOf(err) != verifier.CodeReplay {
		t.Errorf("a second submission of the logout token: %v", err)
	}
	// An ID token is not a logout token, and a logout token is not an ID token.
	if _, err := verifier.VerifyLogoutToken(context.Background(), a.IDToken, lo); err == nil {
		t.Error("an ID token was accepted as a logout token")
	}
	if _, err := verifier.VerifyIDToken(context.Background(), a.LogoutToken, verifier.IDOptions{Issuer: p.issuer, ClientID: a.ClientID, Nonce: a.Nonce, Keys: keys,
		Now: func() time.Time { return now }}); err == nil {
		t.Error("a logout token was accepted as an ID token")
	}
}
