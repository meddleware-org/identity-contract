// Conformance of discovery (contract section 1) against the live provider: the document the provider serves must pass the verifier's checks.

package conformance

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/meddleware-org/identity-contract/verifier"
)

// TestDiscoveryMeetsTheContract fetches the provider's discovery document and checks it with the first-party verifier.
func TestDiscoveryMeetsTheContract(t *testing.T) {
	p := need(t)
	d, err := verifier.FetchDiscovery(context.Background(), httpClient(), p.issuer, p.insecure)
	if err != nil {
		t.Fatalf("discovery refused (%v)", err)
	}
	if d.Issuer != p.issuer {
		t.Fatalf("issuer %q", d.Issuer)
	}
}

// TestPKCEOnlyS256 proves, against the live provider, that the console client cannot use anything but S256 (contract section 3): a request with
// `plain`, and a request with no challenge at all, are both answered with an `invalid_request` error carried back to the redirect URI together
// with the `iss` parameter (RFC 9207), and a request with S256 is not refused for PKCE. The discovery document cannot prove this, because a
// provider may advertise `plain` globally while refusing it for a client.
func TestPKCEOnlyS256(t *testing.T) {
	p := need(t)
	client, redirect := os.Getenv("CONF_CONSOLE_CLIENT"), os.Getenv("CONF_CONSOLE_REDIRECT")
	if client == "" || redirect == "" {
		t.Skip("CONF_CONSOLE_CLIENT and CONF_CONSOLE_REDIRECT are not set")
	}
	d, err := verifier.FetchDiscovery(context.Background(), httpClient(), p.issuer, p.insecure)
	if err != nil {
		t.Fatalf("discovery refused (%v)", err)
	}
	// ask sends one authorization request and returns the Location of the answer (empty when the provider rendered a page).
	ask := func(extra url.Values) string {
		q := url.Values{"client_id": {client}, "response_type": {"code"}, "redirect_uri": {redirect}, "scope": {"openid"}, "state": {"s"}, "nonce": {"n"}}
		for k, v := range extra {
			q[k] = v
		}
		resp, err := httpClient().Get(d.AuthorizationEndpoint + "?" + q.Encode())
		if err != nil {
			t.Fatalf("authorization request: %v", err)
		}
		// Closing a body that was never read cannot fail in a way the test cares about.
		defer func() { _ = resp.Body.Close() }()
		return resp.Header.Get("Location")
	}
	for name, extra := range map[string]url.Values{
		"plain":            {"code_challenge": {"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq"}, "code_challenge_method": {"plain"}},
		"no code verifier": {},
	} {
		loc := ask(extra)
		u, err := url.Parse(loc)
		if err != nil || loc == "" {
			t.Errorf("%s: no redirect with an error (%q)", name, loc)
			continue
		}
		if u.Query().Get("error") != "invalid_request" {
			t.Errorf("%s: error %q, want invalid_request (%s)", name, u.Query().Get("error"), loc)
		}
		if u.Query().Get("iss") != p.issuer {
			t.Errorf("%s: iss parameter %q, want %q (RFC 9207)", name, u.Query().Get("iss"), p.issuer)
		}
	}
	// A proper S256 request is not an error redirect: the provider renders its login page (no Location) or redirects to its own login.
	if loc := ask(url.Values{"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}); strings.Contains(loc, "error=") {
		t.Errorf("S256 request refused: %s", loc)
	}
}
