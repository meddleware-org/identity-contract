// Conformance of the policy decision point (contract section 4): the first-party AuthZEN client against a live PDP (OpenFGA is the reference).
// The harness prepares a store in which `user:alice` has `puller` on `registry:main` and `user:bob` has nothing.

package conformance

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/meddleware-org/identity-contract/authzen"
)

// pdp returns a client for the PDP named by CONF_AUTHZEN_BASE (the store's base URL), or skips the test.
func pdp(t *testing.T, base string) *authzen.Client {
	t.Helper()
	c, err := authzen.New(base, &http.Client{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestAuthZENDecisions asks the live PDP for one allowed and one denied decision, through the client, and checks the answers.
func TestAuthZENDecisions(t *testing.T) {
	base := os.Getenv("CONF_AUTHZEN_BASE")
	if base == "" {
		t.Skip("CONF_AUTHZEN_BASE is not set: the PDP part of the suite needs a live policy decision point")
	}
	c := pdp(t, base)
	ask := func(user string) (bool, error) {
		return c.Evaluate(context.Background(), authzen.Request{Subject: authzen.Entity{Type: "user", ID: user}, Resource: authzen.Entity{Type: "registry", ID: "main"}, Action: authzen.Action{Name: "puller"}})
	}
	start := time.Now()
	if ok, err := ask("alice"); err != nil || !ok {
		t.Errorf("alice (a pusher, who may also pull): %v %v", ok, err)
	}
	if ok, err := ask("bob"); err != nil || ok {
		t.Errorf("bob (no relation): %v %v", ok, err)
	}
	t.Logf("two uncached decisions in %v", time.Since(start))
}

// TestAuthZENFailsClosed proves that a PDP which cannot answer never yields an allow: an address nobody listens on, and a store that does not
// exist, both end in ErrUnavailable (the caller's 503), never in a decision.
func TestAuthZENFailsClosed(t *testing.T) {
	base := os.Getenv("CONF_AUTHZEN_BASE")
	if base == "" {
		t.Skip("CONF_AUTHZEN_BASE is not set")
	}
	req := authzen.Request{Subject: authzen.Entity{Type: "user", ID: "alice"}, Resource: authzen.Entity{Type: "registry", ID: "main"}, Action: authzen.Action{Name: "puller"}}
	for name, addr := range map[string]string{"nobody listens": "http://127.0.0.1:1", "unknown store": base + "-missing"} {
		ok, err := pdp(t, addr).Evaluate(context.Background(), req)
		if ok || !errors.Is(err, authzen.ErrUnavailable) {
			t.Errorf("%s: allow=%v err=%v, want ErrUnavailable", name, ok, err)
		}
	}
}
