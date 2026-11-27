// Tests of the AuthZEN client: the request it sends, the decisions it returns, the cache lifetimes and every way it fails closed.

package authzen

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// pdp is a test decision point that counts requests and answers with a settable decision.
type pdp struct {
	// srv is the test server.
	srv *httptest.Server
	// calls counts requests received.
	calls atomic.Int32
	// answer is what the next request gets: a status and a body.
	status int
	body   string
	// last is the last request body decoded.
	last Request
	// auth is the last Authorization header.
	auth string
}

// newPDP starts a decision point that allows by default.
func newPDP(t *testing.T) *pdp {
	t.Helper()
	p := &pdp{status: 200, body: `{"decision":true}`}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		p.auth = r.Header.Get("Authorization")
		if r.URL.Path != "/access/v1/evaluation" || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&p.last)
		w.WriteHeader(p.status)
		_, _ = w.Write([]byte(p.body))
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// req is the standard request: a user wants to push to a repository.
var req = Request{Subject: Entity{"user", "u_1"}, Resource: Entity{"repository", "meddleware-org/x"}, Action: Action{"push"}}

// TestEvaluateAllowAndDeny: the request has the AuthZEN shape and the decision comes back as given.
func TestEvaluateAllowAndDeny(t *testing.T) {
	p := newPDP(t)
	c, err := New(p.srv.URL, p.srv.Client(), WithTTLs(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := c.Evaluate(context.Background(), req); err != nil || !ok {
		t.Fatalf("allow: %v %v", ok, err)
	}
	if p.last.Subject != req.Subject || p.last.Resource != req.Resource || p.last.Action != req.Action {
		t.Fatalf("the PDP received %+v", p.last)
	}
	p.body = `{"decision":false}`
	if ok, err := c.Evaluate(context.Background(), req); err != nil || ok {
		t.Fatalf("deny: %v %v", ok, err)
	}
}

// TestCacheLifetimes: an allowed decision is reused for up to 30 seconds and a denied one for 5, then the PDP is asked again.
func TestCacheLifetimes(t *testing.T) {
	p := newPDP(t)
	now := time.Unix(1_800_000_000, 0)
	c, _ := New(p.srv.URL, p.srv.Client(), WithClock(func() time.Time { return now }))
	ctx := context.Background()
	_, _ = c.Evaluate(ctx, req)
	_, _ = c.Evaluate(ctx, req)
	if p.calls.Load() != 1 {
		t.Fatalf("allow not cached: %d calls", p.calls.Load())
	}
	now = now.Add(29 * time.Second)
	_, _ = c.Evaluate(ctx, req)
	if p.calls.Load() != 1 {
		t.Fatal("allow expired early")
	}
	now = now.Add(2 * time.Second)
	_, _ = c.Evaluate(ctx, req)
	if p.calls.Load() != 2 {
		t.Fatal("allow outlived 30 s")
	}
	// A denial is kept for 5 seconds only.
	p.body = `{"decision":false}`
	other := req
	other.Action.Name = "delete"
	_, _ = c.Evaluate(ctx, other)
	before := p.calls.Load()
	now = now.Add(4 * time.Second)
	_, _ = c.Evaluate(ctx, other)
	if p.calls.Load() != before {
		t.Fatal("deny not cached")
	}
	now = now.Add(2 * time.Second)
	_, _ = c.Evaluate(ctx, other)
	if p.calls.Load() != before+1 {
		t.Fatal("deny outlived 5 s")
	}
}

// TestTTLsAreCappedAtTheContractMaxima: a caller cannot ask for a longer cache than the contract allows.
func TestTTLsAreCappedAtTheContractMaxima(t *testing.T) {
	c, _ := New("http://pdp.example", nil, WithTTLs(time.Hour, time.Hour))
	if c.allowTTL != MaxAllowTTL || c.denyTTL != MaxDenyTTL {
		t.Fatalf("ttls %v %v", c.allowTTL, c.denyTTL)
	}
}

// TestContextIsNeverCached: a request with a context goes to the PDP every time.
func TestContextIsNeverCached(t *testing.T) {
	p := newPDP(t)
	c, _ := New(p.srv.URL, p.srv.Client())
	r := req
	r.Context = map[string]any{"ip": "203.0.113.7"}
	_, _ = c.Evaluate(context.Background(), r)
	_, _ = c.Evaluate(context.Background(), r)
	if p.calls.Load() != 2 {
		t.Fatalf("calls %d", p.calls.Load())
	}
	if p.last.Context["ip"] != "203.0.113.7" {
		t.Fatal("the context was not sent")
	}
}

// TestFailsClosed: every way of not getting a clear answer is ErrUnavailable, never an allow.
func TestFailsClosed(t *testing.T) {
	p := newPDP(t)
	c, _ := New(p.srv.URL, p.srv.Client(), WithTTLs(0, 0))
	cases := map[string]struct {
		status int
		body   string
	}{
		"server error":      {500, `{"decision":true}`},
		"not found":         {404, `{"decision":true}`},
		"not json":          {200, `allow`},
		"no decision field": {200, `{}`},
		"decision a string": {200, `{"decision":"true"}`},
		"empty body":        {200, ``},
	}
	for name, a := range cases {
		p.status, p.body = a.status, a.body
		if ok, err := c.Evaluate(context.Background(), req); ok || !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: allow=%v err=%v", name, ok, err)
		}
	}
	// An unreachable PDP, and a cancelled context.
	dead, _ := New("http://127.0.0.1:1", nil)
	if ok, err := dead.Evaluate(context.Background(), req); ok || !errors.Is(err, ErrUnavailable) {
		t.Errorf("unreachable: %v %v", ok, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, err := c.Evaluate(ctx, req); ok || !errors.Is(err, ErrUnavailable) {
		t.Errorf("cancelled: %v %v", ok, err)
	}
}

// TestIncompleteRequestsAreRefusedBeforeSending: a missing subject, resource or action never reaches the PDP.
func TestIncompleteRequestsAreRefusedBeforeSending(t *testing.T) {
	p := newPDP(t)
	c, _ := New(p.srv.URL, p.srv.Client())
	for _, r := range []Request{{}, {Subject: req.Subject}, {Subject: req.Subject, Resource: req.Resource}, {Resource: req.Resource, Action: req.Action}} {
		if _, err := c.Evaluate(context.Background(), r); err == nil || errors.Is(err, ErrUnavailable) {
			t.Errorf("request %+v: %v", r, err)
		}
	}
	if p.calls.Load() != 0 {
		t.Fatal("an incomplete request was sent")
	}
}

// TestTokenAndConfiguration: a bearer token is sent when configured (and a failing token source is a refusal), and bad addresses are rejected.
func TestTokenAndConfiguration(t *testing.T) {
	p := newPDP(t)
	c, _ := New(p.srv.URL, p.srv.Client(), WithToken(func(context.Context) (string, error) { return "tok", nil }), WithTTLs(0, 0))
	if _, err := c.Evaluate(context.Background(), req); err != nil || p.auth != "Bearer tok" {
		t.Fatalf("auth %q %v", p.auth, err)
	}
	bad, _ := New(p.srv.URL, p.srv.Client(), WithToken(func(context.Context) (string, error) { return "", errors.New("no token") }))
	if _, err := bad.Evaluate(context.Background(), req); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("token failure: %v", err)
	}
	for _, base := range []string{"", "pdp.example", "ftp://pdp.example", "http://"} {
		if _, err := New(base, nil); err == nil {
			t.Errorf("address %q accepted", base)
		}
	}
}

// TestCacheIsBounded: a flood of distinct requests cannot grow the cache without limit.
func TestCacheIsBounded(t *testing.T) {
	p := newPDP(t)
	c, _ := New(p.srv.URL, p.srv.Client())
	c.maxEntries = 3
	for i := 0; i < 20; i++ {
		r := req
		r.Resource.ID = string(rune('a' + i))
		_, _ = c.Evaluate(context.Background(), r)
	}
	if len(c.cache) > 3 {
		t.Fatalf("cache holds %d entries", len(c.cache))
	}
}
