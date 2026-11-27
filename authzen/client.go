// The Access Evaluation client: one request per decision, a short cache, and a refusal for anything it cannot be sure of.

package authzen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The cache lifetimes of contract section 4: allowed decisions are kept at most 30 seconds, denied ones at most 5.
const (
	// MaxAllowTTL is the longest an allowed decision is cached.
	MaxAllowTTL = 30 * time.Second
	// MaxDenyTTL is the longest a denied decision is cached.
	MaxDenyTTL = 5 * time.Second
	// maxResponseBytes bounds the decision response: it is one small JSON object.
	maxResponseBytes = 64 << 10
	// defaultMaxEntries bounds the decision cache.
	defaultMaxEntries = 4096
	// evaluationPath is the Access Evaluation endpoint, relative to the PDP's base URL.
	evaluationPath = "/access/v1/evaluation"
)

// ErrUnavailable means no decision could be obtained: the PDP is unreachable, slow, answered with an error status or answered with something that
// is not a decision. The caller answers 503; it never treats this as an allow.
var ErrUnavailable = errors.New("authzen: no decision")

// Entity names the subject or the resource of a request: a type and an id, as the policy model knows them.
type Entity struct {
	// Type is the entity type in the policy model (for example "user" or "registry").
	Type string `json:"type"`
	// ID is the entity id (for example the opaque `sub` of a user).
	ID string `json:"id"`
}

// Action names what the subject wants to do (for example "push").
type Action struct {
	// Name is the action name in the policy model.
	Name string `json:"name"`
}

// Request is one Access Evaluation request.
type Request struct {
	// Subject is who asks.
	Subject Entity `json:"subject"`
	// Resource is what the action is on.
	Resource Entity `json:"resource"`
	// Action is what is attempted.
	Action Action `json:"action"`
	// Context is optional extra input for the policy; a request that carries one is never cached.
	Context map[string]any `json:"context,omitempty"`
}

// Client asks one PDP. It is safe for concurrent use.
type Client struct {
	// endpoint is the full evaluation URL.
	endpoint string
	// http is the HTTP client (its Timeout bounds every decision).
	http *http.Client
	// token supplies a bearer credential for the PDP, or is nil when the network policy is the only control.
	token func(context.Context) (string, error)
	// allowTTL and denyTTL are the cache lifetimes, never above the contract's maxima.
	allowTTL, denyTTL time.Duration
	// now is the clock (replaceable in tests).
	now func() time.Time
	// maxEntries bounds the cache.
	maxEntries int

	// mu guards the cache.
	mu sync.Mutex
	// cache maps a request key to its decision and when it stops being valid.
	cache map[string]entry
}

// entry is one cached decision.
type entry struct {
	// allow is the decision.
	allow bool
	// until is when the entry expires.
	until time.Time
}

// Option changes a Client's defaults.
type Option func(*Client)

// WithToken sets a function that returns the bearer token to send to the PDP.
func WithToken(f func(context.Context) (string, error)) Option {
	return func(c *Client) { c.token = f }
}

// WithTTLs sets the cache lifetimes; a value above the contract's maximum is lowered to it, and zero turns that cache off.
func WithTTLs(allow, deny time.Duration) Option {
	return func(c *Client) {
		c.allowTTL = min(allow, MaxAllowTTL)
		c.denyTTL = min(deny, MaxDenyTTL)
	}
}

// WithClock sets the clock the cache uses.
func WithClock(now func() time.Time) Option { return func(c *Client) { c.now = now } }

// New makes a client for the PDP at base (for example `http://openfga.auth.svc.cluster.local:8080`). The decision cache starts with the
// contract's maximum lifetimes; the HTTP client must carry a timeout, which New sets to five seconds when it has none.
func New(base string, hc *http.Client, opts ...Option) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("authzen: the PDP address must be an http(s) URL with a host")
	}
	if hc == nil {
		hc = &http.Client{}
	}
	if hc.Timeout == 0 {
		// Never wait forever for a decision: a hung PDP must become a 503, not a hung request.
		copyClient := *hc
		copyClient.Timeout = 5 * time.Second
		hc = &copyClient
	}
	c := &Client{
		endpoint: strings.TrimRight(base, "/") + evaluationPath, http: hc, allowTTL: MaxAllowTTL, denyTTL: MaxDenyTTL,
		now: time.Now, maxEntries: defaultMaxEntries, cache: make(map[string]entry),
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Evaluate returns the PDP's decision. A cached decision answers when it is still fresh; otherwise one request goes to the PDP. Any failure to
// obtain a clear true or false is ErrUnavailable.
func (c *Client) Evaluate(ctx context.Context, r Request) (bool, error) {
	// An incomplete request is refused before it is sent: the PDP would answer for a different question than the caller meant.
	if r.Subject.Type == "" || r.Subject.ID == "" || r.Resource.Type == "" || r.Resource.ID == "" || r.Action.Name == "" {
		return false, errors.New("authzen: the request needs a subject, a resource and an action")
	}
	key := ""
	// Only a request with no context can be cached: the context may change the answer.
	if len(r.Context) == 0 {
		key = strings.Join([]string{r.Subject.Type, r.Subject.ID, r.Resource.Type, r.Resource.ID, r.Action.Name}, "\x00")
		if allow, ok := c.cached(key); ok {
			return allow, nil
		}
	}
	allow, err := c.ask(ctx, r)
	if err != nil {
		return false, err
	}
	if key != "" {
		c.store(key, allow)
	}
	return allow, nil
}

// cached returns a fresh cached decision for the key.
func (c *Client) cached(key string) (allow, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, found := c.cache[key]
	if !found || !e.until.After(c.now()) {
		delete(c.cache, key)
		return false, false
	}
	return e.allow, true
}

// store remembers a decision for its lifetime, and does nothing when that lifetime is zero.
func (c *Client) store(key string, allow bool) {
	ttl := c.denyTTL
	if allow {
		ttl = c.allowTTL
	}
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.cache) >= c.maxEntries {
		// Make room by dropping what has expired; if that is not enough, drop everything (the cache is only an optimisation).
		for k, e := range c.cache {
			if !e.until.After(now) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= c.maxEntries {
			c.cache = make(map[string]entry)
		}
	}
	c.cache[key] = entry{allow: allow, until: now.Add(ttl)}
}

// ask sends one evaluation request and reads the decision.
func (c *Client) ask(ctx context.Context, r Request) (bool, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return false, ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return false, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != nil {
		tok, err := c.token(ctx)
		if err != nil || tok == "" {
			return false, ErrUnavailable
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, ErrUnavailable
	}
	var out struct {
		// Decision is a pointer so a missing field is told apart from false.
		Decision *bool `json:"decision"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&out); err != nil || out.Decision == nil {
		return false, ErrUnavailable
	}
	return *out.Decision, nil
}
