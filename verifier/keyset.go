package verifier

import (
	"context"
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Defaults of the key cache (contract section 1: one refresh at most every 30 seconds; the cache is bounded in size and age).
const (
	// DefaultMinRefresh is the least time between two fetches of the JWKS, whatever the tokens ask for.
	DefaultMinRefresh = 30 * time.Second
	// DefaultMaxAge is how long a fetched key set is trusted before it is fetched again.
	DefaultMaxAge = time.Hour
	// DefaultMaxKeys is the most keys one JWKS may hold; a larger document is refused.
	DefaultMaxKeys = 32
	// maxJWKSBytes bounds the JWKS response body.
	maxJWKSBytes = 1 << 20
)

// Fetcher returns the provider's current public keys. FetchJWKS builds one for a jwks_uri; a test supplies its own.
type Fetcher func(ctx context.Context) ([]JWK, error)

// KeySet is a bounded cache of a provider's signing keys. It is safe for concurrent use.
type KeySet struct {
	// fetch gets the current keys from the provider.
	fetch Fetcher
	// now is the clock (replaceable in tests).
	now func() time.Time
	// minRefresh is the least time between fetches.
	minRefresh time.Duration
	// maxAge is how old the cache may be before a lookup refreshes it.
	maxAge time.Duration
	// maxKeys bounds the size of one key set.
	maxKeys int

	// mu guards the fields below.
	mu sync.Mutex
	// keys maps a kid to its public key.
	keys map[string]crypto.PublicKey
	// fetchedAt is when the cache was last filled successfully.
	fetchedAt time.Time
	// lastTry is when a fetch was last attempted (successful or not), for the 30-second rule.
	lastTry time.Time
}

// NewKeySet makes a cache over a fetcher with the contract's defaults. Options replace them, for tests and for unusual providers.
func NewKeySet(fetch Fetcher, opts ...KeySetOption) *KeySet {
	s := &KeySet{fetch: fetch, now: time.Now, minRefresh: DefaultMinRefresh, maxAge: DefaultMaxAge, maxKeys: DefaultMaxKeys}
	for _, o := range opts {
		o(s)
	}
	return s
}

// KeySetOption changes a KeySet's defaults.
type KeySetOption func(*KeySet)

// WithClock sets the clock the cache uses.
func WithClock(now func() time.Time) KeySetOption { return func(s *KeySet) { s.now = now } }

// WithMinRefresh sets the least time between fetches (the contract's value is 30 seconds).
func WithMinRefresh(d time.Duration) KeySetOption { return func(s *KeySet) { s.minRefresh = d } }

// Key returns the key for a kid. A kid the cache does not hold triggers one fetch, but never more often than the minimum refresh
// interval, so a flood of unknown kids cannot turn the verifier into a request amplifier. A cache older than the maximum age is refreshed first.
func (s *KeySet) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	stale := s.keys == nil || now.Sub(s.fetchedAt) > s.maxAge
	if k, ok := s.keys[kid]; ok && !stale {
		return k, nil
	}
	// A fetch is allowed when nothing is cached, or when the last attempt is old enough.
	if s.keys == nil || now.Sub(s.lastTry) >= s.minRefresh {
		s.lastTry = now
		if err := s.refresh(ctx, now); err != nil && s.keys == nil {
			return nil, err
		}
	}
	if k, ok := s.keys[kid]; ok {
		return k, nil
	}
	return nil, newError(CodeKey)
}

// refresh replaces the cache with a freshly fetched key set. A failed fetch keeps the old keys (a provider outage must not log everyone out
// before the keys' own expiry), and a set that is too large or has no usable key is refused as a whole. The caller holds the lock.
func (s *KeySet) refresh(ctx context.Context, now time.Time) error {
	jwks, err := s.fetch(ctx)
	if err != nil {
		return newError(CodeKey)
	}
	if len(jwks) == 0 || len(jwks) > s.maxKeys {
		return newError(CodeKey)
	}
	next := make(map[string]crypto.PublicKey, len(jwks))
	for _, k := range jwks {
		if k.Kid == "" {
			continue
		}
		pub, err := k.PublicKey()
		if err != nil {
			// One unusable key (an encryption key, an unsupported curve) does not poison the others.
			continue
		}
		next[k.Kid] = pub
	}
	if len(next) == 0 {
		return newError(CodeKey)
	}
	s.keys, s.fetchedAt = next, now
	return nil
}

// FetchJWKS returns a Fetcher for a jwks_uri. The URI must be https unless allowInsecure is set (development only), the response is
// limited to 1 MiB and must be 200 with a JSON object holding a `keys` array.
func FetchJWKS(client *http.Client, jwksURI string, allowInsecure bool) (Fetcher, error) {
	u, err := url.Parse(jwksURI)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (!allowInsecure || u.Scheme != "http")) {
		return nil, newError(CodeKey)
	}
	return func(ctx context.Context) ([]JWK, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
		if err != nil {
			return nil, newError(CodeKey)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, newError(CodeKey)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, newError(CodeKey)
		}
		var doc struct {
			Keys []JWK `json:"keys"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&doc); err != nil {
			return nil, newError(CodeKey)
		}
		return doc.Keys, nil
	}, nil
}
