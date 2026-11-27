package verifier

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// clock is a settable test clock.
type clock struct{ t time.Time }

// now returns the clock's time.
func (c *clock) now() time.Time { return c.t }

// TestKeySetRefreshesAnUnknownKidAtMostEveryThirtySeconds: contract section 1's rule, with a fake clock and a counting fetcher.
func TestKeySetRefreshesAnUnknownKidAtMostEveryThirtySeconds(t *testing.T) {
	a, b := newES256(t, "a"), newES256(t, "b")
	clk := &clock{t: epoch}
	fetches := 0
	keys := []JWK{a.jwk}
	ks := NewKeySet(func(context.Context) ([]JWK, error) { fetches++; return keys, nil }, WithClock(clk.now))
	if _, err := ks.Key(context.Background(), "a"); err != nil || fetches != 1 {
		t.Fatalf("first lookup: err %v fetches %d", err, fetches)
	}
	// An unknown kid right away must not fetch again.
	if _, err := ks.Key(context.Background(), "b"); CodeOf(err) != CodeKey || fetches != 1 {
		t.Fatalf("unknown kid inside 30s: %v, fetches %d", err, fetches)
	}
	// The provider rotates; after 30 seconds the unknown kid triggers one refresh and is found.
	keys = []JWK{a.jwk, b.jwk}
	clk.t = epoch.Add(31 * time.Second)
	if _, err := ks.Key(context.Background(), "b"); err != nil || fetches != 2 {
		t.Fatalf("after 30s: err %v fetches %d", err, fetches)
	}
	// A flood of unknown kids still costs no fetch inside the interval.
	for i := 0; i < 50; i++ {
		_, _ = ks.Key(context.Background(), "nope")
	}
	if fetches != 2 {
		t.Fatalf("flood caused %d fetches", fetches)
	}
}

// TestKeySetRefreshesWhenOld: a cache older than the maximum age is refreshed even for a known kid.
func TestKeySetRefreshesWhenOld(t *testing.T) {
	a := newES256(t, "a")
	clk := &clock{t: epoch}
	fetches := 0
	ks := NewKeySet(func(context.Context) ([]JWK, error) { fetches++; return []JWK{a.jwk}, nil }, WithClock(clk.now))
	_, _ = ks.Key(context.Background(), "a")
	clk.t = epoch.Add(DefaultMaxAge + time.Minute)
	if _, err := ks.Key(context.Background(), "a"); err != nil || fetches != 2 {
		t.Fatalf("err %v fetches %d", err, fetches)
	}
}

// TestKeySetKeepsOldKeysWhenTheProviderIsDown: a failed refresh does not drop the keys already held.
func TestKeySetKeepsOldKeysWhenTheProviderIsDown(t *testing.T) {
	a := newES256(t, "a")
	clk := &clock{t: epoch}
	down := false
	ks := NewKeySet(func(context.Context) ([]JWK, error) {
		if down {
			return nil, errors.New("down")
		}
		return []JWK{a.jwk}, nil
	}, WithClock(clk.now), WithMinRefresh(time.Second))
	_, _ = ks.Key(context.Background(), "a")
	down = true
	clk.t = epoch.Add(10 * time.Second)
	if _, err := ks.Key(context.Background(), "a"); err != nil {
		t.Fatalf("known key during an outage: %v", err)
	}
	// With nothing cached an outage is an error.
	empty := NewKeySet(func(context.Context) ([]JWK, error) { return nil, errors.New("down") })
	_, err := empty.Key(context.Background(), "a")
	wantCode(t, err, CodeKey)
}

// TestKeySetRefusesOversizedAndUnusableSets: too many keys, no kid, a private member, an encryption key and an unsupported curve.
func TestKeySetRefusesOversizedAndUnusableSets(t *testing.T) {
	good := newES256(t, "good")
	many := make([]JWK, DefaultMaxKeys+1)
	for i := range many {
		many[i] = good.jwk
	}
	_, err := NewKeySet(func(context.Context) ([]JWK, error) { return many, nil }).Key(context.Background(), "good")
	wantCode(t, err, CodeKey)
	mixed := []JWK{
		{Kty: "EC", Kid: "private", Crv: "P-256", X: good.jwk.X, Y: good.jwk.Y, D: "AAAA"},
		{Kty: "EC", Kid: "enc", Use: "enc", Crv: "P-256", X: good.jwk.X, Y: good.jwk.Y},
		{Kty: "EC", Kid: "p384", Crv: "P-384", X: good.jwk.X, Y: good.jwk.Y},
		{Kty: "EC", Crv: "P-256", X: good.jwk.X, Y: good.jwk.Y},
		good.jwk,
	}
	ks := NewKeySet(func(context.Context) ([]JWK, error) { return mixed, nil })
	if _, err := ks.Key(context.Background(), "good"); err != nil {
		t.Fatalf("the good key beside bad ones: %v", err)
	}
	for _, kid := range []string{"private", "enc", "p384"} {
		if _, err := ks.Key(context.Background(), kid); CodeOf(err) != CodeKey {
			t.Errorf("%s must not be usable: %v", kid, err)
		}
	}
	none := NewKeySet(func(context.Context) ([]JWK, error) { return []JWK{{Kty: "oct"}}, nil })
	_, err = none.Key(context.Background(), "x")
	wantCode(t, err, CodeKey)
}

// TestJWKValidation: points off the curve, short RSA moduli and bad encodings are refused.
func TestJWKValidation(t *testing.T) {
	good := newES256(t, "k").jwk
	bad := []JWK{
		{Kty: "EC", Crv: "P-256", X: good.X, Y: enc(make([]byte, 32))},
		{Kty: "EC", Crv: "P-256", X: "!!", Y: good.Y},
		{Kty: "EC", Crv: "P-256", X: enc([]byte{1}), Y: enc([]byte{1})},
		{Kty: "OKP", Crv: "X25519", X: enc(make([]byte, 32))},
		{Kty: "OKP", Crv: "Ed25519", X: enc([]byte{1, 2})},
		{Kty: "RSA", N: enc(make([]byte, 128)), E: enc([]byte{1, 0, 1})},
		{Kty: "RSA", N: enc(append([]byte{0x80}, make([]byte, 255)...)), E: enc([]byte{2})},
		{Kty: "RSA", N: enc(append([]byte{0x80}, make([]byte, 255)...)), E: enc(nil)},
		{Kty: "unknown"},
	}
	for i, k := range bad {
		if _, err := k.PublicKey(); CodeOf(err) != CodeKey {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
	if _, err := (JWK{Kty: "x"}).Thumbprint(); CodeOf(err) != CodeKey {
		t.Error("thumbprint of an unknown type")
	}
}

// TestFetchJWKS: the https requirement, the status check, the size bound and a successful read over a test server.
func TestFetchJWKS(t *testing.T) {
	a := newES256(t, "a")
	if _, err := FetchJWKS(http.DefaultClient, "http://id.example/jwks", false); CodeOf(err) != CodeKey {
		t.Fatalf("plain http accepted: %v", err)
	}
	if _, err := FetchJWKS(http.DefaultClient, "::bad", true); CodeOf(err) != CodeKey {
		t.Fatalf("bad url accepted: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[{"kty":"EC","kid":"a","crv":"P-256","x":"` + a.jwk.X + `","y":"` + a.jwk.Y + `"}]}`))
	})
	mux.HandleFunc("/500", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	mux.HandleFunc("/junk", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	f, err := FetchJWKS(srv.Client(), srv.URL+"/ok", true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := f(context.Background())
	if err != nil || len(keys) != 1 || keys[0].Kid != "a" {
		t.Fatalf("keys %v err %v", keys, err)
	}
	for _, path := range []string{"/500", "/junk"} {
		f, _ := FetchJWKS(srv.Client(), srv.URL+path, true)
		if _, err := f(context.Background()); CodeOf(err) != CodeKey {
			t.Errorf("%s: %v", path, err)
		}
	}
}
