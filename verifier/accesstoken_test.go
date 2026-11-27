// Tests of access-token verification: every allowed algorithm, and each way a token can be refused, with its error code.

package verifier

import (
	"context"
	"strings"
	"testing"
	"time"
)

// wantCode fails the test unless err is a verifier error with the code.
func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	if CodeOf(err) != code {
		t.Fatalf("code = %q (err %v), want %q", CodeOf(err), err, code)
	}
}

// TestAccessTokenAcceptsEveryAllowedAlgorithm: ES256, EdDSA and RS256 tokens with the contract's claims verify, and the claims come back.
func TestAccessTokenAcceptsEveryAllowedAlgorithm(t *testing.T) {
	for _, s := range []*signer{newES256(t, "k1"), newEdDSA(t, "k2"), newRS256(t, "k3")} {
		c, err := VerifyAccessToken(context.Background(), goodToken(t, s), opts(keysFor(s)))
		if err != nil {
			t.Fatalf("%s: %v", s.alg, err)
		}
		if c.Subject != "u_123" || c.ClientID != "console" || !c.HasScope("relay:upload") || c.HasScope("nope") || c.JTI != "tok-1" {
			t.Fatalf("%s: claims %+v", s.alg, c)
		}
	}
}

// TestAccessTokenRefusals: each way a token can be wrong is refused with its own code, and a token that is good except for one thing is not accepted.
func TestAccessTokenRefusals(t *testing.T) {
	s := newES256(t, "k1")
	other := newES256(t, "k1")
	ks := keysFor(s)
	hdr := func() map[string]any { return map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "k1"} }
	with := func(k string, v any) map[string]any { c := goodClaims(); c[k] = v; return c }
	without := func(k string) map[string]any { c := goodClaims(); delete(c, k); return c }
	cases := []struct {
		name string
		tok  string
		code Code
	}{
		{"not three parts", "a.b", CodeMalformed},
		{"empty", "", CodeMalformed},
		{"bad base64", "!!!.!!!.!!!", CodeMalformed},
		{"too large", strings.Repeat("a", maxTokenBytes+1), CodeMalformed},
		{"alg none", compact(t, map[string]any{"alg": "none", "typ": "at+jwt", "kid": "k1"}, goodClaims(), nil), CodeAlgorithm},
		{"alg HS256", compact(t, map[string]any{"alg": "HS256", "typ": "at+jwt", "kid": "k1"}, goodClaims(), s), CodeAlgorithm},
		{"alg lower case", compact(t, map[string]any{"alg": "es256", "typ": "at+jwt", "kid": "k1"}, goodClaims(), s), CodeAlgorithm},
		{"id token typ", compact(t, map[string]any{"alg": "ES256", "typ": "JWT", "kid": "k1"}, goodClaims(), s), CodeType},
		{"no typ", compact(t, map[string]any{"alg": "ES256", "kid": "k1"}, goodClaims(), s), CodeType},
		{"unknown kid", compact(t, map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "zzz"}, goodClaims(), s), CodeKey},
		{"signed by another key", compact(t, hdr(), goodClaims(), other), CodeSignature},
		{"wrong issuer", compact(t, hdr(), with("iss", "https://evil.example"), s), CodeIssuer},
		{"wrong audience", compact(t, hdr(), with("aud", "https://other.example"), s), CodeAudience},
		{"audience list without ours", compact(t, hdr(), with("aud", []string{"a", "b"}), s), CodeAudience},
		{"expired", compact(t, hdr(), with("exp", epoch.Add(-2*time.Minute).Unix()), s), CodeExpired},
		{"issued in the future", compact(t, hdr(), with("iat", epoch.Add(5*time.Minute).Unix()), s), CodeExpired},
		{"lives too long", compact(t, hdr(), with("exp", epoch.Add(time.Hour).Unix()), s), CodeExpired},
		{"exp before iat", compact(t, hdr(), with("exp", epoch.Add(-time.Hour).Unix()), s), CodeExpired},
		{"missing sub", compact(t, hdr(), without("sub"), s), CodeClaim},
		{"missing jti", compact(t, hdr(), without("jti"), s), CodeClaim},
		{"missing client_id", compact(t, hdr(), without("client_id"), s), CodeClaim},
		{"missing scope", compact(t, hdr(), without("scope"), s), CodeClaim},
		{"missing exp", compact(t, hdr(), without("exp"), s), CodeClaim},
		{"aud of the wrong type", compact(t, hdr(), with("aud", 7), s), CodeClaim},
		{"empty aud list", compact(t, hdr(), with("aud", []string{}), s), CodeClaim},
		{"cnf of the wrong type", compact(t, hdr(), with("cnf", "x"), s), CodeClaim},
	}
	for _, c := range cases {
		_, err := VerifyAccessToken(context.Background(), c.tok, opts(ks))
		if CodeOf(err) != c.code {
			t.Errorf("%s: code %q (%v), want %q", c.name, CodeOf(err), err, c.code)
		}
	}
}

// TestAccessTokenLifetimeLimits: a machine resource server refuses a 10-minute token that a user resource server accepts.
func TestAccessTokenLifetimeLimits(t *testing.T) {
	s := newES256(t, "k1")
	tok := goodToken(t, s) // 10 minutes
	o := opts(keysFor(s))
	if _, err := VerifyAccessToken(context.Background(), tok, o); err != nil {
		t.Fatalf("user limit: %v", err)
	}
	o.MaxLifetime = MachineLifetime
	_, err := VerifyAccessToken(context.Background(), tok, o)
	wantCode(t, err, CodeExpired)
}

// TestAccessTokenSkew: a token just expired is accepted inside the skew and refused outside it, and the skew is capped at 60 seconds.
func TestAccessTokenSkew(t *testing.T) {
	s := newES256(t, "k1")
	c := goodClaims()
	c["exp"] = epoch.Add(-20 * time.Second).Unix()
	c["iat"] = epoch.Add(-5 * time.Minute).Unix()
	tok := compact(t, map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "k1"}, c, s)
	o := opts(keysFor(s))
	if _, err := VerifyAccessToken(context.Background(), tok, o); err != nil {
		t.Fatalf("inside the default skew: %v", err)
	}
	o.Skew = time.Second
	_, err := VerifyAccessToken(context.Background(), tok, o)
	wantCode(t, err, CodeExpired)
	c["exp"] = epoch.Add(-90 * time.Second).Unix()
	tok = compact(t, map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "k1"}, c, s)
	o.Skew = time.Hour // capped at MaxSkew
	_, err = VerifyAccessToken(context.Background(), tok, o)
	wantCode(t, err, CodeExpired)
}

// TestAccessTokenAcceptsAudienceListAndFullType: an `aud` list that contains ours and the `application/at+jwt` typ are accepted.
func TestAccessTokenAcceptsAudienceListAndFullType(t *testing.T) {
	s := newES256(t, "k1")
	c := goodClaims()
	c["aud"] = []string{"https://x.example", testAudience}
	tok := compact(t, map[string]any{"alg": "ES256", "typ": "application/at+jwt", "kid": "k1"}, c, s)
	if _, err := VerifyAccessToken(context.Background(), tok, opts(keysFor(s))); err != nil {
		t.Fatal(err)
	}
}

// TestAlgorithmListCanOnlyBeNarrowed: a caller cannot enable an algorithm outside the contract's list, and can restrict to fewer.
func TestAlgorithmListCanOnlyBeNarrowed(t *testing.T) {
	s := newEdDSA(t, "k1")
	o := opts(keysFor(s))
	o.Algorithms = []Algorithm{"HS256", ES256}
	_, err := VerifyAccessToken(context.Background(), goodToken(t, s), o)
	wantCode(t, err, CodeAlgorithm)
	o.Algorithms = []Algorithm{EdDSA}
	if _, err := VerifyAccessToken(context.Background(), goodToken(t, s), o); err != nil {
		t.Fatal(err)
	}
}

// TestKeyTypeMustMatchAlgorithm: an RS256 header over an EC key (key confusion) fails the signature check.
func TestKeyTypeMustMatchAlgorithm(t *testing.T) {
	ec := newES256(t, "k1")
	tok := compact(t, map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "k1"}, goodClaims(), ec)
	_, err := VerifyAccessToken(context.Background(), tok, opts(keysFor(ec)))
	wantCode(t, err, CodeSignature)
}

// TestErrorsCarryOnlyTheCode: the error text is the code and nothing from the token.
func TestErrorsCarryOnlyTheCode(t *testing.T) {
	s := newES256(t, "k1")
	c := goodClaims()
	c["sub"] = "SECRET-SUBJECT"
	c["iss"] = "https://secret-issuer.example"
	tok := compact(t, map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "k1"}, c, s)
	_, err := VerifyAccessToken(context.Background(), tok, opts(keysFor(s)))
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "secret") || err.Error() != "identity: issuer" {
		t.Fatalf("error = %v", err)
	}
	if CodeOf(nil) != "" || CodeOf(context.Canceled) != "" {
		t.Fatal("CodeOf must be empty for non-verifier errors")
	}
}
