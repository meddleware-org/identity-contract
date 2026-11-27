// Tests of ID-token and logout-token verification: the accepting cases and each refusal of contract section 3.

package verifier

import (
	"context"
	"testing"
	"time"
)

// idClaims is a valid ID token payload for the console client.
func idClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "u_123", "aud": "console", "iat": epoch.Unix(), "exp": epoch.Add(10 * time.Minute).Unix(),
		"nonce": "n-1", "sid": "s-1", "acr": "phr", "amr": []string{"hwk", "uv"},
	}
}

// idOpts is the standard ID-token options for the tests.
func idOpts(ks *KeySet) IDOptions {
	return IDOptions{Issuer: testIssuer, ClientID: "console", Nonce: "n-1", Keys: ks, AcceptedACR: []string{"phr"}, RequiredAMR: []string{"hwk", "uv"}, Now: func() time.Time { return epoch }}
}

// idToken signs the claims with a plain JWT header.
func idToken(t *testing.T, s *signer, c map[string]any) string {
	t.Helper()
	return compact(t, map[string]any{"alg": s.alg, "typ": "JWT", "kid": s.jwk.Kid}, c, s)
}

// TestIDTokenAccepted: a token meeting section 3 verifies, and its session id and assurance come back.
func TestIDTokenAccepted(t *testing.T) {
	s := newES256(t, "k1")
	c, err := VerifyIDToken(context.Background(), idToken(t, s, idClaims()), idOpts(keysFor(s)))
	if err != nil || c.Subject != "u_123" || c.SessionID != "s-1" || c.ACR != "phr" || len(c.AMR) != 2 {
		t.Fatalf("%v %+v", err, c)
	}
	// Several audiences are fine when the authorized party is the client.
	m := idClaims()
	m["aud"] = []string{"console", "other"}
	m["azp"] = "console"
	if _, err := VerifyIDToken(context.Background(), idToken(t, s, m), idOpts(keysFor(s))); err != nil {
		t.Fatalf("with azp: %v", err)
	}
}

// TestIDTokenRefusals: each way an ID token can be wrong, with the code the log shows.
func TestIDTokenRefusals(t *testing.T) {
	s := newES256(t, "k1")
	ks := keysFor(s)
	with := func(k string, v any) map[string]any { c := idClaims(); c[k] = v; return c }
	without := func(k string) map[string]any { c := idClaims(); delete(c, k); return c }
	cases := []struct {
		name string
		tok  string
		o    IDOptions
		code Code
	}{
		{"an access token", compact(t, map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "k1"}, idClaims(), s), idOpts(ks), CodeType},
		{"wrong issuer", idToken(t, s, with("iss", "https://evil.example")), idOpts(ks), CodeIssuer},
		{"audience is not the client", idToken(t, s, with("aud", "someone-else")), idOpts(ks), CodeAudience},
		{"several audiences without azp", idToken(t, s, with("aud", []string{"console", "x"})), idOpts(ks), CodeAudience},
		{"azp is another client", idToken(t, s, with("azp", "x")), idOpts(ks), CodeAudience},
		{"expired", idToken(t, s, with("exp", epoch.Add(-time.Hour).Unix())), idOpts(ks), CodeExpired},
		{"not yet valid", idToken(t, s, with("nbf", epoch.Add(time.Hour).Unix())), idOpts(ks), CodeExpired},
		{"bad nbf", idToken(t, s, with("nbf", "soon")), idOpts(ks), CodeClaim},
		{"issued in the future", idToken(t, s, with("iat", epoch.Add(time.Hour).Unix())), idOpts(ks), CodeExpired},
		{"wrong nonce", idToken(t, s, with("nonce", "other")), idOpts(ks), CodeBinding},
		{"missing nonce", idToken(t, s, without("nonce")), idOpts(ks), CodeBinding},
		{"missing sub", idToken(t, s, without("sub")), idOpts(ks), CodeClaim},
		{"missing exp", idToken(t, s, without("exp")), idOpts(ks), CodeClaim},
		{"acr not accepted", idToken(t, s, with("acr", "password")), idOpts(ks), CodeBinding},
		{"missing acr", idToken(t, s, without("acr")), idOpts(ks), CodeBinding},
		{"amr lacks user verification", idToken(t, s, with("amr", []string{"hwk"})), idOpts(ks), CodeBinding},
		{"no amr", idToken(t, s, without("amr")), idOpts(ks), CodeBinding},
		{"alg none", compact(t, map[string]any{"alg": "none", "typ": "JWT", "kid": "k1"}, idClaims(), nil), idOpts(ks), CodeAlgorithm},
		{"signed by another key", idToken(t, newES256(t, "k1"), idClaims()), idOpts(ks), CodeSignature},
		{"malformed", "x", idOpts(ks), CodeMalformed},
	}
	for _, c := range cases {
		if _, err := VerifyIDToken(context.Background(), c.tok, c.o); CodeOf(err) != c.code {
			t.Errorf("%s: code %q (%v), want %q", c.name, CodeOf(err), err, c.code)
		}
	}
	// No nonce configured: the code flow is refused, not silently accepted.
	o := idOpts(ks)
	o.Nonce = ""
	if _, err := VerifyIDToken(context.Background(), idToken(t, s, idClaims()), o); CodeOf(err) != CodeClaim {
		t.Errorf("no configured nonce: %v", err)
	}
	// With no assurance configured only the signature, claims and nonce are checked.
	o = idOpts(ks)
	o.AcceptedACR, o.RequiredAMR = nil, nil
	if _, err := VerifyIDToken(context.Background(), idToken(t, s, without("acr")), o); err != nil {
		t.Errorf("assurance not configured: %v", err)
	}
}

// logoutClaims is a valid back-channel logout token payload.
func logoutClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer, "aud": "console", "iat": epoch.Unix(), "exp": epoch.Add(2 * time.Minute).Unix(), "jti": "l-1",
		"sid": "s-1", "events": map[string]any{backchannelEvent: map[string]any{}},
	}
}

// logoutToken signs the claims with the logout+jwt header.
func logoutToken(t *testing.T, s *signer, c map[string]any) string {
	t.Helper()
	return compact(t, map[string]any{"alg": s.alg, "typ": "logout+jwt", "kid": s.jwk.Kid}, c, s)
}

// logoutOpts is the standard logout options for the tests.
func logoutOpts(ks *KeySet) LogoutOptions {
	return LogoutOptions{Issuer: testIssuer, ClientID: "console", Keys: ks, Replay: NewMemoryReplayCache(10), Now: func() time.Time { return epoch }}
}

// TestLogoutTokenAcceptedOnce: a good logout token names the session, and a second use is a replay.
func TestLogoutTokenAcceptedOnce(t *testing.T) {
	s := newES256(t, "k1")
	o := logoutOpts(keysFor(s))
	tok := logoutToken(t, s, logoutClaims())
	c, err := VerifyLogoutToken(context.Background(), tok, o)
	if err != nil || c.SessionID != "s-1" || c.JTI != "l-1" || c.Subject != "" {
		t.Fatalf("%v %+v", err, c)
	}
	if _, err := VerifyLogoutToken(context.Background(), tok, o); CodeOf(err) != CodeReplay {
		t.Fatalf("replay: %v", err)
	}
	// A logout for a whole subject (no sid) is fine.
	m := logoutClaims()
	delete(m, "sid")
	m["sub"] = "u_9"
	m["jti"] = "l-2"
	if c, err := VerifyLogoutToken(context.Background(), logoutToken(t, s, m), o); err != nil || c.Subject != "u_9" {
		t.Fatalf("subject logout: %v %+v", err, c)
	}
}

// TestLogoutTokenRefusals: each rule of Back-Channel Logout section 2.6.
func TestLogoutTokenRefusals(t *testing.T) {
	s := newES256(t, "k1")
	with := func(k string, v any) map[string]any { c := logoutClaims(); c[k] = v; return c }
	without := func(k string) map[string]any { c := logoutClaims(); delete(c, k); return c }
	cases := []struct {
		name string
		tok  string
		code Code
	}{
		{"an ID token", idToken(t, s, with("jti", "x")), CodeType},
		{"wrong issuer", logoutToken(t, s, with("iss", "https://evil.example")), CodeIssuer},
		{"wrong audience", logoutToken(t, s, with("aud", "x")), CodeAudience},
		{"expired", logoutToken(t, s, with("exp", epoch.Add(-time.Hour).Unix())), CodeExpired},
		{"issued in the future", logoutToken(t, s, with("iat", epoch.Add(time.Hour).Unix())), CodeExpired},
		{"has a nonce", logoutToken(t, s, with("nonce", "n")), CodeClaim},
		{"no events", logoutToken(t, s, without("events")), CodeClaim},
		{"the wrong event", logoutToken(t, s, with("events", map[string]any{"other": map[string]any{}})), CodeClaim},
		{"events of the wrong type", logoutToken(t, s, with("events", "x")), CodeClaim},
		{"neither sub nor sid", logoutToken(t, s, without("sid")), CodeClaim},
		{"no jti", logoutToken(t, s, without("jti")), CodeClaim},
		{"no exp", logoutToken(t, s, without("exp")), CodeClaim},
		{"signed by another key", logoutToken(t, newES256(t, "k1"), logoutClaims()), CodeSignature},
	}
	for _, c := range cases {
		if _, err := VerifyLogoutToken(context.Background(), c.tok, logoutOpts(keysFor(s))); CodeOf(err) != c.code {
			t.Errorf("%s: code %q (%v), want %q", c.name, CodeOf(err), err, c.code)
		}
	}
	// Without a replay cache nothing is accepted.
	o := logoutOpts(keysFor(s))
	o.Replay = nil
	if _, err := VerifyLogoutToken(context.Background(), logoutToken(t, s, logoutClaims()), o); CodeOf(err) != CodeReplay {
		t.Errorf("no cache: %v", err)
	}
}
