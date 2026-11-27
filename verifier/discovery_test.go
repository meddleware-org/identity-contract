package verifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// goodDiscovery is a document that meets every MUST of section 1 for the test issuer.
func goodDiscovery() map[string]any {
	return map[string]any{
		"issuer": testIssuer, "authorization_endpoint": testIssuer + "/auth", "token_endpoint": testIssuer + "/token",
		"jwks_uri": testIssuer + "/jwks", "revocation_endpoint": testIssuer + "/revoke", "end_session_endpoint": testIssuer + "/logout",
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "private_key_jwt"},
		"dpop_signing_alg_values_supported":              []string{"ES256"},
		"backchannel_logout_supported":                   true,
		"authorization_response_iss_parameter_supported": true,
	}
}

// discoveryWith returns the good document with one field changed or removed (nil removes it).
func discoveryWith(k string, v any) []byte {
	d := goodDiscovery()
	if v == nil {
		delete(d, k)
	} else {
		d[k] = v
	}
	b, _ := json.Marshal(d)
	return b
}

// TestParseDiscovery: the good document passes and each contract MUST, when broken, is refused.
func TestParseDiscovery(t *testing.T) {
	good, _ := json.Marshal(goodDiscovery())
	d, err := ParseDiscovery(good, testIssuer, false)
	if err != nil || d.JWKSURI != testIssuer+"/jwks" {
		t.Fatalf("good document: %v %+v", err, d)
	}
	bad := map[string][]byte{
		"issuer differs":     discoveryWith("issuer", "https://evil.example"),
		"issuer with slash":  discoveryWith("issuer", testIssuer+"/"),
		"plain also offered": discoveryWith("code_challenge_methods_supported", []string{"S256", "plain"}),
		"no S256":            discoveryWith("code_challenge_methods_supported", []string{"plain"}),
		"no pkce list":       discoveryWith("code_challenge_methods_supported", nil),
		"no private_key_jwt": discoveryWith("token_endpoint_auth_methods_supported", []string{"client_secret_basic"}),
		"no dpop algs":       discoveryWith("dpop_signing_alg_values_supported", nil),
		"no iss parameter":   discoveryWith("authorization_response_iss_parameter_supported", false),
		"no back-channel":    discoveryWith("backchannel_logout_supported", false),
		"no revocation":      discoveryWith("revocation_endpoint", nil),
		"no end session":     discoveryWith("end_session_endpoint", nil),
		"no jwks":            discoveryWith("jwks_uri", nil),
	}
	for name, body := range bad {
		if _, err := ParseDiscovery(body, testIssuer, false); CodeOf(err) != CodeDiscovery {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseDiscovery([]byte("{"), testIssuer, false); CodeOf(err) != CodeMalformed {
		t.Errorf("malformed: %v", err)
	}
	if _, err := ParseDiscovery([]byte(`{} {}`), testIssuer, false); CodeOf(err) != CodeMalformed {
		t.Errorf("trailing data: %v", err)
	}
	for _, iss := range []string{"http://id.example", "https://id.example?x=1", "https://id.example#f", "not a url", "https://"} {
		if _, err := ParseDiscovery(good, iss, false); CodeOf(err) != CodeDiscovery {
			t.Errorf("issuer %q accepted", iss)
		}
	}
}

// TestFetchDiscovery reads the document from a test server in development mode and refuses a server that answers with an error.
func TestFetchDiscovery(t *testing.T) {
	var issuer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(404)
			return
		}
		d := goodDiscovery()
		d["issuer"] = issuer
		_ = json.NewEncoder(w).Encode(d)
	}))
	defer srv.Close()
	issuer = srv.URL
	if _, err := FetchDiscovery(context.Background(), srv.Client(), issuer, true); err != nil {
		t.Fatal(err)
	}
	// Outside development mode an http issuer is refused before any request.
	if _, err := FetchDiscovery(context.Background(), srv.Client(), issuer, false); CodeOf(err) != CodeDiscovery {
		t.Fatalf("http issuer: %v", err)
	}
	// A path that is not the discovery path answers 404.
	if _, err := FetchDiscovery(context.Background(), srv.Client(), strings.TrimRight(issuer, "/")+"/other", true); CodeOf(err) != CodeDiscovery {
		t.Fatalf("404: %v", err)
	}
}
