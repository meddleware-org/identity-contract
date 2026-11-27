// Tests of the error response and the status mapping.

package verifier

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteProblem: the 401 response carries the challenge and an RFC 9457 body that says nothing about the reason; a 403 has no challenge.
func TestWriteProblem(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteProblem(rec, http.StatusUnauthorized, SchemeDPoP)
	if rec.Code != 401 || rec.Header().Get("WWW-Authenticate") != `DPoP error="invalid_token"` || rec.Header().Get("Content-Type") != "application/problem+json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("401: %d %v", rec.Code, rec.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["status"] != float64(401) || body["title"] != "Unauthorized" || body["type"] != "about:blank" || len(body) != 3 {
		t.Fatalf("body %v (%v)", body, err)
	}
	rec = httptest.NewRecorder()
	WriteProblem(rec, http.StatusForbidden, SchemeBearer)
	if rec.Code != 403 || rec.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("403: %d %v", rec.Code, rec.Header())
	}
	rec = httptest.NewRecorder()
	WriteProblem(rec, http.StatusUnauthorized, SchemeBearer)
	if rec.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Fatal("bearer challenge")
	}
}

// TestStatusFor: any verifier error is a 401, no error is a 200.
func TestStatusFor(t *testing.T) {
	if StatusFor(nil) != 200 || StatusFor(newError(CodeSignature)) != 401 {
		t.Fatal("status mapping")
	}
}
