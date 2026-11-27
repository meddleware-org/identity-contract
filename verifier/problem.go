// The uniform error response (contract section 6): RFC 9457 bodies that never say which check refused.

package verifier

import (
	"encoding/json"
	"net/http"
)

// problemType is the media type of an RFC 9457 error body.
const problemType = "application/problem+json"

// Scheme is the authentication scheme named in a `WWW-Authenticate` challenge.
type Scheme string

const (
	// SchemeBearer challenges a bearer access token.
	SchemeBearer Scheme = "Bearer"
	// SchemeDPoP challenges a DPoP-bound access token.
	SchemeDPoP Scheme = "DPoP"
)

// WriteProblem writes the uniform error response of contract section 6: a status, an RFC 9457 body that names nothing but the status, and for
// 401 a `WWW-Authenticate: <scheme> error="invalid_token"` challenge. The reason a check failed is never in the response (it would help an
// attacker); the service logs CodeOf(err) instead.
func WriteProblem(w http.ResponseWriter, status int, scheme Scheme) {
	h := w.Header()
	h.Set("Content-Type", problemType)
	h.Set("Cache-Control", "no-store")
	if status == http.StatusUnauthorized {
		h.Set("WWW-Authenticate", string(scheme)+` error="invalid_token"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status})
}

// StatusFor maps a verifier error to the response status of section 6: 401 for a credential that is bad, 503 never comes from here
// (a missing dependency is the caller's to report), and 403 is for a good credential that is not allowed, which only the caller can say.
func StatusFor(err error) int {
	if err == nil {
		return http.StatusOK
	}
	return http.StatusUnauthorized
}
