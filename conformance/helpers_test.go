// Helpers of the conformance suite: reading the provider description from the environment and the small JOSE toolkit the tests sign with.

package conformance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"testing"
	"time"
)

// provider describes the provider under test, from the environment.
type provider struct {
	// issuer is the configured issuer URL.
	issuer string
	// insecure allows an http issuer (a local provider).
	insecure bool
	// client, keyPath, kid, audience and scope describe the machine client.
	client, keyPath, kid, audience, scope string
}

// need returns the provider under test, or skips the test when none is configured.
func need(t *testing.T) provider {
	t.Helper()
	iss := os.Getenv("CONF_ISSUER")
	if iss == "" {
		t.Skip("CONF_ISSUER is not set: the conformance suite needs a live provider")
	}
	return provider{
		issuer: iss, insecure: os.Getenv("CONF_ALLOW_INSECURE") == "1", client: os.Getenv("CONF_MACHINE_CLIENT"), keyPath: os.Getenv("CONF_MACHINE_KEY"),
		kid: os.Getenv("CONF_MACHINE_KID"), audience: os.Getenv("CONF_AUDIENCE"), scope: os.Getenv("CONF_SCOPE"),
	}
}

// httpClient is the client the suite uses: a short timeout and no redirects followed (a redirect is a result to inspect).
func httpClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// b64 is unpadded base64url.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pad32 left-pads a big-endian integer to 32 bytes.
func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// loadKey reads an EC private key (SEC 1 or PKCS 8 PEM).
func loadKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block in the machine key")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PrivateKey)
}

// signES256 builds a compact ES256 JWS over the header and claims.
func signES256(t *testing.T, k *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	in := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(append(pad32(r.Bytes()), pad32(s.Bytes())...))
}

// publicJWK is the public half of an EC key as a JWK map (for a DPoP proof header).
func publicJWK(k *ecdsa.PrivateKey) map[string]any {
	return map[string]any{"kty": "EC", "crv": "P-256", "x": b64(pad32(k.X.Bytes())), "y": b64(pad32(k.Y.Bytes()))}
}

// newDPoPKey makes a fresh proof key for a DPoP-bound token.
func newDPoPKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// dpopProof signs a DPoP proof for a request, binding it to the access token when one is given.
func dpopProof(t *testing.T, k *ecdsa.PrivateKey, method, url, accessToken, nonce string) string {
	t.Helper()
	claims := map[string]any{"jti": b64(randomBytes(t, 12)), "htm": method, "htu": url, "iat": time.Now().Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = b64(sum[:])
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return signES256(t, k, map[string]any{"alg": "ES256", "typ": "dpop+jwt", "jwk": publicJWK(k)}, claims)
}

// randomBytes returns n random bytes.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
