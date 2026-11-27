// Test helpers: key pairs for each algorithm, a compact-JWS builder and the fixed clock and issuer the tests share.

package verifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// issuer and audience are the fixed values the tests configure.
const (
	testIssuer   = "https://id.example"
	testAudience = "https://api.example"
)

// epoch is the fixed "now" of the tests.
var epoch = time.Unix(1_800_000_000, 0).UTC()

// enc is unpadded base64url.
func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signer is a test key pair with its public JWK and a way to sign.
type signer struct {
	// alg is the JOSE algorithm of the key.
	alg string
	// jwk is the public key as published.
	jwk JWK
	// sign signs the signing input.
	sign func(input []byte) []byte
}

// pad32 left-pads a big-endian integer to 32 bytes.
func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// newES256 makes a P-256 signer with the given kid.
func newES256(t *testing.T, kid string) *signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{
		alg: "ES256",
		jwk: JWK{Kty: "EC", Kid: kid, Crv: "P-256", X: enc(pad32(k.X.Bytes())), Y: enc(pad32(k.Y.Bytes()))},
		sign: func(in []byte) []byte {
			sum := sha256.Sum256(in)
			r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
			if err != nil {
				t.Fatal(err)
			}
			return append(pad32(r.Bytes()), pad32(s.Bytes())...)
		},
	}
}

// newEdDSA makes an Ed25519 signer.
func newEdDSA(t *testing.T, kid string) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{alg: "EdDSA", jwk: JWK{Kty: "OKP", Kid: kid, Crv: "Ed25519", X: enc(pub)}, sign: func(in []byte) []byte { return ed25519.Sign(priv, in) }}
}

// newRS256 makes a 2048-bit RSA signer.
func newRS256(t *testing.T, kid string) *signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{
		alg: "RS256",
		jwk: JWK{Kty: "RSA", Kid: kid, N: enc(k.N.Bytes()), E: enc(big.NewInt(int64(k.E)).Bytes())},
		sign: func(in []byte) []byte {
			sum := sha256.Sum256(in)
			sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
			if err != nil {
				t.Fatal(err)
			}
			return sig
		},
	}
}

// compact builds a compact JWS with the given header and claims, signed by s (when s is nil the signature is empty).
func compact(t *testing.T, hdr, claims map[string]any, s *signer) string {
	t.Helper()
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	in := enc(hb) + "." + enc(cb)
	var sig []byte
	if s != nil {
		sig = s.sign([]byte(in))
	}
	return in + "." + enc(sig)
}

// goodClaims is a valid user access token payload at the fixed time.
func goodClaims() map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "u_123", "aud": testAudience, "client_id": "console", "scope": "relay:upload registry:pull",
		"jti": "tok-1", "iat": epoch.Unix(), "exp": epoch.Add(10 * time.Minute).Unix(),
	}
}

// goodToken signs the good claims with an at+jwt header.
func goodToken(t *testing.T, s *signer) string {
	t.Helper()
	return compact(t, map[string]any{"alg": s.alg, "typ": "at+jwt", "kid": s.jwk.Kid}, goodClaims(), s)
}

// keysFor makes a KeySet serving the given signers' public keys, on the fixed clock.
func keysFor(signers ...*signer) *KeySet {
	var jwks []JWK
	for _, s := range signers {
		jwks = append(jwks, s.jwk)
	}
	return NewKeySet(func(context.Context) ([]JWK, error) { return jwks, nil }, WithClock(func() time.Time { return epoch }))
}

// opts is the standard verification options for the tests.
func opts(ks *KeySet) Options {
	return Options{Issuer: testIssuer, Audience: testAudience, Keys: ks, Now: func() time.Time { return epoch }}
}
