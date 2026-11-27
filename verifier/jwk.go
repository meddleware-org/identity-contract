// JSON Web Keys (RFC 7517): conversion of a published key to a Go public key with the contract's refusals, and RFC 7638 thumbprints.

package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// minRSABits is the smallest RSA modulus accepted for RS256 keys.
const minRSABits = 2048

// JWK is the part of a JSON Web Key (RFC 7517) the verifier reads: the key type, curve, parameters and the optional id and use.
type JWK struct {
	// Kty is the key type: EC, OKP or RSA.
	Kty string `json:"kty"`
	// Kid is the key id the token header names.
	Kid string `json:"kid,omitempty"`
	// Use is "sig" or empty; a key meant for encryption is not a signature key.
	Use string `json:"use,omitempty"`
	// Crv is the curve of an EC (P-256) or OKP (Ed25519) key.
	Crv string `json:"crv,omitempty"`
	// X is the base64url x coordinate (EC) or public key (OKP).
	X string `json:"x,omitempty"`
	// Y is the base64url y coordinate (EC).
	Y string `json:"y,omitempty"`
	// N is the base64url RSA modulus.
	N string `json:"n,omitempty"`
	// E is the base64url RSA public exponent.
	E string `json:"e,omitempty"`
	// D is a private member; a key that carries one is refused (a JWK in a DPoP header or a JWKS is public).
	D string `json:"d,omitempty"`
}

// b64 decodes unpadded base64url, the encoding of every JOSE value.
func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// PublicKey converts the JWK to a Go public key: *ecdsa.PublicKey (P-256), ed25519.PublicKey or *rsa.PublicKey (at least 2048 bits).
// A key with a private member, an unsupported type or curve, a point not on the curve or a short modulus is refused.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	// A private member means the key was not meant to be published: refuse rather than quietly use it.
	if k.D != "" {
		return nil, newError(CodeKey)
	}
	// A key for encryption cannot verify a signature.
	if k.Use != "" && k.Use != "sig" {
		return nil, newError(CodeKey)
	}
	switch k.Kty {
	case "EC":
		if k.Crv != "P-256" {
			return nil, newError(CodeKey)
		}
		x, errX := b64(k.X)
		y, errY := b64(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, newError(CodeKey)
		}
		// The uncompressed point 0x04||x||y; the parser refuses a point that is not on the curve (an invalid-curve key is an attack, not a key).
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, newError(CodeKey)
		}
		return pub, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, newError(CodeKey)
		}
		x, err := b64(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, newError(CodeKey)
		}
		return ed25519.PublicKey(x), nil
	case "RSA":
		n, errN := b64(k.N)
		e, errE := b64(k.E)
		if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
			return nil, newError(CodeKey)
		}
		// The modulus must be at least 2048 bits.
		mod := new(big.Int).SetBytes(n)
		if mod.BitLen() < minRSABits {
			return nil, newError(CodeKey)
		}
		exp := int(new(big.Int).SetBytes(e).Int64())
		if exp < 3 || exp%2 == 0 {
			return nil, newError(CodeKey)
		}
		return &rsa.PublicKey{N: mod, E: exp}, nil
	default:
		return nil, newError(CodeKey)
	}
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of the key, base64url without padding: the value of `cnf.jkt` in a DPoP-bound token.
func (k JWK) Thumbprint() (string, error) {
	// The required members only, in lexicographic order, with no whitespace: the canonical form RFC 7638 hashes.
	// The canonical thumbprint input (RFC 7638 section 3): only the required members.
	var canon string
	switch k.Kty {
	case "EC":
		canon = `{"crv":` + quote(k.Crv) + `,"kty":"EC","x":` + quote(k.X) + `,"y":` + quote(k.Y) + `}`
	case "OKP":
		canon = `{"crv":` + quote(k.Crv) + `,"kty":"OKP","x":` + quote(k.X) + `}`
	case "RSA":
		canon = `{"e":` + quote(k.E) + `,"kty":"RSA","n":` + quote(k.N) + `}`
	default:
		return "", newError(CodeKey)
	}
	// Hash the canonical text; the result is the `jkt` a DPoP-bound token carries.
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// quote is a JSON string literal for a value that is plain base64url or a curve name.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
