package verifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
)

// maxTokenBytes bounds a token or proof before any parsing: no legitimate one is larger.
const maxTokenBytes = 16 * 1024

// Algorithm names a JOSE signature algorithm the verifier supports.
type Algorithm string

// The algorithms of the contract's allow-list (section 2). Nothing else is ever accepted, whatever a token header says.
const (
	// ES256 is ECDSA over P-256 with SHA-256 (the signature is the raw 64-byte r||s).
	ES256 Algorithm = "ES256"
	// EdDSA is Ed25519.
	EdDSA Algorithm = "EdDSA"
	// RS256 is RSASSA-PKCS1-v1_5 with SHA-256 (keys of at least 2048 bits).
	RS256 Algorithm = "RS256"
)

// header is the JOSE header fields the verifier reads.
type header struct {
	// Alg is the signature algorithm the token claims; checked against the allow-list, never trusted.
	Alg string `json:"alg"`
	// Typ is the media type of the token (at+jwt, dpop+jwt).
	Typ string `json:"typ"`
	// Kid names the verification key.
	Kid string `json:"kid"`
	// JWK is the embedded public key of a DPoP proof.
	JWK *JWK `json:"jwk"`
}

// parsed is a compact JWS split into its parts and decoded.
type parsed struct {
	// hdr is the decoded JOSE header.
	hdr header
	// claims is the payload as a generic object, decoded with numbers kept exact.
	claims map[string]any
	// signingInput is `header.payload`, the bytes the signature covers.
	signingInput []byte
	// sig is the decoded signature.
	sig []byte
}

// parse splits and decodes a compact JWS. It refuses anything that is not exactly three base64url parts, JSON objects for the header and
// the payload, or larger than maxTokenBytes. It checks nothing about the contents.
func parse(token string) (*parsed, error) {
	if len(token) == 0 || len(token) > maxTokenBytes {
		return nil, newError(CodeMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, newError(CodeMalformed)
	}
	hb, errH := b64(parts[0])
	pb, errP := b64(parts[1])
	sig, errS := b64(parts[2])
	if errH != nil || errP != nil || errS != nil {
		return nil, newError(CodeMalformed)
	}
	p := &parsed{signingInput: []byte(parts[0] + "." + parts[1]), sig: sig}
	// Strict decoding: unknown header fields are fine, but a duplicate-key or trailing-garbage document is refused by the decoder's end check.
	if err := decodeStrict(hb, &p.hdr); err != nil {
		return nil, newError(CodeMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	if err := dec.Decode(&p.claims); err != nil || dec.More() || p.claims == nil {
		return nil, newError(CodeMalformed)
	}
	return p, nil
}

// decodeStrict decodes one JSON value and refuses trailing data.
func decodeStrict(data []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return newError(CodeMalformed)
	}
	return nil
}

// allowed reports whether the algorithm name is on the list the caller pinned, and returns it typed. The comparison is exact and
// case-sensitive, so "none", "HS256" and "es256" all fail.
func allowed(name string, list []Algorithm) (Algorithm, bool) {
	for _, a := range list {
		if string(a) == name {
			return a, true
		}
	}
	return "", false
}

// verifySignature checks the signature over the signing input with a key whose type must match the algorithm.
func verifySignature(alg Algorithm, key crypto.PublicKey, signingInput, sig []byte) error {
	switch alg {
	case ES256:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return newError(CodeSignature)
		}
		sum := sha256.Sum256(signingInput)
		if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return newError(CodeSignature)
		}
	case EdDSA:
		pub, ok := key.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(pub, signingInput, sig) {
			return newError(CodeSignature)
		}
	case RS256:
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return newError(CodeSignature)
		}
		sum := sha256.Sum256(signingInput)
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
			return newError(CodeSignature)
		}
	default:
		return newError(CodeAlgorithm)
	}
	return nil
}
