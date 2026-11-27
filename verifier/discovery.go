package verifier

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxDiscoveryBytes bounds a discovery document.
const maxDiscoveryBytes = 1 << 20

// Discovery is the part of the OpenID Connect discovery document the contract relies on (section 1).
type Discovery struct {
	// Issuer is the issuer URL the provider states; it must equal the configured one.
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint is where a console's backend sends the browser.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint is where codes and client credentials are exchanged.
	TokenEndpoint string `json:"token_endpoint"`
	// JWKSURI is where the signing keys are published.
	JWKSURI string `json:"jwks_uri"`
	// RevocationEndpoint revokes refresh tokens (RFC 7009).
	RevocationEndpoint string `json:"revocation_endpoint"`
	// EndSessionEndpoint ends the session (RP-Initiated Logout).
	EndSessionEndpoint string `json:"end_session_endpoint"`
	// CodeChallengeMethods lists the PKCE methods; the contract allows only S256.
	CodeChallengeMethods []string `json:"code_challenge_methods_supported"`
	// TokenEndpointAuthMethods lists client authentication methods; private_key_jwt must be among them.
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	// DPoPSigningAlgs lists the DPoP proof algorithms the provider accepts.
	DPoPSigningAlgs []string `json:"dpop_signing_alg_values_supported"`
	// BackchannelLogoutSupported says the provider sends back-channel logout tokens.
	BackchannelLogoutSupported bool `json:"backchannel_logout_supported"`
	// IssParameterSupported says authorization responses carry `iss` (RFC 9207).
	IssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

// ParseDiscovery checks a discovery document against the contract and returns it. The issuer must equal the configured one by string
// equality and must be https unless allowInsecure is set; the fields section 1 lists must be present with the stated values.
func ParseDiscovery(body []byte, issuer string, allowInsecure bool) (*Discovery, error) {
	if !validIssuer(issuer, allowInsecure) {
		return nil, newError(CodeDiscovery)
	}
	var d Discovery
	if err := decodeStrict(body, &d); err != nil {
		return nil, newError(CodeMalformed)
	}
	// The issuer in the document must be the one the relying party was configured with: nothing else is trusted to name it.
	if d.Issuer != issuer {
		return nil, newError(CodeDiscovery)
	}
	if !d.IssParameterSupported || !d.BackchannelLogoutSupported {
		return nil, newError(CodeDiscovery)
	}
	// S256 and nothing else: a provider that still offers `plain` fails the contract.
	if len(d.CodeChallengeMethods) != 1 || d.CodeChallengeMethods[0] != "S256" {
		return nil, newError(CodeDiscovery)
	}
	if !contains(d.TokenEndpointAuthMethods, "private_key_jwt") || len(d.DPoPSigningAlgs) == 0 {
		return nil, newError(CodeDiscovery)
	}
	if d.RevocationEndpoint == "" || d.EndSessionEndpoint == "" || d.JWKSURI == "" {
		return nil, newError(CodeDiscovery)
	}
	return &d, nil
}

// FetchDiscovery reads `<issuer>/.well-known/openid-configuration` and checks it with ParseDiscovery.
func FetchDiscovery(ctx context.Context, client *http.Client, issuer string, allowInsecure bool) (*Discovery, error) {
	if !validIssuer(issuer, allowInsecure) {
		return nil, newError(CodeDiscovery)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, newError(CodeDiscovery)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, newError(CodeDiscovery)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, newError(CodeDiscovery)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes))
	if err != nil {
		return nil, newError(CodeDiscovery)
	}
	return ParseDiscovery(body, issuer, allowInsecure)
}

// validIssuer is true for an https URL with a host and no query or fragment (http only in development mode).
func validIssuer(issuer string, allowInsecure bool) bool {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "https" || (allowInsecure && u.Scheme == "http")
}

// contains reports whether list holds s.
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
