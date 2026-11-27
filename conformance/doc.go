// Package conformance is the contract test suite (identity contract, section 9): tests that run against a live provider and assert the MUSTs
// of the contract that can be checked without a browser, using the first-party verifier as the relying party.
//
// The suite is skipped unless CONF_ISSUER is set, so `go test ./...` stays hermetic. A provider is described to it by environment variables:
//
//	CONF_ISSUER           the issuer URL (CONF_ALLOW_INSECURE=1 allows http for a local provider)
//	CONF_MACHINE_CLIENT   a machine client that authenticates with private_key_jwt (ES256) and is issued DPoP-bound at+jwt tokens
//	CONF_MACHINE_KEY      path to its EC P-256 private key (PEM)
//	CONF_MACHINE_KID      the key id the provider has registered for it
//	CONF_AUDIENCE         the audience its tokens must carry
//	CONF_SCOPE            a scope it is granted
//
// The browser parts (the authorization-code flow with a passkey) are in the conformance/browser directory.
package conformance
