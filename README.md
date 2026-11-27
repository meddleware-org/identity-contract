# identity-contract

The platform's **identity contract**: one standards-based interface for sign-in and authorization that every Meddleware service, console, Worker and client relies on, the
**first-party verifier** (a Go library, standard library only) that implements it for resource servers and console backends, and (next) the **conformance suite** that decides whether a
provider meets it. The contract is written against standards, not against a product: [Keycloak](https://www.keycloak.org/) is the reference implementation, and any provider that
passes the suite is a drop-in replacement. Licence: BSD Zero Clause ([0BSD](LICENSE)).

- **The contract:** [docs/CONTRACT.md](docs/CONTRACT.md), draft v1 (OpenID Connect Core and Discovery, RFC 9068 access tokens, RFC 9449 DPoP, RFC 7523, RFC 7636, RFC 9207, RFC 9457, AuthZEN 1.0).
- **What is built today:** package `verifier`: discovery checks (section 1), a bounded JWKS cache with the 30-second refresh rule (section 1), access-token verification with a pinned algorithm
  list (section 2), ID-token and back-channel-logout-token verification for a console's backend (section 3), DPoP proof verification with a replay cache (section 5) and the uniform error
  response (section 6); package `authzen`: the AuthZEN 1.0 Access Evaluation client with the contract's cache lifetimes and fail-closed rule (section 4). Not yet: the Rust crate for the two
  consoles and the conformance suite against a live provider (section 9).
- **Dependencies:** none (Go standard library only), so a service that imports it adds no supply-chain surface.
- **Context for contributors and agents:** [CLAUDE.md](CLAUDE.md); how to build and propose a change: [CONTRIBUTING.md](CONTRIBUTING.md).

## Use

```go
import "github.com/meddleware-org/identity-contract/verifier"

// Once, at start-up: check the provider's discovery document and build the key cache from its jwks_uri.
disc, err := verifier.FetchDiscovery(ctx, http.DefaultClient, os.Getenv("ISSUER"), false)
fetch, err := verifier.FetchJWKS(http.DefaultClient, disc.JWKSURI, false)
keys := verifier.NewKeySet(fetch)

// Per request: verify the access token; on a DPoP-bound token also verify the proof.
claims, err := verifier.VerifyAccessToken(r.Context(), token, verifier.Options{
	Issuer: issuer, Audience: "https://registry.example", Keys: keys, MaxLifetime: verifier.MachineLifetime,
})
if err != nil {
	log.Printf("refused: %s", verifier.CodeOf(err)) // the code, never the token
	verifier.WriteProblem(w, verifier.StatusFor(err), verifier.SchemeBearer)
	return
}
```

For a DPoP-bound token call `VerifyDPoP(proof, DPoPRequest{...}, replayCache)` with the token's `ConfirmationJKT`; a token without one is refused where DPoP is required.

## Develop

```bash
go vet ./...
go test -race -cover ./...
golangci-lint run          # v2, with the documentation rules of .golangci.yml
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

## Open standards

Which standards the verifier speaks and the tests that prove each are listed in [CLAUDE.md](CLAUDE.md) ("Conventions") and in the contract's header; the platform-wide list is
[Standards we use](https://meddleware.dev/platform/standards).
