# CLAUDE.md — identity-contract

The platform identity contract and its first-party verifier. A Go library (standard library only) that resource servers and console backends import instead of writing their own token
checks, the contract text it implements ([docs/CONTRACT.md](docs/CONTRACT.md)), and, to come, the conformance suite a provider must pass. It is called by every service that authenticates a
caller: the registry token service, the content hub, Link in Bio, the Walrus relay origin verifier and the access-gate Worker's client (ADR-0016 in the Meddleware workspace). It calls only the
provider's discovery and JWKS endpoints.

## Layout

- `verifier/` — the package: `doc.go` (package doc), `errors.go` (the `Error` type and its `Code`s), `jwk.go` (key parsing and RFC 7638 thumbprints), `jwt.go` (compact-JWS parsing, algorithm pinning,
  signature checks), `keyset.go` (the JWKS cache), `discovery.go`, `accesstoken.go`, `dpop.go`, `problem.go`; one `_test.go` for each, with `helpers_test.go` for the key and token builders.
- `docs/CONTRACT.md` — the contract, the canonical text.
- `.github/workflows/go-ci.yml` — lint, test (race + 90 % coverage floor), govulncheck, Trivy.

## Commands

```bash
go vet ./... && go test -race -cover ./...
golangci-lint run
```

## Conventions and hard rules

- **Standard library only.** No third-party dependency: the library is security code and adds no supply-chain surface to its importers. A change that wants a dependency is a decision (D-number).
- **Algorithms are pinned, never read from the token.** ES256, EdDSA and RS256 for access tokens; ES256 and EdDSA for DPoP proofs. `none` and every HMAC fail with `CodeAlgorithm`; a caller can only narrow
  the list (`narrow`), never extend it. The key type must match the algorithm (key-confusion test).
- **Errors say which check refused, never what the token held.** `*Error` is only a `Code`; the response (`WriteProblem`) names nothing. A test asserts that no claim value reaches an error string.
- **Fail closed.** An unknown kid, an unusable key set, a full replay cache, a missing replay cache and a token with no `cnf.jkt` where DPoP is required are all refusals.
- **The JWKS rule:** one refresh at most every 30 seconds whatever the tokens ask for; a failed refresh keeps the old keys; the set is bounded (32 keys, 1 MiB, one hour).
- **The contract changes by decision.** A change to `docs/CONTRACT.md` is a D-number in the workspace log, announced before it applies; the verifier and the tests change in the same commit.
- **Test both directions.** Every rule has an accepting and a refusing test (RFC 7638's own vector pins the thumbprint).

## Documentation rules (workspace documentation standard, D144)

Every file has a header and every identifier a doc comment that starts with its name (the `revive` rules in `.golangci.yml` enforce the exported ones in CI); line comments say why.
`node scripts/check-docs.mjs --report identity-contract` (in the workspace repository) is the gate. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Gotchas

- `go.mod` names a Go 1.26 toolchain; `golangci-lint` v2 is pinned in CI.
- DPoP `htu` is compared by scheme, host and path only (RFC 9449 section 4.3); a caller behind a proxy must pass the URL the client addressed, not the one it received.

## Related

The contract's sections and the ADR (ADR-0016), the migration plan (`docs/auth/IDP_MIGRATION.md`, stage 1) and FU-0182 and FU-0190 are in the Meddleware workspace repository (private).
