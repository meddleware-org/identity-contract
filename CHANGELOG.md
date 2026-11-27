# Changelog

All notable changes to `identity-contract` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); until the platform's mainnet launch every
release is a patch bump, breaking changes included.

## [Unreleased]

## [0.0.4] - 2026-11-27

### Added
- `conformance`: `TestAuthZENDecisions` and `TestAuthZENFailsClosed` (contract section 4) against a live policy decision point; OpenFGA 1.23 with the AuthZEN experiment passes (allow, deny, and an
  unreachable PDP or a missing store both end in `ErrUnavailable`).

## [0.0.3] - 2026-11-27

### Added
- Package `conformance`: the contract's behavioural tests against a live provider, driven by environment variables (`CONF_ISSUER` and the rest; every test skips when none is set). Discovery, the
  machine client's DPoP-bound RFC 9068 token and the refusal of bad client assertions, S256-only PKCE by behaviour, and the ID token and back-channel logout token a real browser sign-in produced.
  First provider to pass it: Keycloak 26.8.2 (`k8s/base/auth/tests/keycloak-spike` in the workspace).

### Changed
- `verifier.ParseDiscovery` no longer refuses a document that lists `plain` next to `S256`: Keycloak lists it globally while refusing it for a client configured for S256. The behaviour is proved by
  `conformance.TestPKCEOnlyS256`. Contract section 1 and section 3 say so.
- Contract section 3: `amr` is optional (Keycloak emits none); the required assurance is `acr` = `phr`.

## [0.0.2] - 2026-11-27

### Added
- `verifier.VerifyIDToken` and `verifier.VerifyLogoutToken` (contract section 3): the checks a console's backend makes after the code exchange and on back-channel logout, with configurable `acr` and `amr` requirements.
- Package `authzen` (contract section 4): the AuthZEN 1.0 Access Evaluation client, with the 30-second and 5-second cache lifetimes and the fail-closed rule.

## [0.0.1] - 2026-11-27

### Added
- The contract, draft v1 (`docs/CONTRACT.md`).
- Package `verifier` (standard library only): discovery checks, the bounded JWKS cache with the 30-second refresh rule, RFC 9068 access-token verification with a pinned algorithm list,
  RFC 9449 DPoP proof verification with a replay cache, RFC 7638 thumbprints and the uniform RFC 9457 error response. Not yet: the AuthZEN client, the console backend's ID-token and logout
  checks and the conformance suite against a live provider.
