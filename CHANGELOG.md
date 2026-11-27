# Changelog

All notable changes to `identity-contract` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); until the platform's mainnet launch every
release is a patch bump, breaking changes included.

## [Unreleased]

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
