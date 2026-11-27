# Security Policy

## Scope

This policy covers security issues in the `verifier` package and the contract it implements:

- Acceptance of a token or proof that should be refused: a signature, algorithm, key-type, audience, issuer, lifetime, `typ`, `cnf.jkt`, `htm`/`htu`/`ath` or replay check that can be bypassed.
- A way to make the verifier trust a key it should not (a discovery or JWKS document that is accepted although it breaks the contract).
- A response or error that discloses what a token held or which check refused.
- A weakness in the contract text itself (`docs/CONTRACT.md`).

It does not cover the identity provider that issues the tokens (report Keycloak issues upstream), the Go standard library (report to the [Go security team](https://go.dev/security)), or a
service that does not use the library as documented.

## Security model (invariants)

A report that shows any of these violated is in scope and treated as high severity:

1. **Algorithms are pinned.** ES256, EdDSA and RS256 only for access tokens, ES256 and EdDSA for DPoP proofs; never `none`, never an HMAC, never one chosen by the token.
2. **The key type must match the algorithm.**
3. **Fail closed.** An unknown key, an unusable key set, a full or missing replay cache and a missing `cnf.jkt` where DPoP is required are refusals.
4. **Errors never carry token contents.**

## Reporting a vulnerability

Report privately through GitHub's "Report a vulnerability" (Security tab of this repository) or by email to the address in the organisation profile. Please include the input that is wrongly
accepted or refused and the version. You will get an answer within seven days. Please do not open a public issue for a vulnerability.

## Supported versions

Until the platform's mainnet launch only the latest release is supported (patch releases, breaking changes included).
