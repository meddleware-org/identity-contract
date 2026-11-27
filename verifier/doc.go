// Package verifier is the first-party implementation of the platform identity contract (docs/auth/IDENTITY_CONTRACT.md in the workspace,
// sections 1 to 6) for resource servers and console backends: OpenID Connect discovery checks, a bounded JWKS cache, RFC 9068 access-token
// verification with a pinned algorithm list, RFC 9449 DPoP proof verification with a replay cache, and RFC 9457 error bodies.
//
// A service imports this package and does not write its own token checks. It uses only the standard library, so it adds no dependency to a
// service and no supply-chain surface of its own.
//
// Every failure is an *Error with a short Code and no detail a caller could use to probe the checks: the reason goes to the service's log
// (the Code, never the token), and the response is the uniform one written by WriteProblem.
package verifier
