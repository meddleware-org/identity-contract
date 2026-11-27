// Package authzen is a client for the OpenID AuthZEN 1.0 Access Evaluation API, the way a service asks the platform's policy decision point
// whether a subject may perform an action on a resource (identity contract, section 4).
//
// The rules of the contract are built in: a decision that cannot be obtained is an error the caller turns into 503 (never an allow), allowed
// decisions are cached for at most 30 seconds and denied ones for at most 5, and nothing about a request that carries a `context` is cached.
// Like the verifier package it uses only the standard library.
package authzen
