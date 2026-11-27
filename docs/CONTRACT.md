# The platform identity contract (draft v1, 2026-11-20)

Status: **draft** (ADR-0016 in the Meddleware workspace, Accepted 2026-11-20). This file is the contract's canonical text from the first release of this repository. It is the one interface every Meddleware service, console, Worker and client may rely on for sign-in
and authorization. It is written against **standards, not against a product**: Keycloak is the reference implementation, and any provider that passes the
contract test suite (FU-0190) is a drop-in replacement. A service that needs something not in this contract asks for the contract to change; it does not reach
into the provider. Words MUST, SHOULD and MAY are used as in RFC 2119.

Checked against: OpenID Connect Core and Discovery; RFC 6749, 6750, 7009, 7523, 7636, 8176, 8414, 9068, 9207, 9449, 9457 and 9700 (status and obsoletion
checked on rfc-editor.org, 2026-11-20); OpenID Connect RP-Initiated and Back-Channel Logout; OpenID AuthZEN 1.0; W3C WebAuthn. "OAuth 2.1" is an active IETF
draft (revision 17) and is cited only as a target profile.

## 1. Issuer and discovery

- One **issuer URL** per environment, held as configuration by every relying party and resource server (`ISSUER`); nothing else about the provider is hard-coded.
  Everything else comes from discovery: `/.well-known/openid-configuration` (OpenID Connect Discovery), with RFC 8414 metadata available alongside.
- The discovery document MUST state: `issuer` equal to the configured value; `authorization_response_iss_parameter_supported: true`; `code_challenge_methods_supported`
  containing **only `S256`**; `token_endpoint_auth_methods_supported` including `private_key_jwt`; `dpop_signing_alg_values_supported`; `revocation_endpoint`;
  `end_session_endpoint`; `backchannel_logout_supported: true`; `jwks_uri`.
- A relying party MUST refuse a discovery document whose `issuer` differs from its configured issuer (string equality), and MUST refuse a non-`https` issuer outside
  the development mode.
- Keys come from `jwks_uri`, cached; an unknown `kid` triggers one refresh at most every 30 seconds (the existing verifiers' rule); the cache is bounded in size and age.

## 2. Access tokens (RFC 9068)

- Access tokens for our APIs are **JWTs with header `typ: at+jwt`**, signed with an algorithm from a short allow-list pinned in the verifier (**ES256, EdDSA or RS256**;
  never `none`, never an HMAC algorithm, never an algorithm taken from the token).
- Required claims: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`, `scope`. Lifetime at most **5 minutes** for machine clients and 15 minutes for users; clock
  skew tolerance at most 60 seconds.
- **Audience.** Every resource server has one fixed audience URI (for example `https://walrus-storage-relay-origin.meddleware.dev`, `https://registry.meddleware.co.uk`) and MUST reject a
  token whose `aud` does not contain it. The provider assigns audiences by configuration per client (audience mappers), because RFC 8707 resource indicators are not implemented
  by Keycloak (FU-0195); a provider that implements RFC 8707 may use it additionally.
- `sub` is an **opaque, stable internal identifier**; never an email address and never a wallet address. Wallet addresses are separate claims, issued only to a client that asks for
  the `wallets` scope. No personal data in access tokens.
- A token bound to a key carries `cnf.jkt` (section 5).

## 3. ID tokens and the consoles (backend-for-frontend)

- Browser consoles do not hold tokens (AUTH-M7). The console's **backend** is the confidential client: authorization code with **PKCE S256**, **exact** redirect URIs, `state` and `nonce`,
  `iss` checked on the authorization response (RFC 9207), then a server-side session behind a `__Host-` cookie (`Secure; HttpOnly; SameSite=Lax; Path=/`, no `Domain`).
- ID token checks, in the verifier: signature (pinned algorithm), `iss`, `aud` equal to the client id, `exp`, `nbf` if present, `nonce`, `azp` if present, `sub` present.
- **Assurance.** The console requires a phishing-resistant sign-in: it requests `acr_values` for the platform's phishing-resistant level and MUST verify the returned `acr`, and MUST
  verify `amr` (RFC 8176) contains a hardware- or software-key value together with user presence and verification. The exact `acr` and `amr` strings the reference provider emits
  are fixed by the spike (FU-0182) and written here; they are not guessed.
- **Logout.** RP-Initiated Logout with `id_token_hint`, and **back-channel logout**: each backend exposes an endpoint that verifies the logout token and deletes the session named by `sid`.
- Session lifetimes: absolute 12 hours, idle 1 hour for the operator consoles (what Cloudflare Access gives today).

## 4. Authorization decisions (AuthZEN 1.0)

- Object-level decisions are **not** read from token claims. A service asks the policy decision point through the **AuthZEN 1.0 Access Evaluation API**
  (`POST /access/v1/evaluation`: `subject {type, id}`, `resource {type, id}`, `action {name}`, optional `context`).
- **Fail closed**: PDP unreachable means 503 (never allow). Cache allowed decisions at most 30 seconds and denied at most 5 (the existing consoles' rule).
- The reference PDP is OpenFGA; the model keeps today's relations (`Registry` pushers, pullers, admins, listers; `ContentHub` and `LinkInBio` members), written in FU-0191.
  A token's `roles` claim may admit a console (coarse), but never replaces the check.

## 5. Machine clients and sender-constrained tokens

- Machine clients use **client credentials** and authenticate with **`private_key_jwt` (RFC 7523)**, ES256, with the public key registered at the provider. A shared client secret is allowed only
  for in-cluster clients where key custody would cost more than it protects, and is recorded as such.
- A client whose token **crosses a network we do not control** (today: the access-gate Worker to the relay origin) MUST use **DPoP (RFC 9449)**. The resource-server verifier then checks:
  the proof's `typ` is `dpop+jwt`, its signature matches the `jwk` in its header, `htm` and `htu` match the request, `iat` is within 60 seconds, `jti` has not been seen (replay cache), `ath`
  equals the hash of the access token, and the token's `cnf.jkt` equals the proof key's thumbprint; the server nonce is used when the provider requires it. A bearer token presented where DPoP is required is refused.
- Scopes are per audience and minimal (`relay:upload`, `registry:pull`, `registry:push`, `registry:catalog`). The registry token service maps them to Docker token scopes.

## 6. Errors

- `401` with `WWW-Authenticate: Bearer error="invalid_token"` (or the `DPoP` scheme) for a bad credential; `403` for a good credential that is not allowed; `503` when a dependency the decision needs is down.
  API response bodies use `application/problem+json` (RFC 9457). Errors are uniform: they never say which check failed to an unauthenticated caller; the reason goes to the log, without token contents.

## 7. Revocation

- Short lifetimes are the main control. The consoles hold **no refresh token**; machine clients ask for a new token. Where a refresh token exists, the provider's revocation endpoint
  (RFC 7009) revokes it, and an operator can revoke a session and all its tokens by `sid`. Introspection (RFC 7662) is for opaque tokens only, never on the hot path of a JWT.

## 8. Privacy

- The provider sends nothing out (no telemetry, no update check, no third-party calls) and logs no token, secret or personal data beyond what the record of processing (draft 07, Part 1) records.
- Cookies exist only on the issuer's own host and only once a person has started signing in (the provider's authentication-session cookie appears when its login page loads; recorded in the storage ledger).
- Minimal claims: no email in access tokens; an ID token carries `email` only to a client that asked for the scope.

## 9. Conformance and change

- **Contract test suite** (FU-0190, in the `identity-contract` repository): runs against a provider in the hermetic harness (real PostgreSQL, `verify-full`, pod security settings) and asserts every MUST above: discovery fields,
  `typ`, claims, audience, algorithm pinning, S256-only, redirect exactness, the `iss` parameter, DPoP positive and negative cases (replay, wrong `htu`, wrong `ath`, missing `cnf`), RP-initiated and back-channel
  logout, the AuthZEN calls and fail-closed behaviour. Keycloak must pass it; any other provider that passes it is acceptable.
- **First-party verifier library** (Go; FU-0190): the one implementation of sections 1 to 6 for resource servers and backends; services import it and do not write their own checks.
- The contract has a version (**v1**). A change is a decision (a D-number), announced before it applies, and each service records the version it implements. Exit: replacing the provider means passing the suite.
