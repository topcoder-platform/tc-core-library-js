# Keycloak M2M prerelease

Version `4.0.0-keycloak.1` is confined to `keycloak_m2M`. Do not publish it as npm
`latest` or replace `master`. Pin its reviewed Git commit in each opted-in service.
Unmigrated Auth0 services keep their current dependency and deployment configuration.

## Choosing the provider: `USE_KEYCLOAK`

`USE_KEYCLOAK` selects the M2M provider for every factory in this library:

| `USE_KEYCLOAK` | Token issuance (`auth.m2m`) | Machine tokens accepted |
| --- | --- | --- |
| `true` | Keycloak, using `KEYCLOAK_*` | Keycloak; Auth0 too while `LEGACY_M2M_*` is set |
| `false`, empty or unset | Auth0 through `AUTH0_*`, exactly as 3.x | Auth0 via `LEGACY_M2M_*`; Keycloak too while `KEYCLOAK_ISSUER` and `KEYCLOAK_AUDIENCE` are set |

The value is case-insensitive. Any value other than `true`/`false` throws at startup,
so a typo cannot silently pick a provider. To roll back, set `USE_KEYCLOAK=false` and
restart the service; no code or dependency change is needed. Each mode keeps accepting
the other provider's machine tokens (while the settings above are present), so services
can be switched one at a time without rejecting callers that have not switched yet.
Member-token validation is the same in both modes.

Services that need provider-specific settings use the same rule through
`auth.useKeycloak(options?)`, and pass `auth.wrapperSettings(options?)` to
`tc-bus-api-wrapper`, which expects `AUTH0_*` option names in both modes.

## Keycloak mode

With `USE_KEYCLOAK=true`, `KEYCLOAK_ISSUER`, `KEYCLOAK_AUDIENCE` and `KEYCLOAK_TOKEN_URL`
are required. Missing settings fail at initialization. Keycloak token generation never
retries against Auth0; switching providers is always the explicit `USE_KEYCLOAK` change.
`KEYCLOAK_JWKS_URL` defaults to the configured realm's `/protocol/openid-connect/certs`.
All URLs must be HTTPS and are deployment configuration, never token-derived URLs.

## Auth0 mode

With `USE_KEYCLOAK` unset or `false`, `auth.m2m` returns the 3.x Auth0 provider:

- `AUTH0_URL` is the tenant token URL, forwarded as `auth0_url`.
- `AUTH0_PROXY_SERVER_URL` receives the request (default `AUTH0_URL`).
- `AUTH0_AUDIENCE` and optional `AUTH_SCOPE`, `AUTH_PROVIDER` and `AUTH_CONTENT_TYPE` are forwarded.
- `getMachineToken()` defaults to `AUTH0_CLIENT_ID`/`AUTH0_CLIENT_SECRET`.

Missing Auth0 settings reject when a token is requested, not at startup. Tokens are
cached per process until a minute before expiry, as in 3.x. Validation trusts Auth0
machine tokens only through `LEGACY_M2M_ISSUERS` and `LEGACY_M2M_AUDIENCE`; without them
only member tokens (and Keycloak machine tokens, if configured) are accepted.

## Deployment configuration

```dotenv
USE_KEYCLOAK=true
KEYCLOAK_ISSUER=https://keycloak.topcoder-dev.com/realms/topcoder-m2m-dev
KEYCLOAK_AUDIENCE=https://api.topcoder-dev.com
KEYCLOAK_TOKEN_URL=https://keycloak.topcoder-dev.com/m2m/token
KEYCLOAK_TOKEN_FORMAT=json
# Credentials come from workload-scoped encrypted SSM/Secrets Manager references.
KEYCLOAK_CLIENT_ID=<assigned-client-id>
KEYCLOAK_CLIENT_SECRET=<runtime-secret>
# Optional exact scope subset; omit to request this client's approved defaults.
KEYCLOAK_SCOPE=read:groups
```

Confirm the audience against the deployed realm; the example is not automatic
configuration. Set `KEYCLOAK_ALLOWED_CLIENT_IDS` to a JSON string array when a
receiving API additionally restricts machine clients. The default token lifetime
limit is 900 seconds; `KEYCLOAK_MAX_TOKEN_LIFETIME` permits 60–3600 seconds.

Auth0 **member** sessions remain supported. Configure `VALID_ISSUERS` as an exact
JSON string array and `AUTH_USER_AUDIENCES` as a JSON string array. Optional
`AUTH_USER_JWKS` is a JSON issuer-to-JWKS map; otherwise only the already trusted
legacy issuer's conventional JWKS path is used. Existing HS256 member sessions
require `AUTH_SECRET`; HMAC never validates Keycloak machines. Where existing
member tokens have no stable audience contract, explicitly set
`ALLOW_LEGACY_USER_AUDIENCE=true` while retaining issuer/signature/expiry/member-ID
validation. This compatibility exception never applies to machine tokens.

`LEGACY_M2M_ISSUERS` (a subset of `VALID_ISSUERS`) and `LEGACY_M2M_AUDIENCE` allow
RS256 Auth0 machine validation through the same normalizer. `LEGACY_M2M_AUDIENCE` is
one audience or a JSON string array. In Keycloak mode they are an overlap window and
do not enable Auth0 issuance; omit them to reject Auth0 machines once all calling
workloads and cached tokens have migrated. In Auth0 mode they are the machine trust.
Auth0 tenants contain scope names with stray whitespace (DEV has a trailing tab on
`all:achievement`), so Auth0 scope claims split on any whitespace. Keycloak scope
claims keep the exact single-space rule.

## Shared API

- `auth.createValidator(options?).verify(token)` returns a verified `Principal`.
  It throws/rejects a sanitized 401 `AuthenticationError` on invalid tokens or keys.
- `middleware.jwtAuthenticator(options?)` assigns that same principal to both
  `req.authUser` and `req.user`. It invokes `next(error)` for invalid/missing Bearer
  authentication. Optional-auth routes must deliberately skip absent headers.
- `auth.hasScopes(principal, required, mode = 'all')` checks exact scopes for
  services only. Use `mode = 'any'` only when that endpoint's documented permission
  policy is OR. Empty/invalid requirements throw; this does not make a route public.
- `auth.m2m(options?).getMachineToken(clientId?, secret?, scope?)` requests a token
  from the provider `USE_KEYCLOAK` selects. Prefer no arguments: the defaults are
  `KEYCLOAK_CLIENT_ID`/`SECRET` in Keycloak mode and `AUTH0_CLIENT_ID`/`SECRET` in
  Auth0 mode. Configuration options override the environment. Explicit credential
  arguments remain available for wrappers and must belong to the active provider.
- `auth.useKeycloak(options?)` returns the provider decision; it throws `TypeError`
  for values other than `true`/`false`.
- `auth.wrapperSettings(options?)` returns `AUTH0_URL`, `AUTH0_AUDIENCE`,
  `AUTH0_PROXY_SERVER_URL`, `AUTH0_CLIENT_ID` and `AUTH0_CLIENT_SECRET` for the active
  provider (the `KEYCLOAK_*` values in Keycloak mode), ready for `tc-bus-api-wrapper`.
- `auth.verifier().validateToken(token, unusedLegacySecret, callback)` is a callback
  adapter to the same validator, not a separate implementation.

All callers receive authoritative `kind: 'service' | 'user'`, `isMachine`, and
`scopes` fields. A verified service has `clientId`/`azp`, no member `userId`, and
legacy-compatible `azpHash`. Members have numeric positive `userId` and roles;
user OAuth `scope` is removed and `scopes` is empty. Never infer machine identity
again from scopes, `sub`, missing fields, or an unverified decode in a service.
Namespaces default to the two existing Topcoder DEV/production forms and can be
explicitly replaced with `AUTH_USER_CLAIM_NAMESPACES`. Conflicting namespaced
claims are rejected. Scope aliases and route-specific role permissions remain
explicit service policy; no implicit administrator or wildcard grant is added.

Machine verification checks exact issuer, RS256 signature, audience (string or
array), key ID, issued/expiry times, maximum lifetime, grant marker, client ID,
and nonempty scope string. JWKS caches are per trusted issuer and bounded;
unknown-key lookup is rate-limited. Legacy user and machine policies remain
separate. Legacy `lib/auth/*` and `lib/middleware/jwtAuthenticator` imports now delegate
to this same implementation; they cannot select the former permissive policy.

Each Keycloak token provider has its own cache. HMAC cache keys isolate credentials and
canonical requested scopes; endpoints and audience are fixed for the provider.
Concurrent misses share one request, credentials never appear in keys/logs,
and tokens expire from the cache before their signed expiry. Responses are
verified by the same validator and must match the requested scope subset and
client. `clearCache()` clears local reuse but does not revoke existing JWTs.

## Verification and release

Run `nvm use` in this project, then `pnpm install --frozen-lockfile`, `pnpm lint`,
`pnpm test:keycloak`, `pnpm test`, and `pnpm build`. The build syntax-checks the
JavaScript and creates the installable prerelease archive in `dist/`.
The new tests exercise real RSA signing and JWKS responses, negative trust cases,
member/machine separation, explicit overlap, key rotation, credential/cache
isolation, subset scopes, and callback integration. Each consuming service must
also pass its own lint/build and route-policy integration tests before rollout.
