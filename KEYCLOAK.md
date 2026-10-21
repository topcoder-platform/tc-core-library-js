# Keycloak M2M prerelease

Version `4.0.0-keycloak.0` is confined to `keycloak_m2M`. Do not publish it as npm
`latest` or replace `master`. Pin its reviewed Git commit in each opted-in service.
Unmigrated Auth0 services keep their current dependency and deployment configuration.

All public authentication factories require `M2M_PROVIDER=keycloak` and explicit
`KEYCLOAK_ISSUER`, `KEYCLOAK_AUDIENCE`, and `KEYCLOAK_TOKEN_URL` settings. Missing
settings fail at initialization. Token generation never falls back to Auth0.
`KEYCLOAK_JWKS_URL` defaults to the configured realm's `/protocol/openid-connect/certs`.
All URLs must be HTTPS and are deployment configuration, never token-derived URLs.

## Deployment configuration

```dotenv
M2M_PROVIDER=keycloak
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

For a deliberate overlap window, `LEGACY_M2M_ISSUERS` (a subset of `VALID_ISSUERS`)
and `LEGACY_M2M_AUDIENCE` allow RS256 Auth0 machine validation through the same
normalizer. This does not enable Auth0 issuance. Omit them to reject Auth0 machines.
Remove overlap only after all calling workloads and cached tokens have migrated.

## Shared API

- `auth.createValidator(options?).verify(token)` returns a verified `Principal`.
  It throws/rejects a sanitized 401 `AuthenticationError` on invalid tokens or keys.
- `middleware.jwtAuthenticator(options?)` assigns that same principal to both
  `req.authUser` and `req.user`. It invokes `next(error)` for invalid/missing Bearer
  authentication. Optional-auth routes must deliberately skip absent headers.
- `auth.hasScopes(principal, required, mode = 'all')` checks exact scopes for
  services only. Use `mode = 'any'` only when that endpoint's documented permission
  policy is OR. Empty/invalid requirements throw; this does not make a route public.
- `auth.m2m(options?).getMachineToken(clientId?, secret?, scope?)` requests a
  Keycloak token. Prefer no arguments and the explicit `KEYCLOAK_*` environment
  credentials. Configuration options override the environment. Explicit credential
  arguments remain available for wrappers, but must be Keycloak credentials.
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

Each token provider has its own cache. HMAC cache keys isolate credentials and
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
