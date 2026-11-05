# tc-core-library-js v4

**4.0.0-rc.3 changes access-token trust. Read MIGRATION.md before upgrading a service accepting legacy HS256 tokens.**

TypeScript primitives for Topcoder v6 services: JWT verification and identity normalization, outbound OAuth client credentials, and Bus API publishing. Requires Node.js 22.13 or later. The package includes CommonJS output and TypeScript declarations; named imports work from TypeScript and ESM, and `require()` works from CommonJS.

```ts
import { createJwtVerifier, createJwtAuthenticator, createM2MClient, createBusApiClient } from 'tc-core-library-js';

const settings = {
  VALID_ISSUERS: process.env.VALID_ISSUERS,
  AUTH_SECRET: process.env.AUTH_SECRET,
  JWT_AUDIENCE: process.env.JWT_AUDIENCE,
  AUTH0_AUDIENCE: process.env.AUTH0_AUDIENCE,
};
const verifier = createJwtVerifier(settings);
const user = await verifier.verify(compactToken);
// Express services use createJwtAuthenticator(settings); it attaches req.authUser.
// Nest services call verifier.verify and translate rejection into UnauthorizedException.
```

## JWT contract

All access-token verification uses one implementation. It verifies the signature against one configured algorithm per issuer, exact issuer, expiration, issuance time, not-before and configured audience. Expiration and issuance time are mandatory in every environment; future `iat`, unsupported algorithms, malformed tokens, missing RSA key IDs and conflicting human/machine claims are rejected. Tokens are limited to 32 KiB. Failures use a generic message and middleware returns HTTP 401.

`VALID_ISSUERS` accepts a JSON string array, a comma-separated list, or an array. No issuer is learned from a token. For the environment-style configuration:

- `AUTH_SECRET` alone **does not enable HS256**. The environment-style contract uses RS256 by default. During a bounded migration only, set `LEGACY_HS256_ISSUERS` to exact trusted legacy issuers and `LEGACY_HS256_ACCEPT_UNTIL` to a UTC ISO timestamp. These issuers use HS256 instead of RS256, require a secret of at least 32 UTF-8 bytes, and may omit audience for existing Topcoder sessions. A holder of that key can still forge tokens until this compatibility policy expires.
- `JWT_AUDIENCE` configures an allowed RSA browser/application audience. `AUTH0_AUDIENCE` configures an allowed RSA API audience. Without either, RSA configuration fails closed. Client-credentials tokens require an audience-bound policy and must match `AUTH0_AUDIENCE` when it is configured; the audience-free legacy HMAC policy is human-only.
- Audience values are server configuration, never decoded from an incoming token. Services accepting Auth0 browser tokens must set `JWT_AUDIENCE` to the intended application's client ID/audience.
- JWKS endpoints are derived only from allowlisted issuers. Explicit policies can override the endpoint. Each verifier has bounded caching, a 5-second network timeout and a per-issuer request limit.

Use explicit policies when issuers require different audiences or algorithms:

```ts
const verifier = createJwtVerifier({
  issuers: [
    { issuer: 'https://auth.example/', algorithm: 'RS256',
      jwksUri: 'https://auth.example/.well-known/jwks.json', audience: 'my-api' },
    { issuer: 'https://api.example', algorithm: 'HS256',
      secret: process.env.AUTH_SECRET, allowMissingAudience: true,
      legacyHs256Until: process.env.LEGACY_HS256_ACCEPT_UNTIL },
  ],
});
```

RS256 policies always require an audience. Only explicitly enabled, time-limited HS256 policies may use `allowMissingAudience`. A single issuer cannot simultaneously accept RS256 and HS256. Every request rechecks the HS256 retirement deadline, so a running process cannot extend compatibility past it. `maxTokenLifetimeSeconds` limits both `exp - iat` and token age; its default and maximum are 86400 seconds and it can be lowered per service. The default clock tolerance is 5 seconds and can be configured between 0 and 60 seconds. HTTPS is required for remote endpoints; loopback HTTP is supported for local tests. Internal HTTP requires an explicit `allowInsecureHttp` opt-in.

For fleet deployment, `JWT_ISSUER_POLICIES` can contain a JSON array of public policies
(`issuer`, `algorithm`, `audience`, `jwksUri`, and temporary legacy compatibility fields).
It is read from configuration or the process environment and takes precedence over
`VALID_ISSUERS`. Programmatic `issuers` takes precedence over that JSON setting.
Secret values are forbidden in JSON policies; temporary HS256 policies receive
`AUTH_SECRET` separately. Use production-only issuers/audiences in production.

For a Topcoder issuer with an isolated asymmetric signer, configure its published
JWKS endpoint explicitly; the API domain's default `/.well-known/jwks.json` does
not automatically exist. Deploy the issuer and its public JWKS endpoint, configure
all verifiers, and coordinate the signing-policy cutover before retiring HS256.
Do not deploy this breaking verifier upgrade into existing legacy sessions without
that migration or an explicit temporary HS256 policy.

The verified identity retains original claims and supplies normalized `roles`, `scopes`, `userId`, `handle`, `email` and `isMachine`. Only exact standard claims and configured namespace prefixes are read. Default namespaces cover Topcoder's production/development domains and API namespaces; custom providers should pass `claimNamespaces`. Numeric user IDs are validated and preserved without lossy conversion. A machine requires `gty: "client-credentials"` with no human ID or roles. Scope presence alone never establishes a machine identity. Route-specific roles, scope aliases, database permissions and active-session checks remain in each service.

`verifySignedJwt(token, key, options)` handles Identity's purpose-bound OTP, resend and email-change proofs. It requires an audience and expiry, pins one algorithm (HS256 by default), and enforces `userId` when supplied. It preserves `JsonWebTokenError`/`TokenExpiredError` for existing flow-specific HTTP responses. It does not replace replay/one-time-token storage.

## Shared access-token denylist (4.0.0-rc.2)

Both `createJwtVerifier()` and `createJwtAuthenticator()` automatically read:

| Environment variable | Matches |
| --- | --- |
| `ACCESS_CONTROL_BLOCKED_SUBJECTS` | Exact, case-sensitive verified JWT `sub` values, for humans or machines |
| `ACCESS_CONTROL_BLOCKED_USER_IDS` | Verified, normalized Topcoder user IDs, including legacy tokens without `sub` |

Set comma-separated values, for example `ACCESS_CONTROL_BLOCKED_SUBJECTS=auth0|example,client@clients`
and `ACCESS_CONTROL_BLOCKED_USER_IDS=123,456`. Whitespace and empty entries are
ignored. Unset or empty values add no blocks. User IDs must be positive decimal
integers within the supported signed 64-bit range; invalid configuration fails
at verifier creation. Subject values are not inferred from user IDs or handles.

The same keys can be supplied in `JwtConfiguration` as comma-separated strings
or string arrays. These entries are **added to** the environment lists; an empty
local setting cannot disable a global block. This also applies to explicit
`issuers` configurations. Each verifier snapshots both lists at creation.

Checks run after signature/issuer/audience validation and identity normalization,
before an identity is returned. Either matching list rejects the token with the
existing generic authentication error; middleware returns 401 without exposing
the blocked identifier. Administrator roles and machine scopes do not bypass it.

For v6 ECS deployments, use shared SSM parameters
`/config/common/global-appvar/ACCESS_CONTROL_BLOCKED_SUBJECTS` and
`/config/common/global-appvar/ACCESS_CONTROL_BLOCKED_USER_IDS`, injected under the
environment names above. Ensure each task imports these parameters and can read
them. Avoid duplicate service/global parameters with the same environment name:
deployment precedence could hide the shared list. Roll out new tasks after a
change; this library does not poll SSM or add AWS calls to token verification.

Services must upgrade to this release and deploy to enforce the lists. Anonymous
routes, outbound M2M token acquisition, and purpose-bound `verifySignedJwt()`
proofs are outside this access-token check. Service URL/attachment protections
remain necessary to prevent SSRF by other identities.

Consume the immutable release with:

```json
"tc-core-library-js": "github:topcoder-platform/tc-core-library-js#v4.0.0-rc.3"
```

Compiled `dist` files and declarations are included, so GitHub consumers do not
need to compile the library. Refresh the service lockfile when upgrading.

## Outbound M2M tokens

```ts
const tokens = createM2MClient({
  AUTH0_URL: process.env.AUTH0_URL, // full /oauth/token URL
  AUTH0_AUDIENCE: process.env.AUTH0_AUDIENCE,
  AUTH0_PROXY_SERVER_URL: process.env.AUTH0_PROXY_SERVER_URL,
  TOKEN_CACHE_TIME: 900, // optional maximum seconds
});
const token = await tokens.getMachineToken(clientId, clientSecret);
```

Clients isolate their configuration and credential caches. Concurrent requests for the same credentials share one token request. Cache lifetime is the minimum of `expires_in`, JWT `exp` when present, the configured maximum and 24 hours, with a 60-second refresh margin. Missing expiration does not produce an indefinitely cached token. `clearCache()` invalidates cached tokens. Proxy requests include the configured `auth0_url`; direct OAuth requests omit that proxy field. Optional `AUTH_SCOPE`, `AUTH_PROVIDER` and `AUTH_CONTENT_TYPE` retain the deployed proxy contract.

Requests have a 10-second default timeout, reject redirects, limit responses to 1 MiB and never include credentials or response bodies in thrown errors. The default transport uses Node's HTTP/HTTPS clients and works when a host application replaces `global.Promise` with Bluebird, including on Node 26. It does not modify the host's Promise implementation. `timeoutMs` and an injectable `fetch` support service-specific deadlines and isolated tests; an injected transport is responsible for compatibility with its host runtime. Bus API publishing uses the same transport.

## Bus API publishing

```ts
const bus = createBusApiClient({
  BUSAPI_URL: 'https://api.topcoder-dev.com/v6',
  AUTH0_URL: process.env.AUTH0_URL,
  AUTH0_AUDIENCE: process.env.AUTH0_AUDIENCE,
  AUTH0_CLIENT_ID: process.env.AUTH0_CLIENT_ID,
  AUTH0_CLIENT_SECRET: process.env.AUTH0_CLIENT_SECRET,
  AUTH0_PROXY_SERVER_URL: process.env.AUTH0_PROXY_SERVER_URL,
});
await bus.postEvent({
  topic: 'example.changed', originator: 'example-api-v6',
  timestamp: new Date().toISOString(), 'mime-type': 'application/json',
  key: 'stable-key', payload: { id: '123' },
});
```

An existing service token provider can be supplied as `getToken: () => tokens.getMachineToken(id, secret)`. Base URLs ending in `/v6`, `/bus`, or `/bus/events` resolve without duplicating suffixes. Legacy local `/eventBus` mocks are supported. Configure production/dev deployments to use the Bus API v6 endpoint.

`postEvent` preserves the envelope, payload and partition key and resolves to `{ status, body }` for a successful HTTP response. It rejects on HTTP/network/timeout errors, and invalidates its own cached token after HTTP 401. There are **no automatic POST retries**: services retain their existing outbox/retry and idempotency policy. The client never logs payloads or credentials. Topic/service administration, health wrappers and error-topic convenience methods are omitted because the migrated services do not use them.

## Development

```sh
nvm use
pnpm install --frozen-lockfile
pnpm lint
pnpm build
pnpm test
pnpm audit --prod
pnpm pack
```

See [MIGRATION.md](MIGRATION.md) for removed APIs, deployment requirements and service coverage. Security behavior follows [JWT best current practices](https://www.rfc-editor.org/rfc/rfc8725.html) and the [jsonwebtoken verification API](https://github.com/auth0/node-jsonwebtoken).

### Email verification required for member access

All human access tokens must include a boolean `true` in `email_verified`,
`emailVerified`, or `emailActive`, either at the top level or in a configured
trusted claim namespace. Missing, false, non-boolean or conflicting claims are
rejected with HTTP 401 by the middleware. Roles, scopes, and an `isMachine` flag
cannot bypass this check. Genuine client-credentials grants remain supported.
Purpose-bound activation/resend proofs continue through `verifySignedJwt`.

Deploy token issuance changes first: verified members must receive this claim.
Already-issued tokens without it will be rejected and require a fresh login.
Upgrade consumer dependency pins and lockfiles to this revision; updating this
repository alone does not update services pinned to older releases.
