# tc-core-library-js v4

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

All access-token verification uses one implementation. It verifies the signature against an explicit HS256/RS256 algorithm, exact configured issuer, expiration, not-before and configured audience. Expiration is mandatory in every environment; future `iat`, unsupported algorithms, malformed tokens, missing RSA key IDs and conflicting human/machine claims are rejected. Tokens are limited to 32 KiB. Failures use a generic message and middleware returns HTTP 401.

`VALID_ISSUERS` accepts a JSON string array, a comma-separated list, or an array. No issuer is learned from a token. For the environment-style configuration:

- `AUTH_SECRET` enables legacy HS256 human tokens and must contain at least 32 UTF-8 bytes. There is no default secret. These legacy tokens may omit `aud`; their trust boundary remains the configured issuer and shared signing key.
- `JWT_AUDIENCE` configures an allowed RSA browser/application audience. `AUTH0_AUDIENCE` configures an allowed RSA API audience. Without either, RSA verification is disabled. Client-credentials tokens require an audience-bound policy and must match `AUTH0_AUDIENCE` when it is configured; the audience-free legacy HMAC policy is human-only.
- Audience values are server configuration, never decoded from an incoming token. Services accepting Auth0 browser tokens must set `JWT_AUDIENCE` to the intended application's client ID/audience.
- JWKS endpoints are derived only from allowlisted issuers. Explicit policies can override the endpoint. Each verifier has bounded caching, a 5-second network timeout and a per-issuer request limit.

Use explicit policies when issuers require different audiences or algorithms:

```ts
const verifier = createJwtVerifier({
  issuers: [
    { issuer: 'https://auth.example/', algorithm: 'RS256',
      jwksUri: 'https://auth.example/.well-known/jwks.json', audience: 'my-api' },
    { issuer: 'https://api.example', algorithm: 'HS256',
      secret: process.env.AUTH_SECRET, allowMissingAudience: true },
  ],
});
```

Explicit policies require an audience unless `allowMissingAudience` is deliberately enabled for a legacy contract. The default clock tolerance is 5 seconds and can be configured between 0 and 60 seconds. HTTPS is required for remote endpoints; loopback HTTP is supported for local tests. Internal HTTP requires an explicit `allowInsecureHttp` opt-in.

The verified identity retains original claims and supplies normalized `roles`, `scopes`, `userId`, `handle`, `email` and `isMachine`. Only exact standard claims and configured namespace prefixes are read. Default namespaces cover Topcoder's production/development domains and API namespaces; custom providers should pass `claimNamespaces`. Numeric user IDs are validated and preserved without lossy conversion. A machine requires `gty: "client-credentials"` with no human ID or roles. Scope presence alone never establishes a machine identity. Route-specific roles, scope aliases, database permissions and active-session checks remain in each service.

`verifySignedJwt(token, key, options)` handles Identity's purpose-bound OTP, resend and email-change proofs. It requires an audience and expiry, pins one algorithm (HS256 by default), and enforces `userId` when supplied. It preserves `JsonWebTokenError`/`TokenExpiredError` for existing flow-specific HTTP responses. It does not replace replay/one-time-token storage.

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
