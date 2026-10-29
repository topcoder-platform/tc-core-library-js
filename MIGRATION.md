# Migration to 4.0.0-rc.1

This breaking prerelease replaces the legacy JavaScript library with a small TypeScript library and folds the used bus API publisher into it. Node.js 22.13 or newer is required. CommonJS, TypeScript declarations and source maps ship together; consumers do not compile this package.

## Public API

| Previous API | New API |
| --- | --- |
| `middleware.jwtAuthenticator(config)` | `createJwtAuthenticator(config)` |
| `auth.verifier(...)` / local JWT verification | `createJwtVerifier(config).verify(token)` |
| `auth.m2m(config)` / deep import | `createM2MClient(config)` |
| Any `tc-bus-api-wrapper` package alias | `createBusApiClient(config)` |
| Identity purpose-specific signed proofs | `verifySignedJwt(token, key, options)` |

Factories are named exports from `tc-core-library-js`. Both HTTP middleware and Nest adapters use the same verifier. Service authorization remains local: route scopes, database roles, active-session checks and resource ownership are still enforced by the service.

No scoped service uses the old library logger, logging middleware, response utilities, permission middleware or policy Authorizer. Those APIs and their dependencies have been removed. The old bus wrapper's unused topic administration and error-publishing helpers are not carried forward. Broker consumers and Kafka retry/dead-letter producers remain service-owned.

## Configuration and security changes

- Configure exact trusted issuers. RSA access tokens require an audience: `JWT_AUDIENCE` for browser/client tokens and `AUTH0_AUDIENCE` for service tokens. Services with explicit issuer policies retain their existing environment names.
- HMAC secrets must contain at least 32 UTF-8 bytes. Default `mysecret` values are removed. Legacy Topcoder human HMAC tokens may omit audience under the environment-compatible policy. Explicit policies should bind an audience where the issuer supplies one. Machine tokens always require an audience-bound policy.
- Signatures, algorithms, issuer, expiry and not-before are mandatory checks. Expired tokens and unsupported algorithms fail closed. A `scope` claim alone never makes a token a machine. Client-credentials grants with human IDs or roles are rejected.
- Only exact Topcoder claim namespaces are recognized by default. Custom deployments can pass explicit `claimNamespaces`; arbitrary namespace suffix matches are not used by the shared verifier.
- Token caches are per client instance and credential pair, bounded, expiration-aware, and deduplicate concurrent requests. OAuth endpoints use HTTPS; loopback HTTP is supported for tests, with an explicit opt-in for internal HTTP deployments. Credentials and upstream response bodies are excluded from errors.
- Bus publishing uses `createBusApiClient(...).postEvent(event)`. It preserves the complete envelope and optional message key. `BUSAPI_URL` accepts the API base, `/bus`, or `/bus/events`; scoped service defaults now point to v6. POST requests are not automatically retried because duplicate events are possible. Application retry/outbox policies remain intact.
- Autopilot's local login now requires explicit `LOCAL_AUTH_USERNAME` and a `LOCAL_AUTH_PASSWORD` of at least 32 characters; its access tokens are audience/issuer-bound and verified by this library. Its hard-coded default administrator login has been removed.
- Identity caches database permissions only; current-token scopes and machine classification cannot be replaced by a cached identity.

## Shared development configuration

The JWT configuration follow-up uses `/config/common/global-appvar` in development:

| Key | Development value |
| --- | --- |
| `VALID_ISSUERS` | Existing shared exact issuer allowlist; JSON arrays and comma-separated lists are accepted |
| `AUTH_SECRET` | Existing shared signing key, at least 32 UTF-8 bytes; never create a different key per service |
| `JWT_AUDIENCE` | `BXWXUWnilVUPdN01t2Se29Tw2ZYNGZvH` (Platform UI browser client) |
| `AUTH0_AUDIENCE` | `https://m2m.topcoder-dev.com/` (machine/API audience) |

All four global parameters are SecureStrings. On 2026-10-28 the missing browser
audience was added, Identity's issuer/audience overrides were aligned, and
Standardized Skills' issuer override was aligned. The shared signing key and
machine audience were retained. Finance and Standardized Skills deployment jobs
now include the common appvar path. Parameter Store updates are loaded on the
next deployment/task startup, not by already running tasks.

Challenge, Member and Resource now pass both audiences and reuse one route
authenticator/JWKS cache. Review and Marathon pass the separate browser audience.
Identity's Passport strategy now consumes the same four common settings as its
middleware; `JWT_VALIDATION_MODE`, `JWT_ISSUER_URL` and `JWT_JWKS_URI` no longer
select an independent access-token policy. Internal purpose-bound signing keys
remain separate. Finance also uses the common settings, including the browser
custom-domain issuer; its outbound OAuth configuration remains service-specific.

Status retains its explicit issuer policies, dedicated task configuration and
machine-client allowlist. Its dev signing key and browser/machine audiences match
the shared values; its stricter route authorization remains unchanged. Autopilot's
local login maps `jwt.secret` to shared `AUTH_SECRET` and retains the purpose-bound
issuer/audience `autopilot-v6`. Local login requires explicit credentials and its
tokens are not trusted as Platform access tokens by the other services.

## Rollout

The release is a prerelease for dev/develop testing. Services use an immutable GitHub release reference; the versioned `dist` directory makes Git installs usable without build hooks. CircleCI publishes the same version to npm's `next` tag when its existing `NPM_TOKEN` is configured. Do not archive the old wrapper until migrated services have passed deployment smoke tests and any out-of-scope consumers have been reviewed.

Service changes are isolated in `v6-refresh` worktrees; original feature branches and local changes are preserved. Merge each service branch into the listed development base after reviewing deployment configuration. Contact and QA have no configured Git remote in this workspace, so their commits remain local.

## Scoped services

| Service | Development base | Migration branch |
| --- | --- | --- |
| autopilot-v6 | develop | `v6-refresh` |
| av-scanner-v6 | develop | `v6-refresh` |
| billing-accounts-api-v6 | develop | `v6-refresh` |
| bus-api-v6 | develop | `v6-refresh` |
| challenge-api-v6 | develop | `v6-refresh` |
| contact-api-v6 | local HEAD (no remote) | `v6-refresh` |
| email-service-v6 | develop | `v6-refresh` |
| engagements-api-v6 | develop | `v6-refresh` |
| forms-api-v6 | develop | `v6-refresh` |
| forms-processor-v6 | develop | `v6-refresh` |
| forums-api-v6 | develop | `v6-refresh` |
| groups-api-v6 | develop | `v6-refresh` |
| identity-api-v6 | develop | `v6-refresh` |
| leave-api-v6 | develop | `v6-refresh` |
| lookups-api-v6 | develop | `v6-refresh` |
| marathon-match-api-v6 | develop | `v6-refresh` |
| member-api-v6 | develop | `v6-refresh` |
| opportunities-api-v6 | develop | `v6-refresh` |
| procurement-api-v6 | develop | `v6-refresh` |
| projects-api-v6 | dev | `v6-refresh` |
| qa-v6 | local HEAD (no remote) | `v6-refresh` |
| reports-api-v6 | develop | `v6-refresh` |
| resource-api-v6 | develop | `v6-refresh` |
| review-api-v6 | develop | `v6-refresh` |
| status-api-v6 | develop | `v6-refresh` |
| support-api-v6 | develop | `v6-refresh` |
| tc-finance-api | dev | `v6-refresh` |
| standardized-skills-api | develop | `v6-refresh` |

Email Service and Opportunities have no JWT-verifying or bus API-publishing execution path in the audited code; they receive the versioned dependency without adding authentication to non-HTTP workers. Other active services without a `-v6` name are outside this migration, except Finance and Standardized Skills, as requested.

## Validation

The library has offline tests for JWT rejection paths, trusted JWKS lookup, identity classification, purpose-bound proofs, OAuth caching/isolation, HTTP errors and event publishing. All scoped services must pass their lint/build scripts after installing the released dependency. Targeted authentication, session and event tests run without deployment credentials. Live Auth0, database and bus integration smoke tests require the development environment; they are not simulated as production verification.

### Existing validation limitations

Identity's `auth-flow.service.spec.ts` has 21 failing cases (35 pass), and `two-factor-auth.service.spec.ts` has incompatible fixture method calls that prevent compilation. The same failures were reproduced on unchanged `origin/develop` (`ccde1d3`) and on the migration branch. These existing failures are not counted as migration successes. The new real-signature Identity strategy/cache tests and the updated event module tests pass independently.

Contact's test runner includes disposable PostgreSQL integration coverage and marks 11 environment-dependent checks skipped. No live Auth0 credentials, production databases or deployed bus endpoints are used during local validation.
