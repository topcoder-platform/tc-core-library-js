import jwt, { JwtPayload } from 'jsonwebtoken';
export type JwtAlgorithm = 'HS256' | 'RS256';
export interface JwtIssuer {
    issuer: string;
    algorithm: JwtAlgorithm;
    audience?: string | string[];
    /** Explicit compatibility for legacy Topcoder human tokens with no audience. */
    allowMissingAudience?: boolean;
    /** Required, finite retirement deadline for temporary HS256 access-token verification. */
    legacyHs256Until?: string;
    secret?: string;
    jwksUri?: string;
}
export interface JwtConfiguration {
    issuers?: readonly JwtIssuer[];
    /** Public issuer policies as JSON; never put secret values in this setting. */
    JWT_ISSUER_POLICIES?: string;
    VALID_ISSUERS?: string | readonly string[];
    AUTH_SECRET?: string;
    AUTH0_AUDIENCE?: string;
    JWT_AUDIENCE?: string;
    JWT_KEY_CACHE_TIME?: string | number;
    /** Exact legacy issuers; AUTH_SECRET alone never enables HS256. */
    LEGACY_HS256_ISSUERS?: string | readonly string[];
    /** ISO timestamp; checked on every request, including already-running verifiers. */
    LEGACY_HS256_ACCEPT_UNTIL?: string;
    /** Maximum exp - iat and token age, in seconds (default 86400). */
    maxTokenLifetimeSeconds?: number;
    /** Additional exact JWT subjects; merged with the environment denylist. */
    ACCESS_CONTROL_BLOCKED_SUBJECTS?: string | readonly string[];
    /** Additional normalized user IDs; merged with the environment denylist. */
    ACCESS_CONTROL_BLOCKED_USER_IDS?: string | readonly string[];
    clockTolerance?: number;
    timeoutMs?: number;
    claimNamespaces?: readonly string[];
    allowInsecureHttp?: boolean;
}
export interface AuthUser extends JwtPayload {
    userId?: number | string;
    handle?: string;
    email?: string;
    roles: string[];
    scopes: string[];
    isMachine: boolean;
    azpHash?: number;
}
export interface JwtVerifier {
    verify(token: string): Promise<AuthUser>;
}
/** Extracts exact standard or explicitly trusted namespaced claims after verification.
 * @param payload Verified claims. @param name Exact claim name. @param namespaces Trusted namespace prefixes.
 * @returns Claim value or undefined. No exceptions are raised.
 */
export declare function getClaim(payload: JwtPayload, name: string, namespaces?: readonly string[]): unknown;
/** Requires an explicit boolean verification claim from a trusted namespace.
 * Conflicting aliases fail closed. Activation proofs are not access tokens and
 * intentionally use verifySignedJwt instead.
 */
export declare function hasVerifiedEmail(payload: JwtPayload, namespaces?: readonly string[]): boolean;
/** Produces the common Topcoder identity without trusting token-supplied derived flags.
 * @param payload Cryptographically verified JWT claims. @param namespaces Exact trusted namespace prefixes.
 * @returns Normalized identity retaining original claims. @throws Error for malformed user IDs.
 */
export declare function normalizeAuthUser(payload: JwtPayload, namespaces?: readonly string[]): AuthUser;
/** Parses configured issuer strings; this never derives trust from a token.
 * @param value JSON array, comma-separated list or array of issuer identifiers.
 * @returns Nonempty issuer allowlist. @throws Error for missing or malformed entries.
 */
export declare function parseIssuers(value: JwtConfiguration['VALID_ISSUERS']): string[];
/** Creates the shared verifier for HTTP middleware, Nest guards and background services.
 * @param config Explicit issuer policies or the documented v6 environment configuration.
 * @returns Verifier checking signature, algorithm, issuer, expiry, nbf, audience and identity denylists.
 * @throws Error for invalid configuration; verify rejects every invalid token without leaking key details.
 */
export declare function createJwtVerifier(config: JwtConfiguration): JwtVerifier;
export interface AuthenticatorRequest {
    id?: string;
    headers: {
        authorization?: string | string[];
    };
    authUser?: JwtPayload;
}
export interface AuthenticatorResponse {
    status?: (code: number) => {
        json?: (body: unknown) => unknown;
        send?: (body: unknown) => unknown;
    };
    json?: (body: unknown) => unknown;
    send?: (...args: unknown[]) => unknown;
    end?: (body?: string) => unknown;
    setHeader?: (name: string, value: string) => unknown;
    statusCode?: number;
}
export type JwtAuthenticator = (request: AuthenticatorRequest, response: AuthenticatorResponse, next: (error?: Error) => void) => void;
/** Creates the shared Express-compatible JWT middleware using the same verifier as Nest adapters.
 * @param config Trusted JWT settings. @returns Middleware attaching authUser or responding with HTTP 401.
 * @throws Error at construction for invalid settings; request authentication failures are handled as 401.
 */
export declare function createJwtAuthenticator(config: JwtConfiguration): JwtAuthenticator;
export interface SignedJwtOptions {
    audience: string;
    issuer?: string;
    userId?: string | number;
    algorithms?: JwtAlgorithm[];
}
/** Verifies purpose-bound Identity API proofs (OTP, resend, email change) with a configured key.
 * These application proofs may omit issuer, but always require their distinct audience and expiry.
 * @param token Compact JWT. @param key Server-configured signing key, never token-controlled.
 * @param options Required purpose audience, optional issuer/user binding, and explicit algorithms (HS256 by default).
 * @returns Verified original claims. @throws JsonWebTokenError or TokenExpiredError on verification failure.
 */
export declare function verifySignedJwt(token: string, key: jwt.Secret, options: SignedJwtOptions): JwtPayload;
