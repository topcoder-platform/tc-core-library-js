import jwt, { JwtPayload } from 'jsonwebtoken';
import jwks from 'jwks-rsa';
import { endpoint } from './http';

export type JwtAlgorithm = 'HS256' | 'RS256';
export interface JwtIssuer {
  issuer: string;
  algorithm: JwtAlgorithm;
  audience?: string | string[];
  /** Explicit compatibility for legacy Topcoder human tokens with no audience. */
  allowMissingAudience?: boolean;
  secret?: string;
  jwksUri?: string;
}
export interface JwtConfiguration {
  issuers?: readonly JwtIssuer[];
  VALID_ISSUERS?: string | readonly string[];
  AUTH_SECRET?: string;
  AUTH0_AUDIENCE?: string;
  JWT_AUDIENCE?: string;
  JWT_KEY_CACHE_TIME?: string | number;
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
export function getClaim(payload: JwtPayload, name: string, namespaces: readonly string[] = ['https://topcoder.com/', 'https://www.topcoder.com/', 'https://topcoder-dev.com/', 'https://api.topcoder.com/v6/', 'https://api.topcoder-dev.com/v6/', 'http://www.topcoder.com/', 'https://api.topcoder.com/', 'https://api.topcoder-dev.com/']): unknown {
  if (Object.hasOwn(payload, name)) return payload[name];
  for (const namespace of namespaces) if (Object.hasOwn(payload, `${namespace}${name}`)) return payload[`${namespace}${name}`];
  return undefined;
}

/** Normalizes a verified roles/scopes claim to a list, preserving multiword role names.
 * @param value Claim value. @param separator String-list separator.
 * @returns Nonempty strings; malformed claims produce an empty list. Never throws.
 */
function stringList(value: unknown, separator: RegExp): string[] {
  if (typeof value === 'string' && value.trim().startsWith('[')) {
    try { value = JSON.parse(value) as unknown; } catch { return []; }
  }
  const list = Array.isArray(value) ? value : typeof value === 'string' ? value.split(separator) : [];
  return [...new Set(list.filter((entry): entry is string => typeof entry === 'string').map(entry => entry.trim()).filter(Boolean))];
}

/** Produces the common Topcoder identity without trusting token-supplied derived flags.
 * @param payload Cryptographically verified JWT claims. @param namespaces Exact trusted namespace prefixes.
 * @returns Normalized identity retaining original claims. @throws Error for malformed user IDs.
 */
export function normalizeAuthUser(payload: JwtPayload, namespaces?: readonly string[]): AuthUser {
  const claim = (name: string): unknown => getClaim(payload, name, namespaces);
  const roles = stringList(claim('roles'), /,/);
  const scopes = stringList(claim('scope') ?? claim('scopes'), /\s+/);
  const userId = claim('userId');
  if (userId !== undefined && !(typeof userId === 'number' && Number.isSafeInteger(userId) && userId > 0) && !(typeof userId === 'string' && /^[1-9]\d{0,18}$/.test(userId) && BigInt(userId) <= 9223372036854775807n)) {
    throw new Error('Invalid user identity');
  }
  const isMachine = claim('gty') === 'client-credentials' && userId === undefined && roles.length === 0;
  if ((payload.sub !== undefined && (typeof payload.sub !== 'string' || !payload.sub.trim())) ||
      (claim('gty') === 'client-credentials' && !isMachine) ||
      (payload.isMachine !== undefined && payload.isMachine !== isMachine)) throw new Error('Conflicting identity claims');
  const result: AuthUser = { ...payload, roles, scopes, isMachine };
  delete result.azpHash;
  if (typeof userId === 'string' || typeof userId === 'number') result.userId = userId;
  for (const name of ['handle', 'email'] as const) {
    const value = claim(name);
    if (typeof value === 'string') result[name] = value;
  }
  // Retain deterministic legacy audit IDs for existing machine consumers.
  if (isMachine && typeof payload.azp === 'string' && payload.azp.length <= 512) {
    let hash = 100000;
    for (let i = 0; i < payload.azp.length; i++) hash += payload.azp.charCodeAt(i) * (i + 1);
    result.azpHash = -hash;
  }
  return result;
}

/** Parses configured issuer strings; this never derives trust from a token.
 * @param value JSON array, comma-separated list or array of issuer identifiers.
 * @returns Nonempty issuer allowlist. @throws Error for missing or malformed entries.
 */
export function parseIssuers(value: JwtConfiguration['VALID_ISSUERS']): string[] {
  let parsed: unknown = value;
  if (typeof value === 'string') {
    try { parsed = JSON.parse(value) as unknown; } catch { parsed = value.split(','); }
  }
  if (!Array.isArray(parsed) || !parsed.length || parsed.some(v => typeof v !== 'string' || !v.trim())) throw new Error('VALID_ISSUERS must contain trusted issuers');
  return [...new Set((parsed as string[]).map(v => v.trim()))];
}

/** Converts the retained v6 environment contract into explicit issuer/algorithm policies.
 * @param config Server-owned JWT settings. @returns Policies with separate HMAC and RSA keys.
 * @throws Error if the issuer allowlist is missing or invalid.
 */
function policiesFromConfig(config: JwtConfiguration): JwtIssuer[] {
  if (config.issuers) return config.issuers.map(policy => ({ ...policy, audience: Array.isArray(policy.audience) ? [...policy.audience] : policy.audience }));
  return parseIssuers(config.VALID_ISSUERS).flatMap(issuer => {
    const audience = [...new Set([config.JWT_AUDIENCE, config.AUTH0_AUDIENCE].filter((value): value is string => Boolean(value)))];
    const policies: JwtIssuer[] = audience.length ? [{ issuer, algorithm: 'RS256', audience }] : [];
    if (config.AUTH_SECRET) policies.push({ issuer, algorithm: 'HS256', secret: config.AUTH_SECRET, allowMissingAudience: true });
    return policies;
  });
}

/** Creates the shared verifier for HTTP middleware, Nest guards and background services.
 * @param config Explicit issuer policies or the documented v6 environment configuration.
 * @returns Verifier that checks signature, algorithm, issuer, expiry, nbf and configured audience.
 * @throws Error for invalid configuration; verify rejects every invalid token without leaking key details.
 */
export function createJwtVerifier(config: JwtConfiguration): JwtVerifier {
  config = { ...config, claimNamespaces: config.claimNamespaces ? [...config.claimNamespaces] : undefined };
  const policies = policiesFromConfig(config);
  if (!policies.length) throw new Error('At least one JWT issuer policy is required');
  const tolerance = config.clockTolerance ?? 5;
  const timeout = config.timeoutMs ?? 5000;
  if (!Number.isFinite(tolerance) || tolerance < 0 || tolerance > 60 || !Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 30000) throw new Error('Invalid JWT timing configuration');
  const clients = new Map<JwtIssuer, jwks.JwksClient>();
  const seen = new Set<string>();
  for (const policy of policies) {
    if (!policy.issuer || !['HS256', 'RS256'].includes(policy.algorithm)) throw new Error('Invalid issuer policy');
    const id = JSON.stringify([policy.issuer, policy.algorithm]);
    if (seen.has(id)) throw new Error('Duplicate issuer/algorithm policy');
    seen.add(id);
    if (!policy.audience && !policy.allowMissingAudience) throw new Error('JWT audience is required');
    if (Array.isArray(policy.audience) && (!policy.audience.length || policy.audience.some(a => !a))) throw new Error('Invalid JWT audience');
    if (policy.algorithm === 'HS256') {
      if (!policy.secret || Buffer.byteLength(policy.secret, 'utf8') < 32 || policy.secret.includes('-----BEGIN')) throw new Error('A symmetric JWT secret of at least 32 bytes is required');
    } else {
      const url = endpoint(policy.jwksUri || `${policy.issuer.replace(/\/$/, '')}/.well-known/jwks.json`, config.allowInsecureHttp);
      clients.set(policy, jwks({ jwksUri: url.toString(), cache: true, cacheMaxEntries: 5, cacheMaxAge: 600000, rateLimit: true, jwksRequestsPerMinute: 10, timeout }));
    }
  }
  return {
    /** Verifies a compact JWT and returns its normalized identity; rejects with a generic Error on failure. */
    async verify(token: string): Promise<AuthUser> {
      try {
        if (typeof token !== 'string' || token.length > 32768 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw new Error();
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded || typeof decoded.payload !== 'object' || decoded.payload === null || decoded.header.crit) throw new Error();
        const untrustedIssuer = decoded.payload.iss;
        const policy = policies.find(p => p.issuer === untrustedIssuer && p.algorithm === decoded.header.alg);
        if (!policy) throw new Error();
        let key: string;
        if (policy.algorithm === 'HS256') key = policy.secret!;
        else {
          const kid = decoded.header.kid;
          if (typeof kid !== 'string' || !kid || kid.length > 256) throw new Error();
          key = (await clients.get(policy)!.getSigningKey(kid)).getPublicKey();
        }
        const payload = jwt.verify(token, key, { algorithms: [policy.algorithm], issuer: policy.issuer,
          ...(policy.audience ? { audience: Array.isArray(policy.audience) ? policy.audience as [string, ...string[]] : policy.audience } : {}), clockTolerance: tolerance });
        if (typeof payload !== 'object' || typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) throw new Error();
        if (typeof payload.iat === 'number' && payload.iat > Date.now() / 1000 + tolerance) throw new Error();
        // Legacy human tokens may omit aud; machine tokens must match the configured API audience.
        const user = normalizeAuthUser(payload, config.claimNamespaces);
        if (user.isMachine && !policy.audience) throw new Error();
        if (user.isMachine && config.AUTH0_AUDIENCE) {
          const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
          if (!audiences.includes(config.AUTH0_AUDIENCE)) throw new Error();
        }
        return user;
      } catch {
        throw new Error('Invalid or expired access token');
      }
    },
  };
}

export interface AuthenticatorRequest {
  id?: string;
  headers: { authorization?: string | string[] };
  authUser?: JwtPayload;
}
export interface AuthenticatorResponse {
  status?: (code: number) => { json?: (body: unknown) => unknown; send?: (body: unknown) => unknown };
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
export function createJwtAuthenticator(config: JwtConfiguration): JwtAuthenticator {
  const verifier = createJwtVerifier(config);
  return (request, response, next) => {
    const header = request.headers.authorization;
    const match = typeof header === 'string' ? /^Bearer ([^\s]+)$/i.exec(header) : null;
    const verification = match ? verifier.verify(match[1]) : Promise.reject(new Error('Missing bearer token'));
    void verification.then(user => { request.authUser = user; next(); }, () => {
      const body = { message: 'Invalid or expired access token', result: { success: false, status: 401, content: { message: 'Invalid or expired access token' } } };
      if (response.status) {
        const output = response.status(401);
        if (output.json) { output.json(body); return; }
        if (output.send) { output.send(body); return; }
      }
      if (response.send) { response.send(401, body); return; }
      response.statusCode = 401;
      response.setHeader?.('Content-Type', 'application/json');
      if (response.end) response.end(JSON.stringify(body));
      else next(new Error('Invalid or expired access token'));
    });
  };
}

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
export function verifySignedJwt(token: string, key: jwt.Secret, options: SignedJwtOptions): JwtPayload {
  if (!options.audience || !token || token.length > 32768) throw new jwt.JsonWebTokenError('Invalid token configuration');
  const algorithms = options.algorithms ?? ['HS256'];
  if (!algorithms.length || algorithms.some(algorithm => !['HS256', 'RS256'].includes(algorithm)) || new Set(algorithms).size !== 1) throw new jwt.JsonWebTokenError('One signing algorithm is required');
  const payload = jwt.verify(token, key, { audience: options.audience, issuer: options.issuer, algorithms });
  if (typeof payload !== 'object' || typeof payload.exp !== 'number') throw new jwt.JsonWebTokenError('Token expiry is required');
  if (options.userId !== undefined && String(payload.userId ?? payload.sub) !== String(options.userId)) throw new jwt.JsonWebTokenError('Token user mismatch');
  return payload;
}
