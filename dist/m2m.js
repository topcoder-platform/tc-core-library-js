"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createM2MClient = createM2MClient;
const node_crypto_1 = require("node:crypto");
const jsonwebtoken_1 = require("jsonwebtoken");
const http_1 = require("./http");
/** Creates an isolated OAuth client used for outbound service authentication.
 * @param config Explicit token/proxy endpoints, audience and HTTP limits.
 * @returns Client with bounded, expiration-aware caching and concurrent request deduplication.
 * @throws Error for invalid configuration; token requests reject with sanitized HttpError.
 */
function createM2MClient(config) {
    config = { ...config };
    if (!config.AUTH0_URL || !config.AUTH0_AUDIENCE)
        throw new Error('AUTH0_URL and AUTH0_AUDIENCE are required');
    const tokenUrl = (0, http_1.endpoint)(config.AUTH0_URL, config.allowInsecureHttp).toString();
    const requestUrl = (0, http_1.endpoint)(config.AUTH0_PROXY_SERVER_URL || config.AUTH0_URL, config.allowInsecureHttp).toString();
    const cache = new Map();
    const pending = new Map();
    const ttl = config.TOKEN_CACHE_TIME === undefined ? 86400 : Number(config.TOKEN_CACHE_TIME);
    if (!Number.isFinite(ttl) || ttl < 0)
        throw new Error('Invalid TOKEN_CACHE_TIME');
    return {
        /** Acquires an access token for the supplied client ID and secret; returns a token or rejects with HttpError. */
        async getMachineToken(clientId, clientSecret) {
            if (!clientId || !clientSecret)
                throw new Error('M2M client credentials are required');
            const key = (0, node_crypto_1.createHash)('sha256').update(JSON.stringify([clientId, clientSecret])).digest('hex');
            const cached = cache.get(key);
            if (cached && cached.expiresAt > Date.now())
                return cached.token;
            const active = pending.get(key);
            if (active)
                return active;
            if (pending.size >= 256)
                throw new http_1.HttpError('Too many concurrent token requests');
            const request = (async () => {
                const { body } = await (0, http_1.postJson)(requestUrl, {
                    grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret,
                    audience: config.AUTH0_AUDIENCE,
                    ...(config.AUTH0_PROXY_SERVER_URL ? { auth0_url: tokenUrl } : {}),
                    ...(config.AUTH_SCOPE ? { scope: config.AUTH_SCOPE } : {}),
                    ...(config.AUTH_PROVIDER ? { provider: config.AUTH_PROVIDER } : {}),
                    ...(config.AUTH_CONTENT_TYPE ? { content_type: config.AUTH_CONTENT_TYPE } : {}),
                }, config);
                if (!body || typeof body !== 'object' || !('access_token' in body) ||
                    typeof body.access_token !== 'string' || !body.access_token || /\s/.test(body.access_token)) {
                    throw new http_1.HttpError('Invalid token response');
                }
                const now = Date.now();
                const expiresIn = 'expires_in' in body && typeof body.expires_in === 'number' && Number.isFinite(body.expires_in) ? Math.max(0, body.expires_in) : 0;
                // Unverified exp only shortens cache lifetime; it never authenticates a caller.
                const claims = (0, jsonwebtoken_1.decode)(body.access_token);
                const jwtLifetime = claims && typeof claims === 'object' && typeof claims.exp === 'number' ? Math.max(0, claims.exp - now / 1000) : Infinity;
                const lifetime = Math.min(expiresIn, jwtLifetime, ttl, 86400);
                if (cache.size >= 256)
                    cache.delete(cache.keys().next().value);
                cache.set(key, { token: body.access_token, expiresAt: now + Math.max(0, lifetime - 60) * 1000 });
                return body.access_token;
            })();
            pending.set(key, request);
            try {
                return await request;
            }
            finally {
                pending.delete(key);
            }
        },
        /** Removes cached tokens after rejected credentials; takes no arguments, returns void and does not throw. */
        clearCache() { cache.clear(); },
    };
}
//# sourceMappingURL=m2m.js.map