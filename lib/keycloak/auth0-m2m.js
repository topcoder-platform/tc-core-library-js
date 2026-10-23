"use strict";
const axios = require("axios");
const jwt = require("jsonwebtoken");
const {createHmac, randomBytes} = require("node:crypto");

// Shared by every Auth0 provider in the process, like the 3.x module-level cache, so
// services that build a provider per call still reuse a token until it nears expiry.
const cache = new Map();
const inFlight = new Map();
const cacheKey = randomBytes(32);

/** Return the token's expiry in epoch milliseconds from its unverified exp claim, or 0 when absent. */
function expiry(token) {
  const decoded = jwt.decode(token);
  return decoded && Number.isFinite(decoded.exp) ? decoded.exp * 1000 : 0;
}

/**
 * Create the Auth0 client-credentials token provider, used when USE_KEYCLOAK is not true.
 * It keeps the 3.x contract:
 * - AUTH0_URL: the Auth0 tenant token URL, forwarded to the proxy as auth0_url.
 * - AUTH0_AUDIENCE: the requested audience.
 * - AUTH0_PROXY_SERVER_URL: the endpoint that receives the request (default AUTH0_URL).
 * - AUTH0_CLIENT_ID/AUTH0_CLIENT_SECRET: default credentials.
 * These options merge over the environment, so auth.m2m() works without arguments.
 * AUTH_SCOPE, AUTH_PROVIDER and AUTH_CONTENT_TYPE are read from the options only, as in
 * 3.x, so unrelated environment variables never change the token request.
 *
 * Returns getMachineToken(clientId?, clientSecret?, scope?) and clearCache(). Missing
 * settings reject when a token is requested rather than at construction, as in 3.x, so a
 * rollback never stops a service from starting. Errors never include the token, secret
 * or response body.
 */
function auth0M2m(options = {}) {
  const env = {...process.env, ...options};
  const auth0Url = env.AUTH0_URL;
  const {AUTH_SCOPE: authScope, AUTH_PROVIDER: authProvider, AUTH_CONTENT_TYPE: contentType} = options;
  const proxyUrl = env.AUTH0_PROXY_SERVER_URL || auth0Url;

  /** Request a new token through the proxy and cache it until a minute before expiry; rejects sanitized errors. */
  async function issue(clientId, clientSecret, scope, key) {
    const data = {grant_type: "client_credentials", client_id: clientId, client_secret: clientSecret, auth0_url: auth0Url};
    if (env.AUTH0_AUDIENCE !== undefined) data.audience = env.AUTH0_AUDIENCE;
    if (scope !== undefined) data.scope = scope;
    if (authProvider !== undefined) data.provider = authProvider;
    if (contentType !== undefined) data.content_type = contentType;
    let body;
    try {
      body = (await axios({method: "post", url: proxyUrl, data, timeout: 10000,
        headers: {"content-type": "application/json"}})).data;
    } catch { throw new Error("Auth0 M2M token request failed"); }
    if (!body || typeof body.access_token !== "string" || !body.access_token) {
      throw new Error("Auth0 M2M token request failed; check AUTH0_URL, AUTH0_AUDIENCE, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET and AUTH0_PROXY_SERVER_URL");
    }
    const expiresAt = expiry(body.access_token) - 60000;
    if (expiresAt > Date.now()) cache.set(key, {token: body.access_token, expiresAt});
    return body.access_token;
  }

  return {
    /**
     * Return a cached or new Auth0 token. Optional ID/secret/scope override AUTH0_CLIENT_ID,
     * AUTH0_CLIENT_SECRET and the AUTH_SCOPE option. Rejects when credentials or the token URL are
     * missing, or when the proxy returns no token. Concurrent equivalent requests share one call.
     */
    async getMachineToken(clientId = env.AUTH0_CLIENT_ID, clientSecret = env.AUTH0_CLIENT_SECRET, scope = authScope) {
      if (typeof clientId !== "string" || !clientId || typeof clientSecret !== "string" || !clientSecret) {
        throw new TypeError("AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET are required");
      }
      if (typeof proxyUrl !== "string" || !proxyUrl) throw new TypeError("AUTH0_URL or AUTH0_PROXY_SERVER_URL is required");
      const key = createHmac("sha256", cacheKey).update(JSON.stringify([proxyUrl, auth0Url ?? null,
        env.AUTH0_AUDIENCE ?? null, clientId, clientSecret, scope ?? null])).digest("hex");
      const saved = cache.get(key);
      if (saved && saved.expiresAt > Date.now()) return saved.token;
      cache.delete(key);
      if (!inFlight.has(key)) {
        inFlight.set(key, issue(clientId, clientSecret, scope, key).finally(() => inFlight.delete(key)));
      }
      return inFlight.get(key);
    },
    /** Clear every cached Auth0 token in this process; returns nothing and does not revoke issued JWTs. */
    clearCache() { cache.clear(); }
  };
}

module.exports = auth0M2m;
