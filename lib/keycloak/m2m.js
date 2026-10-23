"use strict";
const {configuration} = require("./configuration");
const {parseScopes} = require("./principal");
const {createValidator} = require("./validator");

/**
 * Create the Keycloak client-credentials token provider from deployment options. The
 * public auth.m2m factory returns it when USE_KEYCLOAK=true (see provider.js).
 * Returns getMachineToken(clientId?, clientSecret?, scope?) and clearCache(). Explicit
 * credentials override KEYCLOAK_CLIENT_ID/SECRET. Each factory owns its cache, isolated
 * by credentials and canonical scope; the fixed issuer/audience/endpoint cannot vary.
 * Configuration errors throw at startup; issuance failures reject without token,
 * secret, response body or HTTP-client request details in the error.
 */
function m2m(options = {}) {
  const config = configuration(options);
  const validator = createValidator(options);
  const cache = new Map();
  const inFlight = new Map();
  const {createHmac, randomBytes} = require("node:crypto");
  const cacheKey = randomBytes(32);

  /** Obtain and verify a newly issued token for the supplied credentials/scope; rejects sanitized errors. */
  async function issue(clientId, clientSecret, requested, key) {
    try {
      const payload = {grant_type: "client_credentials", client_id: clientId,
        client_secret: clientSecret, audience: config.audience};
      if (requested !== undefined) payload.scope = requested;
      const form = config.format === "form";
      const response = await fetch(config.tokenUrl, {method: "POST", redirect: "error",
        headers: {"content-type": form ? "application/x-www-form-urlencoded" : "application/json"},
        body: form ? new URLSearchParams(payload).toString() : JSON.stringify(payload),
        signal: AbortSignal.timeout(10000)});
      if (!response.ok) throw new Error("Token request failed");
      const data = await response.json();
      const verified = await validator.verify(data.access_token);
      if (verified.iss !== config.issuer || verified.kind !== "service" || verified.clientId !== clientId ||
          (requested !== undefined && verified.scopes.join(" ") !== requested)) throw new Error("Token contract mismatch");
      const seconds = Number(data.expires_in);
      if (!Number.isFinite(seconds) || seconds <= 0) throw new Error("Invalid token expiry");
      const expiresAt = Math.min(verified.exp * 1000, Date.now() + seconds * 1000) - 60000 - Math.floor(Math.random() * 5000);
      if (expiresAt > Date.now()) cache.set(key, {token: data.access_token, expiresAt});
      return data.access_token;
    } catch { throw new Error("Keycloak M2M token request failed"); }
  }

  return {
    /**
     * Return a verified cached/new token. Optional ID/secret/scope override configured values.
     * Missing credentials or invalid scopes reject. Concurrent equivalent requests share
     * one issuance; an omitted scope is distinct from any explicit scope set.
     */
    async getMachineToken(clientId = config.clientId, clientSecret = config.clientSecret, scope = config.scope) {
      if (typeof clientId !== "string" || !clientId || typeof clientSecret !== "string" || !clientSecret) {
        throw new TypeError("KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET are required");
      }
      const requested = scope === undefined ? undefined : parseScopes(scope).join(" ");
      const key = createHmac("sha256", cacheKey).update(JSON.stringify([clientId, clientSecret, requested ?? null])).digest("hex");
      const saved = cache.get(key);
      if (saved && saved.expiresAt > Date.now()) return saved.token;
      cache.delete(key);
      if (!inFlight.has(key)) {
        inFlight.set(key, issue(clientId, clientSecret, requested, key).finally(() => inFlight.delete(key)));
      }
      return inFlight.get(key);
    },
    /** Clear cached bearer tokens after a configuration change; returns nothing and does not revoke issued JWTs. */
    clearCache() { cache.clear(); }
  };
}
module.exports = m2m;
