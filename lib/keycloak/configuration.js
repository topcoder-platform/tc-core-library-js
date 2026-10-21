"use strict";

/** Validate a trusted HTTPS endpoint. Returns the URL string or throws TypeError. */
function httpsUrl(value, name) {
  let url;
  try { url = new URL(value); } catch { throw new TypeError(`${name} must be an HTTPS URL`); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search) {
    throw new TypeError(`${name} must be an HTTPS URL without credentials, query or fragment`);
  }
  return value;
}

/** Parse a string array from an array or JSON configuration; throws TypeError for invalid input. */
function stringArray(value, name, fallback = []) {
  if (value === undefined || value === "") return fallback;
  let result = value;
  if (typeof value === "string") {
    try { result = JSON.parse(value); } catch { throw new TypeError(`${name} must be a JSON string array`); }
  }
  if (!Array.isArray(result) || result.some(item => typeof item !== "string" || !item.trim())) {
    throw new TypeError(`${name} must be a JSON string array`);
  }
  return [...new Set(result)];
}

/**
 * Resolve the explicitly enabled Keycloak deployment contract from options/environment.
 * Options override environment variables. Returns immutable validation/issuance settings.
 * Used by every public authentication factory; throws TypeError before serving requests
 * when Keycloak M2M or its issuer/audience/token endpoint are not explicitly configured.
 */
function configuration(options = {}) {
  const env = {...process.env, ...options};
  if (env.M2M_PROVIDER !== "keycloak") {
    throw new TypeError("This core prerelease requires M2M_PROVIDER=keycloak; keep Auth0 services on core 3.x");
  }
  const issuer = httpsUrl(env.KEYCLOAK_ISSUER, "KEYCLOAK_ISSUER");
  if (!/\/realms\/[^/]+$/.test(issuer)) throw new TypeError("KEYCLOAK_ISSUER must be an exact realm URL without a trailing slash");
  const audience = env.KEYCLOAK_AUDIENCE;
  if (typeof audience !== "string" || !audience.trim() || audience !== audience.trim()) {
    throw new TypeError("KEYCLOAK_AUDIENCE is required");
  }
  const tokenUrl = httpsUrl(env.KEYCLOAK_TOKEN_URL, "KEYCLOAK_TOKEN_URL");
  const jwksUri = httpsUrl(env.KEYCLOAK_JWKS_URL || `${issuer}/protocol/openid-connect/certs`, "KEYCLOAK_JWKS_URL");
  const namespaces = stringArray(env.AUTH_USER_CLAIM_NAMESPACES, "AUTH_USER_CLAIM_NAMESPACES", [
    "https://topcoder-dev.com/claims/", "https://topcoder-dev.com/",
    "https://topcoder.com/claims/", "https://topcoder.com/"
  ]);
  const userIssuers = stringArray(env.VALID_ISSUERS, "VALID_ISSUERS").filter(value => value !== issuer);
  userIssuers.forEach(value => httpsUrl(value, "VALID_ISSUERS"));
  const legacyM2mIssuers = stringArray(env.LEGACY_M2M_ISSUERS, "LEGACY_M2M_ISSUERS");
  if (legacyM2mIssuers.some(value => !userIssuers.includes(value))) throw new TypeError("Legacy M2M issuers must also have configured legacy issuer trust");
  const legacyM2mAudience = env.LEGACY_M2M_AUDIENCE;
  if (legacyM2mIssuers.length && (typeof legacyM2mAudience !== "string" || !legacyM2mAudience.trim())) {
    throw new TypeError("LEGACY_M2M_AUDIENCE is required for explicit overlap validation");
  }
  const userAudiences = stringArray(env.AUTH_USER_AUDIENCES, "AUTH_USER_AUDIENCES");
  let userJwks = env.AUTH_USER_JWKS || {};
  if (typeof userJwks === "string") {
    try { userJwks = JSON.parse(userJwks); } catch { throw new TypeError("AUTH_USER_JWKS must be a JSON object"); }
  }
  if (!userJwks || typeof userJwks !== "object" || Array.isArray(userJwks)) throw new TypeError("AUTH_USER_JWKS must be a JSON object");
  for (const [trustedIssuer, uri] of Object.entries(userJwks)) {
    if (!userIssuers.includes(trustedIssuer)) throw new TypeError("AUTH_USER_JWKS contains an untrusted issuer");
    httpsUrl(uri, "AUTH_USER_JWKS");
  }
  if (userIssuers.length && !userAudiences.length && env.ALLOW_LEGACY_USER_AUDIENCE !== "true") {
    throw new TypeError("Set AUTH_USER_AUDIENCES or explicitly retain legacy user audience behavior");
  }
  const maxLifetime = Number(env.KEYCLOAK_MAX_TOKEN_LIFETIME || 900);
  if (!Number.isInteger(maxLifetime) || maxLifetime < 60 || maxLifetime > 3600) throw new TypeError("Invalid Keycloak token lifetime limit");
  const format = env.KEYCLOAK_TOKEN_FORMAT || "json";
  if (!["json", "form"].includes(format)) throw new TypeError("KEYCLOAK_TOKEN_FORMAT must be json or form");
  return Object.freeze({issuer, audience, tokenUrl, jwksUri, namespaces, userIssuers,
    userAudiences, legacyM2mIssuers, legacyM2mAudience, userJwks: Object.freeze({...userJwks}), userSecret: env.AUTH_SECRET,
    allowedClientIds: stringArray(env.KEYCLOAK_ALLOWED_CLIENT_IDS, "KEYCLOAK_ALLOWED_CLIENT_IDS"),
    clientId: env.KEYCLOAK_CLIENT_ID, clientSecret: env.KEYCLOAK_CLIENT_SECRET,
    scope: env.KEYCLOAK_SCOPE, maxLifetime, format});
}

module.exports = {configuration, stringArray};
