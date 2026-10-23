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
 * Decide whether Keycloak is the active M2M provider for these deployment settings.
 * Input is a settings object (options already merged over the environment); it defaults
 * to process.env. Returns true only for USE_KEYCLOAK=true (boolean, or the string "true"
 * in any case with surrounding whitespace ignored). A missing, empty or "false" value
 * returns false, so services fall back to Auth0. Used by every factory and by services
 * that must pick provider-specific settings. Throws TypeError for any other value, so a
 * typo fails at startup instead of silently choosing a provider.
 */
function useKeycloak(env = process.env) {
  const value = env.USE_KEYCLOAK;
  if (value === undefined || value === null || value === false) return false;
  if (value === true) return true;
  const text = typeof value === "string" ? value.trim().toLowerCase() : undefined;
  if (text === "true") return true;
  if (text === "false" || text === "") return false;
  throw new TypeError("USE_KEYCLOAK must be true or false");
}

/**
 * Parse the Auth0 machine audience: a JSON string array or one plain string. Returns a
 * string, array or undefined; configuration() rejects an empty string or empty array
 * whenever LEGACY_M2M_ISSUERS is set, so machine tokens always get an audience check.
 */
function audienceSetting(value, name) {
  if (typeof value === "string" && value.trim().startsWith("[")) return stringArray(value, name);
  return value;
}

/**
 * Resolve the validation/issuance contract for the provider selected by USE_KEYCLOAK.
 * Options override environment variables. Returns immutable settings used by every public
 * authentication factory.
 *
 * - USE_KEYCLOAK=true requires KEYCLOAK_ISSUER, KEYCLOAK_AUDIENCE and KEYCLOAK_TOKEN_URL.
 *   LEGACY_M2M_ISSUERS/LEGACY_M2M_AUDIENCE optionally keep Auth0 machine tokens valid.
 * - Otherwise (Auth0, the default) LEGACY_M2M_ISSUERS/LEGACY_M2M_AUDIENCE describe the
 *   trusted Auth0 machine tokens. Keycloak machine tokens remain valid only while both
 *   KEYCLOAK_ISSUER and KEYCLOAK_AUDIENCE are set, so callers that have not yet been
 *   switched back keep working; no Keycloak endpoint is contacted unless such a token arrives.
 *
 * Throws TypeError before serving requests when the selected provider's settings are
 * missing or malformed, or when USE_KEYCLOAK is not true/false.
 */
function configuration(options = {}) {
  const env = {...process.env, ...options};
  const keycloak = useKeycloak(env);
  const trustKeycloak = keycloak || Boolean(env.KEYCLOAK_ISSUER && env.KEYCLOAK_AUDIENCE);
  let issuer, audience, tokenUrl, jwksUri;
  if (trustKeycloak) {
    issuer = httpsUrl(env.KEYCLOAK_ISSUER, "KEYCLOAK_ISSUER");
    if (!/\/realms\/[^/]+$/.test(issuer)) throw new TypeError("KEYCLOAK_ISSUER must be an exact realm URL without a trailing slash");
    audience = env.KEYCLOAK_AUDIENCE;
    if (typeof audience !== "string" || !audience.trim() || audience !== audience.trim()) {
      throw new TypeError("KEYCLOAK_AUDIENCE is required");
    }
    jwksUri = httpsUrl(env.KEYCLOAK_JWKS_URL || `${issuer}/protocol/openid-connect/certs`, "KEYCLOAK_JWKS_URL");
  }
  if (keycloak) tokenUrl = httpsUrl(env.KEYCLOAK_TOKEN_URL, "KEYCLOAK_TOKEN_URL");
  const namespaces = stringArray(env.AUTH_USER_CLAIM_NAMESPACES, "AUTH_USER_CLAIM_NAMESPACES", [
    "https://topcoder-dev.com/claims/", "https://topcoder-dev.com/",
    "https://topcoder.com/claims/", "https://topcoder.com/"
  ]);
  const userIssuers = stringArray(env.VALID_ISSUERS, "VALID_ISSUERS").filter(value => value !== issuer);
  userIssuers.forEach(value => httpsUrl(value, "VALID_ISSUERS"));
  const legacyM2mIssuers = stringArray(env.LEGACY_M2M_ISSUERS, "LEGACY_M2M_ISSUERS");
  if (legacyM2mIssuers.some(value => !userIssuers.includes(value))) throw new TypeError("Legacy M2M issuers must also have configured legacy issuer trust");
  const legacyM2mAudience = audienceSetting(env.LEGACY_M2M_AUDIENCE, "LEGACY_M2M_AUDIENCE");
  if (legacyM2mIssuers.length && (Array.isArray(legacyM2mAudience) ? !legacyM2mAudience.length
    : typeof legacyM2mAudience !== "string" || !legacyM2mAudience.trim())) {
    throw new TypeError("LEGACY_M2M_AUDIENCE is required for Auth0 machine validation");
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
  return Object.freeze({useKeycloak: keycloak, issuer, audience, tokenUrl, jwksUri, namespaces, userIssuers,
    userAudiences, legacyM2mIssuers, legacyM2mAudience, userJwks: Object.freeze({...userJwks}), userSecret: env.AUTH_SECRET,
    allowedClientIds: stringArray(env.KEYCLOAK_ALLOWED_CLIENT_IDS, "KEYCLOAK_ALLOWED_CLIENT_IDS"),
    clientId: env.KEYCLOAK_CLIENT_ID, clientSecret: env.KEYCLOAK_CLIENT_SECRET,
    scope: env.KEYCLOAK_SCOPE, maxLifetime, format});
}

module.exports = {configuration, stringArray, useKeycloak};
