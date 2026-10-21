"use strict";

/** Sanitized error returned by validation; never includes token or credential contents. */
class AuthenticationError extends Error {
  /** Create a generic 401 error. No inputs or side effects; used by auth adapters. */
  constructor() {
    super("Invalid or expired token");
    this.name = "AuthenticationError";
    this.status = 401;
    this.statusCode = 401;
    this.code = "invalid_token";
  }
}

/** Read an exact plain/namespaced claim, rejecting conflicting values; returns the value or undefined. */
function claim(payload, name, namespaces) {
  const values = [name, ...namespaces.map(prefix => prefix + name)]
    .filter(key => Object.prototype.hasOwnProperty.call(payload, key)).map(key => payload[key]);
  if (values.some(value => JSON.stringify(value) !== JSON.stringify(values[0]))) throw new AuthenticationError();
  return values[0];
}

/** Parse an OAuth scope string into unique permissions. Returns an array or throws TypeError. */
function parseScopes(value) {
  if (typeof value !== "string" || !value.trim()) throw new TypeError("A nonempty OAuth scope string is required");
  const scopes = value.trim().split(/ +/);
  if (scopes.some(scope => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope))) throw new TypeError("Invalid OAuth scope syntax");
  return [...new Set(scopes)].sort();
}

/** Reproduce the legacy numeric client hash for audited consumers; accepts an ID and returns a negative number. */
function azpHash(clientId) {
  return -(100000 + [...clientId].reduce((sum, char, index) => sum + char.charCodeAt(0) * (index + 1), 0));
}

/**
 * Normalize an already verified JWT into the common service/user principal.
 * Inputs are verified claims and configuration; returns claims plus authoritative
 * kind/isMachine/scopes/clientId fields. Throws AuthenticationError on conflicting
 * identities. User OAuth scopes are never treated as machine permissions.
 */
function principal(payload, config) {
  const userId = claim(payload, "userId", config.namespaces);
  const roles = claim(payload, "roles", config.namespaces);
  const grant = claim(payload, "gty", config.namespaces);
  if (payload.iss === config.issuer || (config.legacyM2mIssuers.includes(payload.iss) && grant === "client-credentials")) {
    if (grant !== "client-credentials" || userId !== undefined || roles !== undefined ||
        typeof payload.azp !== "string" || !payload.azp || typeof payload.sub !== "string" || !payload.sub ||
        (config.allowedClientIds.length && !config.allowedClientIds.includes(payload.azp))) throw new AuthenticationError();
    let scopes;
    try { scopes = parseScopes(payload.scope); } catch { throw new AuthenticationError(); }
    return {...payload, kind: "service", isMachine: true, clientId: payload.azp,
      scopes, roles: [], userId: undefined, handle: undefined, azpHash: azpHash(payload.azp)};
  }
  if (grant === "client-credentials" || payload.isMachine === true ||
      (typeof payload.sub === "string" && payload.sub.endsWith("@clients")) ||
      !/^[1-9][0-9]*$/.test(String(userId)) || !Number.isSafeInteger(Number(userId)) ||
      (roles !== undefined && (!Array.isArray(roles) || roles.some(role => typeof role !== "string")))) {
    throw new AuthenticationError();
  }
  return {...payload, kind: "user", isMachine: false, clientId: undefined, azpHash: undefined,
    scopes: [], scope: undefined, userId: Number(userId), roles: roles || [],
    handle: claim(payload, "handle", config.namespaces),
    email: claim(payload, "email", config.namespaces)};
}

module.exports = {AuthenticationError, claim, parseScopes, principal};
