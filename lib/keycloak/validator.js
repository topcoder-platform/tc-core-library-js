"use strict";
const jwt = require("jsonwebtoken");
const jwks = require("jwks-rsa");
const {configuration} = require("./configuration");
const {AuthenticationError, principal, claim} = require("./principal");

/**
 * Create the shared verified-principal validator. Options are deployment settings.
 * Returns {verify(token)}; configuration errors throw synchronously. verify rejects
 * with AuthenticationError for all token/network failures, without raw diagnostics.
 * Only configured issuers select keys; token jku/x5u URLs are never followed.
 */
function createValidator(options = {}) {
  const config = configuration(options);
  const clients = new Map();

  /** Get the signing key for a configured issuer and key ID; rejects on JWKS failure. */
  async function signingKey(issuer, kid) {
    if (typeof kid !== "string" || !kid || kid.length > 256) throw new AuthenticationError();
    if (!clients.has(issuer)) {
      const uri = issuer === config.issuer ? config.jwksUri
        : config.userJwks[issuer] || `${issuer.replace(/\/$/, "")}/.well-known/jwks.json`;
      clients.set(issuer, jwks({jwksUri: uri, cache: true, cacheMaxAge: 600000,
        cacheMaxEntries: 10, rateLimit: true, jwksRequestsPerMinute: 10, timeout: 5000}));
    }
    return (await clients.get(issuer).getSigningKey(kid)).getPublicKey();
  }

  /** Verify a compact JWT and return its normalized principal; rejects invalid tokens with a sanitized 401. */
  async function verify(token) {
    try {
      if (typeof token !== "string" || token.length > 32768 || token.split(".").length !== 3) throw new AuthenticationError();
      const decoded = jwt.decode(token, {complete: true});
      if (!decoded || !decoded.payload || typeof decoded.payload !== "object" || decoded.header.crit) throw new AuthenticationError();
      const {iss} = decoded.payload;
      const machine = iss === config.issuer;
      if (!machine && !config.userIssuers.includes(iss)) throw new AuthenticationError();
      const legacyMachine = config.legacyM2mIssuers.includes(iss) &&
        claim(decoded.payload, "gty", config.namespaces) === "client-credentials";
      const alg = decoded.header.alg;
      let key;
      if (alg === "RS256") key = await signingKey(iss, decoded.header.kid);
      else if (!machine && !legacyMachine && alg === "HS256" && config.userSecret) key = config.userSecret;
      else throw new AuthenticationError();
      const audience = machine ? config.audience : (legacyMachine ? config.legacyM2mAudience : config.userAudiences);
      const payload = jwt.verify(token, key, {algorithms: [alg], issuer: iss, clockTolerance: 30,
        ...(audience.length ? {audience} : {})});
      if (!Number.isSafeInteger(payload.exp) || !Number.isSafeInteger(payload.iat) ||
          payload.iat > Math.floor(Date.now() / 1000) + 30 || payload.exp <= payload.iat ||
          (machine && payload.exp - payload.iat > config.maxLifetime)) throw new AuthenticationError();
      return principal(payload, config);
    } catch { throw new AuthenticationError(); }
  }
  return {verify};
}

/** Adapt the former verifier callback signature to shared validation; configuration comes from environment. */
function legacyVerifier() {
  const validator = createValidator();
  return {
    /** Verify token and invoke callback(error, principal); the unused legacy secret cannot change issuer trust. */
    validateToken(token, _secret, callback) {
      validator.verify(token).then(value => callback(undefined, value), error => callback(error));
    }
  };
}

module.exports = {createValidator, legacyVerifier};
