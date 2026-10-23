"use strict";
const configuration = require("./configuration");
const keycloakM2m = require("./m2m");
const auth0M2m = require("./auth0-m2m");

/**
 * Create the M2M token provider selected by USE_KEYCLOAK. Options merge over the
 * environment. USE_KEYCLOAK=true returns the Keycloak provider (KEYCLOAK_* settings,
 * verified tokens); anything else returns the Auth0 provider (3.x AUTH0_* settings).
 * Both return getMachineToken(clientId?, clientSecret?, scope?) and clearCache().
 * Used directly by services and by tc-bus-api-wrapper through auth.m2m. Throws
 * TypeError for an invalid USE_KEYCLOAK value or invalid Keycloak settings.
 */
function m2m(options = {}) {
  return useKeycloak(options) ? keycloakM2m(options) : auth0M2m(options);
}

/**
 * Return the active provider's endpoint, audience and workload credentials under the
 * AUTH0_* option names that tc-bus-api-wrapper validates and hands back to auth.m2m.
 * Options merge over the environment, so a service can map its own setting names.
 * - USE_KEYCLOAK=true: KEYCLOAK_TOKEN_URL (as AUTH0_URL and AUTH0_PROXY_SERVER_URL),
 *   KEYCLOAK_AUDIENCE, KEYCLOAK_CLIENT_ID and KEYCLOAK_CLIENT_SECRET.
 * - Otherwise: AUTH0_URL, AUTH0_AUDIENCE, AUTH0_PROXY_SERVER_URL, AUTH0_CLIENT_ID and
 *   AUTH0_CLIENT_SECRET, unchanged.
 * Missing values are returned as undefined so the wrapper's validation reports them.
 * Throws TypeError only for an invalid USE_KEYCLOAK value.
 */
function wrapperSettings(options = {}) {
  const env = {...process.env, ...options};
  if (configuration.useKeycloak(env)) {
    return {AUTH0_URL: env.KEYCLOAK_TOKEN_URL, AUTH0_AUDIENCE: env.KEYCLOAK_AUDIENCE,
      AUTH0_PROXY_SERVER_URL: env.KEYCLOAK_TOKEN_URL, AUTH0_CLIENT_ID: env.KEYCLOAK_CLIENT_ID,
      AUTH0_CLIENT_SECRET: env.KEYCLOAK_CLIENT_SECRET};
  }
  return {AUTH0_URL: env.AUTH0_URL, AUTH0_AUDIENCE: env.AUTH0_AUDIENCE,
    AUTH0_PROXY_SERVER_URL: env.AUTH0_PROXY_SERVER_URL, AUTH0_CLIENT_ID: env.AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET: env.AUTH0_CLIENT_SECRET};
}

/**
 * Report whether USE_KEYCLOAK selects Keycloak. Options merge over the environment.
 * Returns true for "true" (any case), false when missing, empty or "false". Services use
 * it to choose provider-specific settings such as config validation; the factories call
 * it themselves. Throws TypeError for any other value.
 */
function useKeycloak(options = {}) {
  return configuration.useKeycloak({...process.env, ...options});
}

module.exports = {m2m, wrapperSettings, useKeycloak};
