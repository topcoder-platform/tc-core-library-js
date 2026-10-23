"use strict";
const {createValidator, legacyVerifier} = require("./lib/keycloak/validator");
const {hasScopes} = require("./lib/keycloak/scopes");
const {m2m, wrapperSettings, useKeycloak} = require("./lib/keycloak/provider");

module.exports = {
  middleware: {
    jwtAuthenticator: require("./lib/keycloak/middleware"),
    logger: require("./lib/middleware/logger"),
    permissions: require("./lib/middleware/permissions")
  },
  Authorizer: require("./lib/authorizer"),
  util: require("./lib/util"),
  logger: require("./lib/logger"),
  auth: {
    m2m,
    wrapperSettings,
    useKeycloak,
    verifier: legacyVerifier,
    createValidator,
    hasScopes
  }
};
