"use strict";
const {createValidator} = require("./validator");
const {AuthenticationError} = require("./principal");

/**
 * Create Express/Restify-compatible bearer middleware using shared validation.
 * Options are deployment settings. Returns middleware assigning req.authUser and
 * req.user to the same verified principal. Configuration errors throw at startup;
 * missing/invalid credentials reach next(error) with a sanitized status 401.
 */
function jwtAuthenticator(options = {}) {
  const validator = createValidator(options);
  return function authenticate(req, _res, next) {
    const header = req.headers && req.headers.authorization;
    const match = typeof header === "string" && /^Bearer ([^\s]+)$/i.exec(header);
    if (!match) return next(new AuthenticationError());
    validator.verify(match[1]).then(user => {
      req.authUser = user;
      req.user = user;
      next();
    }, next);
  };
}
module.exports = jwtAuthenticator;
