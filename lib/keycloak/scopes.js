"use strict";

/**
 * Evaluate exact permissions on a normalized service principal.
 * Inputs are principal, required scopes and mode ('all' default or 'any'). Returns
 * a boolean. Invalid requirements/mode throw TypeError; users never pass. Alias
 * expansion belongs in explicit reviewed route policy, not issuer normalization.
 */
function hasScopes(user, required, mode = "all") {
  if (!["all", "any"].includes(mode) || !Array.isArray(required) || !required.length ||
      required.some(scope => typeof scope !== "string" || !scope)) throw new TypeError("Invalid scope policy");
  if (!user || user.kind !== "service" || user.isMachine !== true || !Array.isArray(user.scopes)) return false;
  const check = scope => user.scopes.includes(scope);
  return mode === "all" ? required.every(check) : required.some(check);
}

module.exports = {hasScopes};
