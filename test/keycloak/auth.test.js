"use strict";
const {test, afterEach, mock} = require("node:test");
const assert = require("node:assert/strict");
const {generateKeyPairSync} = require("node:crypto");
const jwt = require("jsonwebtoken");
const nock = require("nock");
const {auth, middleware} = require("../..");
const {configuration} = require("../../lib/keycloak/configuration");
const {parseScopes} = require("../../lib/keycloak/principal");
const issuer = "https://keycloak.example.test/realms/m2m";
const legacy = "https://auth.example.test/";
const pair = generateKeyPairSync("rsa", {modulusLength: 2048});
const other = generateKeyPairSync("rsa", {modulusLength: 2048});
const options = {M2M_PROVIDER: "keycloak", KEYCLOAK_ISSUER: issuer,
  KEYCLOAK_AUDIENCE: "api", KEYCLOAK_TOKEN_URL: "https://proxy.example.test/token",
  VALID_ISSUERS: "[]", KEYCLOAK_CLIENT_ID: "client-a", KEYCLOAK_CLIENT_SECRET: "test-only-a"};

/** Sign realistic synthetic service claims with configurable overrides for cryptographic contract tests. */
function token(overrides = {}, key = pair.privateKey, alg = "RS256", kid = "key-1") {
  const now = Math.floor(Date.now() / 1000);
  const payload = {iss: issuer, aud: "api", sub: "service-account-a", azp: "client-a",
    gty: "client-credentials", scope: "read:groups write:groups", iat: now, exp: now + 900,
    ...overrides};
  for (const name of Object.keys(payload)) if (payload[name] === undefined) delete payload[name];
  return jwt.sign(payload, key, {algorithm: alg, keyid: kid,
    ...(Object.prototype.hasOwnProperty.call(overrides, "iat") && overrides.iat === undefined ? {noTimestamp: true} : {})});
}

/** Mock the trusted issuer's public JWKS endpoint with a real RSA public key; returns the HTTP scope. */
function keys(origin = issuer, key = pair.publicKey, kid = "key-1") {
  const uri = origin === issuer ? `${issuer}/protocol/openid-connect/certs` : `${origin}.well-known/jwks.json`;
  const url = new URL(uri);
  return nock(url.origin).get(url.pathname).reply(200, {keys: [{...key.export({format: "jwk"}), kid, alg: "RS256", use: "sig"}]});
}

afterEach(() => { nock.cleanAll(); mock.restoreAll(); });

test("requires explicit Keycloak deployment settings", () => {
  for (const override of [{M2M_PROVIDER: "auth0"}, {KEYCLOAK_ISSUER: "http://untrusted"},
    {KEYCLOAK_AUDIENCE: ""}, {KEYCLOAK_TOKEN_URL: undefined}, {KEYCLOAK_ISSUER: issuer + "/"}]) {
    assert.throws(() => auth.createValidator({...options, ...override}), TypeError);
  }
  assert.throws(() => configuration({...options, VALID_ISSUERS: JSON.stringify([legacy])}), /audience/);
});

test("normalizes verified Keycloak tokens and checks exact all/any permissions", async () => {
  keys();
  const user = await auth.createValidator(options).verify(token({aud: ["api", "other"]}));
  assert.equal(user.kind, "service"); assert.equal(user.isMachine, true);
  assert.equal(user.clientId, "client-a"); assert.equal(user.userId, undefined);
  assert.deepEqual(user.scopes, ["read:groups", "write:groups"]);
  assert.equal(auth.hasScopes(user, ["read:groups", "write:bus_api"]), false);
  assert.equal(auth.hasScopes(user, ["read:groups", "write:bus_api"], "any"), true);
  assert.equal(auth.hasScopes(user, ["read:group"]), false);
  assert.throws(() => auth.hasScopes(user, []), TypeError);
});

test("rejects wrong issuer without contacting arbitrary JWKS URLs", async () => {
  nock.disableNetConnect();
  try {
    await assert.rejects(auth.createValidator(options).verify(token({iss: "https://attacker.example/"})), {code: "invalid_token"});
  } finally { nock.enableNetConnect(); }
});

test("rejects tampering, wrong audience, missing/expired/future claims and unsafe identity", async () => {
  const bad = [
    token({}, other.privateKey), token({aud: "wrong"}), token({exp: undefined}), token({iat: undefined}),
    token({exp: Math.floor(Date.now()/1000)-60}), token({iat: Math.floor(Date.now()/1000)+120}),
    token({exp: Math.floor(Date.now()/1000)+7200}), token({gty: "password"}), token({azp: ""}),
    token({sub: ""}), token({scope: ""}), token({scope: "read:groups\nadmin"}),
    token({"https://topcoder-dev.com/claims/userId": 123}), token({roles: []}),
    token({}, "test-only-hmac-secret", "HS256"), "not.a.token"
  ];
  for (const value of bad) {
    keys();
    await assert.rejects(auth.createValidator(options).verify(value), error => error.status === 401 && error.message === "Invalid or expired token");
    nock.cleanAll();
  }
});

test("enforces the optional machine client allowlist", async () => {
  keys();
  await assert.rejects(auth.createValidator({...options, KEYCLOAK_ALLOWED_CLIENT_IDS: '["another-client"]'}).verify(token()), {code: "invalid_token"});
});

test("keeps Auth0 member OAuth scopes out of machine authorization", async () => {
  keys(legacy);
  const config = {...options, VALID_ISSUERS: JSON.stringify([legacy]), AUTH_USER_AUDIENCES: '["browser-client"]'};
  const user = await auth.createValidator(config).verify(token({iss: legacy, aud: "browser-client", sub: "auth0|123",
    gty: "authorization_code", azp: "browser-client", "https://topcoder-dev.com/claims/userId": "123",
    "https://topcoder-dev.com/claims/roles": ["administrator"], "https://topcoder-dev.com/claims/handle": "sample"}));
  assert.equal(user.kind, "user"); assert.equal(user.isMachine, false); assert.equal(user.userId, 123);
  assert.deepEqual(user.scopes, []); assert.equal(user.scope, undefined);
  assert.equal(auth.hasScopes(user, ["read:groups"]), false);
});

test("legacy user HS256 remains isolated from Keycloak and requires member identity", async () => {
  const config = {...options, VALID_ISSUERS: JSON.stringify([legacy]), ALLOW_LEGACY_USER_AUDIENCE: "true", AUTH_SECRET: "test-only-legacy-secret"};
  const value = token({iss: legacy, gty: undefined, sub: "auth0|123", userId: 123, roles: []}, config.AUTH_SECRET, "HS256");
  assert.equal((await auth.createValidator(config).verify(value)).kind, "user");
  await assert.rejects(auth.createValidator(config).verify(token({}, config.AUTH_SECRET, "HS256")));
});

test("rejects conflicting namespaced member identities", async () => {
  keys(legacy);
  const config = {...options, VALID_ISSUERS: JSON.stringify([legacy]), AUTH_USER_AUDIENCES: '["api"]'};
  await assert.rejects(auth.createValidator(config).verify(token({iss: legacy, gty: undefined, userId: 123,
    "https://topcoder-dev.com/claims/userId": 456})), {code: "invalid_token"});
});

test("Auth0 machines require explicit overlap and their own audience; scope alone grants nothing", async () => {
  const config = {...options, VALID_ISSUERS: JSON.stringify([legacy]), AUTH_USER_AUDIENCES: '["browser"]'};
  keys(legacy);
  await assert.rejects(auth.createValidator(config).verify(token({iss: legacy, sub: "client-a@clients"})));
  keys(legacy);
  const overlap = {...config, LEGACY_M2M_ISSUERS: JSON.stringify([legacy]), LEGACY_M2M_AUDIENCE: "api"};
  assert.equal((await auth.createValidator(overlap).verify(token({iss: legacy, sub: "client-a@clients"}))).kind, "service");
  keys(legacy);
  await assert.rejects(auth.createValidator(overlap).verify(token({iss: legacy, aud: "wrong", sub: "client-a@clients"})));
});

test("signing key rollover refreshes the same issuer cache for a new kid", async () => {
  const validator = auth.createValidator(options);
  keys(); await validator.verify(token());
  keys(issuer, other.publicKey, "key-2");
  assert.equal((await validator.verify(token({}, other.privateKey, "RS256", "key-2"))).kind, "service");
});

test("callback middleware assigns one shared principal and rejects a missing bearer token", async () => {
  const authenticate = middleware.jwtAuthenticator(options);
  const missing = await new Promise(resolve => authenticate({headers: {}}, {}, resolve));
  assert.equal(missing.status, 401);
  keys(); const req = {headers: {authorization: `Bearer ${token()}`}};
  await new Promise((resolve, reject) => authenticate(req, {}, error => error ? reject(error) : resolve()));
  assert.equal(req.user, req.authUser); assert.equal(req.authUser.kind, "service");
});

test("M2M cache isolates secrets and requested subsets, and coalesces concurrent requests", async () => {
  keys(); let requests = 0;
  mock.method(globalThis, "fetch", async (_url, request) => {
    requests += 1; const body = JSON.parse(request.body);
    if (body.client_secret !== "test-only-a") return {ok: false};
    return {ok: true, json: async () => ({access_token: token({scope: body.scope || "read:groups write:groups"}), expires_in: 900})};
  });
  const provider = auth.m2m(options);
  const first = await Promise.all([provider.getMachineToken(), provider.getMachineToken()]);
  assert.equal(first[0], first[1]); assert.equal(requests, 1);
  await provider.getMachineToken(); assert.equal(requests, 1);
  await provider.getMachineToken(undefined, undefined, "read:groups"); assert.equal(requests, 2);
  await assert.rejects(provider.getMachineToken("client-a", "invalid"), /Keycloak M2M token request failed/);
  assert.equal(requests, 3);
  await assert.rejects(provider.getMachineToken(undefined, undefined, ""), TypeError);
});

test("M2M rejects overbroad scope responses and returns sanitized errors", async () => {
  keys();
  mock.method(globalThis, "fetch", async () => ({ok: true, json: async () => ({access_token: token(), expires_in: 900})}));
  await assert.rejects(auth.m2m(options).getMachineToken(undefined, undefined, "read:groups"), error =>
    error.message === "Keycloak M2M token request failed" && !error.message.includes(options.KEYCLOAK_CLIENT_SECRET));
});

test("M2M uses trusted endpoint and form encoding when selected", async () => {
  keys();
  mock.method(globalThis, "fetch", async (url, request) => {
    assert.equal(url, options.KEYCLOAK_TOKEN_URL); assert.equal(request.redirect, "error");
    assert.equal(request.headers["content-type"], "application/x-www-form-urlencoded");
    assert.equal(new URLSearchParams(request.body).get("audience"), "api");
    return {ok: true, json: async () => ({access_token: token(), expires_in: 900})};
  });
  await auth.m2m({...options, KEYCLOAK_TOKEN_FORMAT: "form"}).getMachineToken();
});

test("scope parsing is exact, canonical and does not expand wildcards", () => {
  assert.deepEqual(parseScopes("write:groups  read:groups read:groups"), ["read:groups", "write:groups"]);
  assert.deepEqual(parseScopes("all:groups"), ["all:groups"]);
  assert.throws(() => parseScopes("read:groups\twrite:groups"));
});
