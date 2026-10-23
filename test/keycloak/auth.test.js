"use strict";
const {test, afterEach, mock} = require("node:test");
const assert = require("node:assert/strict");
const {generateKeyPairSync} = require("node:crypto");
const jwt = require("jsonwebtoken");
const nock = require("nock");
const {auth, middleware} = require("../..");
const {configuration} = require("../../lib/keycloak/configuration");
const {parseScopes, parseAuth0Scopes} = require("../../lib/keycloak/principal");
const issuer = "https://keycloak.example.test/realms/m2m";
const legacy = "https://auth.example.test/";
const pair = generateKeyPairSync("rsa", {modulusLength: 2048});
const other = generateKeyPairSync("rsa", {modulusLength: 2048});
const options = {USE_KEYCLOAK: "true", KEYCLOAK_ISSUER: issuer,
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

test("requires explicit Keycloak deployment settings when USE_KEYCLOAK=true", () => {
  for (const override of [{USE_KEYCLOAK: "yes"}, {KEYCLOAK_ISSUER: "http://untrusted"},
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

const auth0Mode = {USE_KEYCLOAK: "false", KEYCLOAK_ISSUER: undefined, KEYCLOAK_AUDIENCE: undefined,
  KEYCLOAK_TOKEN_URL: undefined, VALID_ISSUERS: JSON.stringify([legacy]), AUTH_USER_AUDIENCES: '["browser"]',
  LEGACY_M2M_ISSUERS: JSON.stringify([legacy]), LEGACY_M2M_AUDIENCE: "https://m2m.example.test/"};
const auth0Claims = {iss: legacy, aud: "https://m2m.example.test/", sub: "client-a@clients"};

test("USE_KEYCLOAK selects the provider, defaults to Auth0 and rejects other values", () => {
  for (const value of [true, "true", "TRUE", " true "]) assert.equal(auth.useKeycloak({USE_KEYCLOAK: value}), true);
  for (const value of [undefined, "", "false", "False", false]) assert.equal(auth.useKeycloak({USE_KEYCLOAK: value}), false);
  for (const value of ["yes", "1", "keycloak"]) assert.throws(() => auth.useKeycloak({USE_KEYCLOAK: value}), /USE_KEYCLOAK/);
  assert.equal(configuration(auth0Mode).useKeycloak, false);
  assert.equal(configuration(options).useKeycloak, true);
});

test("Auth0 mode needs no Keycloak settings and trusts Auth0 machines through LEGACY_M2M_*", async () => {
  nock.disableNetConnect();
  try {
    keys(legacy);
    const validator = auth.createValidator(auth0Mode);
    const service = await validator.verify(token(auth0Claims));
    assert.equal(service.kind, "service"); assert.equal(service.clientId, "client-a");
    await assert.rejects(validator.verify(token()), {code: "invalid_token"});
    keys(legacy);
    await assert.rejects(auth.createValidator(auth0Mode).verify(token({...auth0Claims, aud: "api"})), {code: "invalid_token"});
  } finally { nock.enableNetConnect(); }
});

test("Auth0 mode keeps accepting Keycloak machines while Keycloak issuer and audience are set", async () => {
  keys();
  const both = {...auth0Mode, KEYCLOAK_ISSUER: issuer, KEYCLOAK_AUDIENCE: "api"};
  assert.equal((await auth.createValidator(both).verify(token())).kind, "service");
  assert.equal(configuration(both).tokenUrl, undefined);
});

test("Auth0 machine scopes tolerate stray whitespace; Keycloak scopes stay exact", async () => {
  assert.deepEqual(parseAuth0Scopes("read:groups\tall:achievement\t write:groups"),
    ["all:achievement", "read:groups", "write:groups"]);
  assert.throws(() => parseAuth0Scopes(" \t"), TypeError);
  keys(legacy);
  const service = await auth.createValidator(auth0Mode).verify(token({...auth0Claims, scope: "read:groups all:achievement\t"}));
  assert.deepEqual(service.scopes, ["all:achievement", "read:groups"]);
  keys();
  await assert.rejects(auth.createValidator(options).verify(token({scope: "read:groups\twrite:groups"})), {code: "invalid_token"});
});

test("Auth0 provider sends the 3.x proxy request, caches per credentials and sanitizes errors", async () => {
  const settings = {USE_KEYCLOAK: "false", AUTH0_URL: "https://tenant.example.test/oauth/token",
    AUTH0_AUDIENCE: "https://m2m.example.test/", AUTH0_PROXY_SERVER_URL: "https://proxy.example.test/token",
    AUTH0_CLIENT_ID: "auth0-client-cache", AUTH0_CLIENT_SECRET: "test-only-auth0"};
  let requests = 0;
  const proxy = nock("https://proxy.example.test").post("/token", body => {
    requests += 1;
    return body.grant_type === "client_credentials" && body.auth0_url === settings.AUTH0_URL &&
      body.audience === settings.AUTH0_AUDIENCE && body.client_id === settings.AUTH0_CLIENT_ID &&
      body.client_secret === settings.AUTH0_CLIENT_SECRET && body.scope === undefined;
  }).reply(200, {access_token: token(auth0Claims)});
  const provider = auth.m2m(settings);
  const tokens = await Promise.all([provider.getMachineToken(), provider.getMachineToken()]);
  assert.equal(tokens[0], tokens[1]); assert.equal(requests, 1); assert.ok(proxy.isDone());
  assert.equal(await auth.m2m(settings).getMachineToken(), tokens[0]);
  nock("https://proxy.example.test").post("/token").reply(200, {error: "access_denied"});
  await assert.rejects(provider.getMachineToken("auth0-client-denied", "test-only-denied"), error =>
    /Auth0 M2M token request failed/.test(error.message) && !error.message.includes("test-only-denied"));
  nock("https://proxy.example.test").post("/token").reply(500, {});
  await assert.rejects(provider.getMachineToken("auth0-client-error", "test-only-error"), /Auth0 M2M token request failed/);
  provider.clearCache();
});

test("Auth0 provider defaults the proxy to AUTH0_URL and fails on use, not construction", async () => {
  const provider = auth.m2m({USE_KEYCLOAK: "false", AUTH0_URL: undefined, AUTH0_PROXY_SERVER_URL: undefined,
    AUTH0_CLIENT_ID: undefined, AUTH0_CLIENT_SECRET: undefined});
  await assert.rejects(provider.getMachineToken(), TypeError);
  await assert.rejects(provider.getMachineToken("auth0-client-x", "test-only-x"), /AUTH0_URL/);
  nock("https://tenant.example.test").post("/oauth/token", body => body.client_id === "auth0-client-direct")
    .reply(200, {access_token: token(auth0Claims)});
  const direct = auth.m2m({USE_KEYCLOAK: "false", AUTH0_URL: "https://tenant.example.test/oauth/token",
    AUTH0_PROXY_SERVER_URL: undefined, AUTH0_AUDIENCE: "https://m2m.example.test/"});
  assert.equal(typeof await direct.getMachineToken("auth0-client-direct", "test-only-direct"), "string");
  direct.clearCache();
});

test("wrapperSettings returns the active provider's settings under the wrapper's AUTH0_* names", () => {
  const all = {AUTH0_URL: "https://tenant.example.test/oauth/token", AUTH0_AUDIENCE: "https://m2m.example.test/",
    AUTH0_PROXY_SERVER_URL: "https://proxy.example.test/token", AUTH0_CLIENT_ID: "auth0-id", AUTH0_CLIENT_SECRET: "auth0-secret",
    KEYCLOAK_TOKEN_URL: options.KEYCLOAK_TOKEN_URL, KEYCLOAK_AUDIENCE: "api",
    KEYCLOAK_CLIENT_ID: "client-a", KEYCLOAK_CLIENT_SECRET: "test-only-a"};
  assert.deepEqual(auth.wrapperSettings({...all, USE_KEYCLOAK: "true"}), {AUTH0_URL: options.KEYCLOAK_TOKEN_URL,
    AUTH0_AUDIENCE: "api", AUTH0_PROXY_SERVER_URL: options.KEYCLOAK_TOKEN_URL,
    AUTH0_CLIENT_ID: "client-a", AUTH0_CLIENT_SECRET: "test-only-a"});
  assert.deepEqual(auth.wrapperSettings({...all, USE_KEYCLOAK: "false"}), {AUTH0_URL: all.AUTH0_URL,
    AUTH0_AUDIENCE: all.AUTH0_AUDIENCE, AUTH0_PROXY_SERVER_URL: all.AUTH0_PROXY_SERVER_URL,
    AUTH0_CLIENT_ID: "auth0-id", AUTH0_CLIENT_SECRET: "auth0-secret"});
});

test("LEGACY_M2M_AUDIENCE also accepts a JSON array of Auth0 audiences", async () => {
  keys(legacy);
  const config = {...auth0Mode, LEGACY_M2M_AUDIENCE: '["https://other.example.test/", "https://m2m.example.test/"]'};
  assert.equal((await auth.createValidator(config).verify(token(auth0Claims))).kind, "service");
});

test("an empty LEGACY_M2M_AUDIENCE array is rejected instead of disabling the audience check", async () => {
  for (const value of ["[]", "", " "]) {
    assert.throws(() => auth.createValidator({...auth0Mode, LEGACY_M2M_AUDIENCE: value}), /LEGACY_M2M_AUDIENCE/);
    assert.throws(() => auth.createValidator({...options, ...auth0Mode, USE_KEYCLOAK: "true",
      KEYCLOAK_ISSUER: issuer, KEYCLOAK_AUDIENCE: "api", KEYCLOAK_TOKEN_URL: options.KEYCLOAK_TOKEN_URL,
      LEGACY_M2M_AUDIENCE: value}), /LEGACY_M2M_AUDIENCE/);
  }
});

test("Auth0 provider ignores AUTH_SCOPE, AUTH_PROVIDER and AUTH_CONTENT_TYPE from the environment", async () => {
  const saved = {...process.env};
  Object.assign(process.env, {AUTH_SCOPE: "env:scope", AUTH_PROVIDER: "env-provider", AUTH_CONTENT_TYPE: "env-type"});
  try {
    nock("https://proxy.example.test").post("/token", body => body.scope === undefined &&
      body.provider === undefined && body.content_type === undefined).reply(200, {access_token: token(auth0Claims)});
    const settings = {USE_KEYCLOAK: "false", AUTH0_URL: "https://tenant.example.test/oauth/token",
      AUTH0_AUDIENCE: "https://m2m.example.test/", AUTH0_PROXY_SERVER_URL: "https://proxy.example.test/token"};
    const provider = auth.m2m(settings);
    assert.equal(typeof await provider.getMachineToken("auth0-client-env", "test-only-env"), "string");
    nock("https://proxy.example.test").post("/token", body => body.scope === "read:a" &&
      body.provider === "p" && body.content_type === "c").reply(200, {access_token: token(auth0Claims)});
    const explicit = auth.m2m({...settings, AUTH_SCOPE: "read:a", AUTH_PROVIDER: "p", AUTH_CONTENT_TYPE: "c"});
    assert.equal(typeof await explicit.getMachineToken("auth0-client-options", "test-only-options"), "string");
    explicit.clearCache();
  } finally {
    for (const name of ["AUTH_SCOPE", "AUTH_PROVIDER", "AUTH_CONTENT_TYPE"]) {
      if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name];
    }
  }
});
