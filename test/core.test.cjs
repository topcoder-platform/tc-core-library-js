const { test } = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const { createServer } = require('node:http');
const jwt = require('jsonwebtoken');
const { createJwtVerifier, createJwtAuthenticator, normalizeAuthUser, createM2MClient, createBusApiClient, resolveBusEventsUrl } = require('../dist');

const secret = 'a-test-only-secret-with-at-least-32-bytes';
const issuer = 'https://issuer.example/';
const config = { issuers: [{ issuer, algorithm: 'HS256', secret, audience: 'api' }], clockTolerance: 0 };
const sign = (claims = {}, options = {}) => jwt.sign({ sub: '42', ...claims }, secret, { issuer, audience: 'api', expiresIn: 300, ...options });

test('verifies signed identities and exact trusted namespaced claims', async () => {
  const user = await createJwtVerifier(config).verify(sign({ 'https://topcoder.com/userId': '42', 'https://topcoder.com/roles': ['Administrator'], scope: 'read:foo' }));
  assert.equal(user.userId, '42');
  assert.deepEqual(user.roles, ['Administrator']);
  assert.equal(user.isMachine, false);
});

test('rejects malformed, unsigned, wrong-key, wrong-issuer/audience, expired and future tokens', async () => {
  const verifier = createJwtVerifier(config);
  const bad = ['abc', '', sign({}, { algorithm: 'HS384' }), sign({}, { issuer: 'https://untrusted.example/' }), sign({}, { audience: 'elsewhere' }), sign({}, { expiresIn: -1 }), sign({ nbf: Math.floor(Date.now() / 1000) + 1000 }), sign({ iat: Math.floor(Date.now() / 1000) + 1000 }), jwt.sign({ iss: issuer, aud: 'api' }, secret), jwt.sign({ iss: issuer, aud: 'api', exp: 9999999999 }, 'different-secret'), jwt.sign({ iss: issuer, aud: 'api', exp: 9999999999 }, null, { algorithm: 'none' })];
  for (const token of bad) await assert.rejects(verifier.verify(token), /Invalid or expired/);
});

test('rejects missing trust, duplicate policies, unsafe keys and unconfigured audience', () => {
  assert.throws(() => createJwtVerifier({}), /VALID_ISSUERS/);
  assert.throws(() => createJwtVerifier({ issuers: [...config.issuers, ...config.issuers] }), /Duplicate/);
  assert.throws(() => createJwtVerifier({ issuers: [{ issuer, algorithm: 'HS256', secret }] }), /audience/);
  assert.throws(() => createJwtVerifier({ issuers: [{ issuer, algorithm: 'HS256', secret: '-----BEGIN PUBLIC KEY-----', audience: 'api' }] }), /symmetric/);
});

test('does not promote scope-bearing humans or spoofed flags and arbitrary suffix claims', () => {
  assert.throws(() => normalizeAuthUser({ scope: 'admin', isMachine: true }), /Conflicting/);
  const user = normalizeAuthUser({ 'https://attacker.example/roles': ['Administrator'], fakeuserId: 1 });
  assert.deepEqual(user.roles, []);
  assert.equal(user.userId, undefined);
  assert.equal(normalizeAuthUser({ gty: 'client-credentials', scope: 'read:foo' }).isMachine, true);
  assert.throws(() => normalizeAuthUser({ gty: 'client-credentials', roles: ['member'] }), /Conflicting/);
  assert.throws(() => normalizeAuthUser({ userId: '42garbage' }), /identity/);
});

test('RS256 uses configured JWKS, separates key types and rejects untrusted issuers before I/O', async (t) => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'key-1', use: 'sig', alg: 'RS256' };
  let requests = 0;
  const server = createServer((_req, res) => { requests++; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ keys: [jwk] })); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const verifier = createJwtVerifier({ issuers: [{ issuer, algorithm: 'RS256', audience: 'api', jwksUri: `http://127.0.0.1:${server.address().port}/keys` }] });
  const token = jwt.sign({ sub: '42' }, privateKey, { algorithm: 'RS256', keyid: 'key-1', issuer, audience: 'api', expiresIn: 300 });
  await assert.rejects(verifier.verify(sign({}, { issuer: 'https://untrusted.example/' })));
  assert.equal(requests, 0);
  assert.equal((await verifier.verify(token)).sub, '42');
  await verifier.verify(token);
  assert.equal(requests, 1);
  await assert.rejects(verifier.verify(sign()));
});

test('middleware always completes unsupported algorithms with 401 and never calls next', async () => {
  const authenticator = createJwtAuthenticator(config);
  await new Promise((resolve, reject) => {
    const response = { status(code) { assert.equal(code, 401); return response; }, json(body) { assert.equal(body.result.status, 401); resolve(); } };
    authenticator({ headers: { authorization: `Bearer ${sign({}, { algorithm: 'HS512' })}` } }, response, () => reject(new Error('must not authorize')));
  });
});

const oauth = { AUTH0_URL: 'https://auth.example/oauth/token', AUTH0_AUDIENCE: 'api' };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

test('M2M deduplicates concurrent requests and isolates credentials and client instances', async () => {
  let calls = 0;
  const mock = async (_url, request) => { calls++; assert.equal(request.redirect, 'error'); return json({ access_token: `token-${calls}`, expires_in: 3600 }); };
  const one = createM2MClient({ ...oauth, fetch: mock });
  const two = createM2MClient({ ...oauth, AUTH0_AUDIENCE: 'other', fetch: mock });
  const tokens = await Promise.all(Array.from({ length: 10 }, () => one.getMachineToken('id', 'secret')));
  assert.equal(new Set(tokens).size, 1);
  assert.equal(calls, 1);
  await one.getMachineToken('id', 'rotated-secret');
  await two.getMachineToken('id', 'secret');
  assert.equal(calls, 3);
  one.clearCache();
  await one.getMachineToken('id', 'secret');
  assert.equal(calls, 4);
});

test('M2M does not cache absent/short expiry; failures are safe and not cached', async () => {
  let calls = 0;
  const client = createM2MClient({ ...oauth, fetch: async () => { calls++; return json({ access_token: 'opaque', expires_in: 30 }); } });
  await client.getMachineToken('id', 'secret');
  await client.getMachineToken('id', 'secret');
  assert.equal(calls, 2);
  const failed = createM2MClient({ ...oauth, fetch: async () => json({ client_secret: 'do-not-log', access_token: 'sensitive' }, 403) });
  await assert.rejects(failed.getMachineToken('id', 'secret'), error => !error.message.includes('do-not-log') && error.status === 403);
});

test('proxy receives its explicit auth0_url without cross-client state', async () => {
  const client = createM2MClient({ ...oauth, AUTH0_PROXY_SERVER_URL: 'https://proxy.example/token', fetch: async (url, request) => {
    assert.equal(url, 'https://proxy.example/token');
    assert.equal(JSON.parse(request.body).auth0_url, oauth.AUTH0_URL);
    return json({ access_token: 'opaque', expires_in: 3600 });
  } });
  assert.equal(await client.getMachineToken('id', 'secret'), 'opaque');
});

const event = { topic: 'test.event', originator: 'test', timestamp: '2026-10-26T00:00:00.000Z', 'mime-type': 'application/json', key: 'key', payload: { id: 1 } };

test('bus normalizes endpoints and preserves event envelopes and keys', async () => {
  for (const suffix of ['/v6', '/v6/', '/v6/bus', '/v6/bus/', '/v6/bus/events']) assert.equal(resolveBusEventsUrl(`https://api.example${suffix}`), 'https://api.example/v6/bus/events');
  assert.throws(() => resolveBusEventsUrl('https://user:pass@api.example/v6'));
  assert.throws(() => resolveBusEventsUrl('http://api.example/v6'));
  const client = createBusApiClient({ BUSAPI_URL: 'https://api.example/v6', getToken: async () => 'token', fetch: async (url, request) => {
    assert.equal(url, 'https://api.example/v6/bus/events');
    assert.equal(request.headers.Authorization, 'Bearer token');
    assert.equal(request.redirect, 'error');
    assert.deepEqual(JSON.parse(request.body), event);
    return json({ accepted: true }, 202);
  } });
  assert.equal((await client.postEvent(event)).status, 202);
});

test('bus does not retry ambiguous publications or mutate envelopes', async () => {
  let calls = 0;
  const client = createBusApiClient({ BUSAPI_URL: 'https://api.example/v6', KAFKA_ERROR_TOPIC: 'errors', getToken: async () => 'token', fetch: async (_url, request) => {
    calls++;
    assert.equal(JSON.parse(request.body).topic, 'test.event');
    return json({ secret: 'sensitive' }, 503);
  } });
  await assert.rejects(client.postEvent(event), error => error.status === 503 && !error.message.includes('sensitive'));
  assert.equal(calls, 1);
  assert.equal(event.topic, 'test.event');
  await assert.rejects(client.postEvent({ ...event, timestamp: 'invalid' }), /envelope/);
});

test('purpose-bound proofs require expiry, exact audience and exact user binding', () => {
  const { verifySignedJwt } = require('../dist');
  const proof = jwt.sign({ userId: '42' }, secret, { audience: 'otp', expiresIn: 300 });
  assert.equal(verifySignedJwt(proof, secret, { audience: 'otp', userId: '42' }).userId, '42');
  assert.throws(() => verifySignedJwt(proof, secret, { audience: 'email', userId: '42' }));
  assert.throws(() => verifySignedJwt(proof, secret, { audience: 'otp', userId: '43' }));
  assert.throws(() => verifySignedJwt(jwt.sign({ userId: '42' }, secret, { audience: 'otp' }), secret, { audience: 'otp' }));
});

test('environment configuration disables RSA without a configured audience and rejects default HMAC secrets', async () => {
  const verifier = createJwtVerifier({ VALID_ISSUERS: [issuer], AUTH_SECRET: secret });
  assert.equal((await verifier.verify(sign())).sub, '42');
  assert.throws(() => createJwtVerifier({ VALID_ISSUERS: [issuer], AUTH_SECRET: 'mysecret' }), /32 bytes/);
  assert.throws(() => createJwtVerifier({ VALID_ISSUERS: [issuer] }), /issuer policy/);
});


test('legacy audience-free HMAC policy cannot authenticate machines, including namespaced grants', async () => {
  const verifier = createJwtVerifier({ VALID_ISSUERS: [issuer], AUTH_SECRET: secret });
  for (const claims of [{ gty: 'client-credentials' }, { 'https://topcoder.com/gty': 'client-credentials' }]) {
    await assert.rejects(verifier.verify(sign(claims)), /Invalid or expired/);
  }
});
