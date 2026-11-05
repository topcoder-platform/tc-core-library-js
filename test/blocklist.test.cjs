const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const { createServer } = require('node:http');
const { env } = require('node:process');
const jwt = require('jsonwebtoken');
const { createJwtVerifier, createJwtAuthenticator, verifySignedJwt } = require('../dist');

const subjectKey = 'ACCESS_CONTROL_BLOCKED_SUBJECTS';
const userIdKey = 'ACCESS_CONTROL_BLOCKED_USER_IDS';
const secret = 'blocklist-test-secret-at-least-32-bytes';
const issuer = 'https://blocklist.example/';
const config = { issuers: [{ issuer, algorithm: 'HS256', secret, audience: 'api' }], clockTolerance: 0 };
const sign = (claims = {}, options = {}) => jwt.sign({ email_verified: true, ...claims }, secret, { issuer, audience: 'api', expiresIn: 300, ...options });
const invalid = { message: 'Invalid or expired access token' };
let original;

beforeEach(() => {
  original = { [subjectKey]: env[subjectKey], [userIdKey]: env[userIdKey] };
  delete env[subjectKey];
  delete env[userIdKey];
});
afterEach(() => {
  for (const key of [subjectKey, userIdKey]) {
    if (original[key] === undefined) delete env[key];
    else env[key] = original[key];
  }
});

test('automatically blocks subjects with explicit policies, including admins and machines', async () => {
  env[subjectKey] = ' auth0|blocked, , service@clients,auth0|blocked ';
  const verifier = createJwtVerifier(config);
  for (const claims of [
    { sub: 'auth0|blocked' },
    { sub: 'auth0|blocked', roles: ['Administrator'], userId: '123' },
    { sub: 'service@clients', gty: 'client-credentials', scope: 'admin:all' },
  ]) await assert.rejects(verifier.verify(sign(claims)), invalid);
  assert.equal((await verifier.verify(sign({ sub: 'auth0|allowed' }))).sub, 'auth0|allowed');
});

test('environment-style JWT configuration uses the same automatic blocks', async () => {
  env[subjectKey] = 'auth0|blocked';
  env[userIdKey] = '123';
  const verifier = createJwtVerifier({ VALID_ISSUERS: [issuer], AUTH_SECRET: secret });
  await assert.rejects(verifier.verify(sign({ sub: 'auth0|blocked' })), invalid);
  await assert.rejects(verifier.verify(sign({ userId: '123' })), invalid);
  assert.equal((await verifier.verify(sign({ userId: '456' }))).userId, '456');
});

test('subject matching is exact and case sensitive, with no fallback to id or userId', async () => {
  env[subjectKey] = 'auth0|blocked,123';
  const verifier = createJwtVerifier(config);
  for (const claims of [
    { sub: 'auth0|blocked-extra' }, { sub: 'AUTH0|blocked' }, { sub: 'auth0|block' },
    { sub: 'auth0|allowed', id: 'auth0|blocked' }, { userId: 123 },
  ]) await verifier.verify(sign(claims));
  await assert.rejects(verifier.verify(sign({ sub: '123' })), invalid);
});

test('blocks numeric, string and namespaced user IDs, including legacy tokens without sub', async () => {
  env[userIdKey] = ' 123, ,456,9223372036854775807,123 ';
  const verifier = createJwtVerifier(config);
  for (const claims of [
    { userId: 123 }, { userId: '123' }, { 'https://topcoder.com/userId': '456' },
    { 'https://api.topcoder.com/v6/userId': 123 },
    { sub: 'different-subject', userId: '123', roles: ['Administrator'] },
    { userId: '9223372036854775807' },
  ]) await assert.rejects(verifier.verify(sign(claims)), invalid);
  assert.equal((await verifier.verify(sign({ userId: '9223372036854775806' }))).userId, '9223372036854775806');
  // Never derive a human ID from an Auth0 subject suffix or an arbitrary claim.
  await verifier.verify(sign({ sub: 'auth0|123' }));
  await verifier.verify(sign({ sub: 'allowed', id: '123', 'https://attacker.example/userId': '123' }));
});

test('user ID blocking honors explicitly trusted claim namespaces', async () => {
  env[userIdKey] = '123';
  const verifier = createJwtVerifier({ ...config, claimNamespaces: ['https://trusted.example/'] });
  await assert.rejects(verifier.verify(sign({ 'https://trusted.example/userId': '123' })), invalid);
  await verifier.verify(sign({ 'https://other.example/userId': '123' }));
});

test('either denylist rejects, while absent or empty lists preserve existing behavior', async () => {
  for (const value of [undefined, '', ' ,  , ']) {
    for (const key of [subjectKey, userIdKey]) {
      if (value === undefined) delete env[key]; else env[key] = value;
    }
    await createJwtVerifier(config).verify(sign({ sub: 'auth0|blocked', userId: '123' }));
  }
  env[subjectKey] = 'auth0|blocked';
  env[userIdKey] = '123';
  const verifier = createJwtVerifier(config);
  await assert.rejects(verifier.verify(sign({ sub: 'auth0|blocked', userId: '456' })), invalid);
  await assert.rejects(verifier.verify(sign({ sub: 'auth0|allowed', userId: '123' })), invalid);
});

test('local configuration extends global lists and cannot clear them', async () => {
  env[subjectKey] = 'global-subject';
  env[userIdKey] = '123';
  for (const value of ['', [], undefined]) {
    const verifier = createJwtVerifier({ ...config, [subjectKey]: value, [userIdKey]: value });
    await assert.rejects(verifier.verify(sign({ sub: 'global-subject' })), invalid);
    await assert.rejects(verifier.verify(sign({ userId: 123 })), invalid);
  }
  const verifier = createJwtVerifier({ ...config, [subjectKey]: [' local-subject ', ''], [userIdKey]: '456,789' });
  for (const claims of [{ sub: 'global-subject' }, { sub: 'local-subject' }, { userId: 123 }, { userId: '456' }, { userId: 789 }]) {
    await assert.rejects(verifier.verify(sign(claims)), invalid);
  }
  await verifier.verify(sign({ sub: 'allowed', userId: 1000 }));
});

test('each verifier snapshots environment and configuration lists', async () => {
  env[subjectKey] = 'global-subject';
  const subjects = ['local-subject'];
  const verifier = createJwtVerifier({ ...config, [subjectKey]: subjects });
  env[subjectKey] = 'new-subject';
  subjects.length = 0;
  await assert.rejects(verifier.verify(sign({ sub: 'global-subject' })), invalid);
  await assert.rejects(verifier.verify(sign({ sub: 'local-subject' })), invalid);
  await verifier.verify(sign({ sub: 'new-subject' }));
  await assert.rejects(createJwtVerifier(config).verify(sign({ sub: 'new-subject' })), invalid);
});

test('invalid denylist configuration fails at construction without revealing entries', () => {
  for (const key of [subjectKey, userIdKey]) {
    for (const value of [null, 123, {}, [123], ['valid', false]]) {
      assert.throws(() => createJwtVerifier({ ...config, [key]: value }), /Invalid ACCESS_CONTROL_BLOCKED_/);
    }
  }
  for (const id of ['0', '-1', '01', '1.5', '1e3', 'auth0|123', '9223372036854775808']) {
    env[userIdKey] = id;
    assert.throws(() => createJwtVerifier(config), { message: `Invalid ${userIdKey}: entries must be positive decimal user IDs` });
  }
});

test('RS256 blocks verified subjects and user IDs with cached JWKS', async (t) => {
  env[subjectKey] = 'auth0|blocked';
  env[userIdKey] = '123';
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'key-1', alg: 'RS256', use: 'sig' };
  let requests = 0;
  const server = createServer((_req, res) => {
    requests++;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const verifier = createJwtVerifier({ issuers: [{ issuer, algorithm: 'RS256', audience: 'api', jwksUri: `http://127.0.0.1:${server.address().port}/keys` }] });
  const rsaSign = claims => jwt.sign({ email_verified: true, ...claims }, privateKey, { algorithm: 'RS256', keyid: 'key-1', issuer, audience: 'api', expiresIn: 300 });
  await assert.rejects(verifier.verify(rsaSign({ sub: 'auth0|blocked' })), invalid);
  await assert.rejects(verifier.verify(rsaSign({ userId: '123' })), invalid);
  assert.equal((await verifier.verify(rsaSign({ sub: 'allowed' }))).sub, 'allowed');
  assert.equal(requests, 1);
});

test('an allowed identity still requires a valid signature, audience and lifetime', async () => {
  env[subjectKey] = 'blocked';
  const verifier = createJwtVerifier(config);
  const tampered = sign({ sub: 'allowed' }).split('.');
  tampered[2] = `${tampered[2][0] === 'a' ? 'b' : 'a'}${tampered[2].slice(1)}`;
  for (const token of [tampered.join('.'), sign({ sub: 'allowed' }, { audience: 'wrong' }), sign({ sub: 'allowed' }, { expiresIn: -1 })]) {
    await assert.rejects(verifier.verify(token), invalid);
  }
});

test('middleware rejects blocked subjects and legacy user IDs with 401, without authenticating the request', async () => {
  env[subjectKey] = 'blocked';
  env[userIdKey] = '123';
  const authenticate = createJwtAuthenticator(config);
  for (const claims of [{ sub: 'blocked' }, { userId: 123 }]) {
    const request = { headers: { authorization: `Bearer ${sign(claims)}` } };
    await new Promise((resolve, reject) => {
      const response = {
        status(code) { assert.equal(code, 401); return response; },
        json(body) {
          assert.equal(body.message, invalid.message);
          assert.equal(body.result.status, 401);
          assert.equal(request.authUser, undefined);
          resolve();
        },
      };
      authenticate(request, response, () => reject(new Error('must not call next')));
    });
  }
  const request = { headers: { authorization: `Bearer ${sign({ sub: 'allowed' })}` } };
  await new Promise((resolve, reject) => {
    authenticate(request, { status() { reject(new Error('allowed identity rejected')); return {}; } }, resolve);
  });
  assert.equal(request.authUser.sub, 'allowed');
});

test('purpose-bound identity proofs retain their separate contract', () => {
  env[subjectKey] = 'blocked';
  env[userIdKey] = '123';
  const proof = jwt.sign({ sub: 'blocked', userId: '123' }, secret, { audience: 'otp', expiresIn: 300 });
  assert.equal(verifySignedJwt(proof, secret, { audience: 'otp', userId: '123' }).userId, '123');
});
