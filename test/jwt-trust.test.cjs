const { test } = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const { createJwtVerifier, verifySignedJwt } = require('../dist');
const issuer = 'https://api.example';
const secret = 'only-a-test-secret-at-least-thirty-two-bytes';
const deadline = () => new Date(Date.now() + 60000).toISOString();
const legacy = (extra = {}) => ({ issuer, algorithm: 'HS256', secret, audience: 'api', legacyHs256Until: deadline(), ...extra });
const sign = (payload = {}, options = {}) => jwt.sign({ sub: 'user', ...payload }, secret, { issuer, audience: 'api', expiresIn: 300, ...options });

test('knowing AUTH_SECRET cannot authenticate an access token under default trust', async () => {
  const verifier = createJwtVerifier({ VALID_ISSUERS: [issuer], AUTH_SECRET: secret, AUTH0_AUDIENCE: 'api' });
  await assert.rejects(verifier.verify(sign({ userId: '42', roles: ['Administrator'] })), /Invalid or expired/);
});

test('one issuer cannot simultaneously trust asymmetric and symmetric signatures', () => {
  assert.throws(() => createJwtVerifier({ issuers: [legacy(), { issuer, algorithm: 'RS256', audience: 'api' }] }), /one algorithm per issuer/);
});

test('RS256 never permits missing audiences, even with a legacy compatibility flag', () => {
  assert.throws(() => createJwtVerifier({ issuers: [{ issuer, algorithm: 'RS256', allowMissingAudience: true }] }), /audience/);
});

test('legacy HMAC requires a valid explicit retirement deadline', () => {
  for (const value of [undefined, '', 'not-a-date', '2099-01-01', new Date(Date.now() - 1000).toISOString()]) {
    assert.throws(() => createJwtVerifier({ issuers: [legacy({ legacyHs256Until: value })] }), /retirement deadline/);
  }
  assert.throws(() => createJwtVerifier({ VALID_ISSUERS: [issuer], AUTH_SECRET: secret, LEGACY_HS256_ISSUERS: ['https://untrusted.example'], LEGACY_HS256_ACCEPT_UNTIL: deadline() }), /explicitly trusted/);
});

test('a running verifier stops trusting HMAC at its retirement deadline', async (t) => {
  const now = Date.now();
  const policy = legacy({ legacyHs256Until: new Date(now + 10000).toISOString() });
  const verifier = createJwtVerifier({ issuers: [policy] });
  const token = sign();
  assert.equal((await verifier.verify(token)).sub, 'user');
  t.mock.method(Date, 'now', () => now + 10000);
  await assert.rejects(verifier.verify(token), /Invalid or expired/);
});

test('access tokens require issuance time, bounded lifetime and consistent expiry', async () => {
  const verifier = createJwtVerifier({ issuers: [legacy()], maxTokenLifetimeSeconds: 300, clockTolerance: 0 });
  await verifier.verify(sign());
  for (const token of [sign({}, { noTimestamp: true }), sign({}, { expiresIn: 301 }), sign({ iat: Math.floor(Date.now() / 1000) - 400 }, { expiresIn: 500 })]) {
    await assert.rejects(verifier.verify(token), /Invalid or expired/);
  }
  for (const maxTokenLifetimeSeconds of [0, -1, 86401, Infinity, NaN, 1.5]) {
    assert.throws(() => createJwtVerifier({ issuers: [legacy()], maxTokenLifetimeSeconds }), /lifetime/);
  }
});

test('a purpose-bound HMAC proof is not an API access token', async () => {
  const token = sign({ userId: '42' }, { audience: 'email-change' });
  assert.equal(verifySignedJwt(token, secret, { audience: 'email-change', userId: '42' }).userId, '42');
  const verifier = createJwtVerifier({ VALID_ISSUERS: [issuer], AUTH_SECRET: secret, AUTH0_AUDIENCE: 'api' });
  await assert.rejects(verifier.verify(token), /Invalid or expired/);
});

test('JSON policies select public trust without accepting embedded secrets', async () => {
  const verifier = createJwtVerifier({ JWT_ISSUER_POLICIES: JSON.stringify([{ issuer, algorithm: 'RS256', audience: 'api', jwksUri: 'https://keys.example/jwks' }]), AUTH_SECRET: secret });
  await assert.rejects(verifier.verify(sign()), /Invalid or expired/);
  for (const policies of ['not-json', '{}', '[]', JSON.stringify([null]), JSON.stringify([legacy()])]) {
    assert.throws(() => createJwtVerifier({ JWT_ISSUER_POLICIES: policies }), /JWT_ISSUER_POLICIES/);
  }
});
