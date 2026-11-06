const { test } = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const { createServer } = require('node:http');
const jwt = require('jsonwebtoken');
const { createJwtVerifier, createJwtAuthenticator, verifySignedJwt } = require('../dist');

const secret = 'lifetime-tests-only-not-a-production-secret';
const issuer = 'https://lifetime.example';
const day = 86400;

test('both JWT verifiers require expiry and cap the original lifetime at 24 hours', async t => {
  const now = Math.floor(Date.now() / 1000);
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'lifetime-key', alg: 'RS256', use: 'sig' };
  const server = createServer((_req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));

  const cases = [
    ['missing expiry', { iat: now }],
    ['missing issuance time', { exp: now + 300 }],
    ['missing both timestamps', {}],
    ['24 hours plus one second', { iat: now, exp: now + day + 1 }],
    ['long-lived token in its final hour', { iat: now - day, exp: now + 3600 }],
    ['expiry equals issuance time', { iat: now, exp: now }],
    ['expiry before issuance time', { iat: now, exp: now - 1 }],
    ['future issuance time', { iat: now + 120, exp: now + 300 }],
    ['expired token', { iat: now - 600, exp: now - 1 }],
  ];

  for (const algorithm of ['HS256', 'RS256']) {
    const key = algorithm === 'HS256' ? secret : privateKey;
    const verificationKey = algorithm === 'HS256' ? secret : publicKey;
    const sign = claims => jwt.sign({ sub: 'allowed', email_verified: true, ...claims }, key, {
      algorithm, issuer, audience: 'purpose', keyid: 'lifetime-key',
      noTimestamp: !Object.hasOwn(claims, 'iat'),
    });
    const policy = algorithm === 'HS256'
      ? { issuer, algorithm, secret, audience: 'purpose', legacyHs256Until: new Date((now + day) * 1000).toISOString() }
      : { issuer, algorithm, audience: 'purpose', jwksUri: `http://127.0.0.1:${server.address().port}/keys` };
    const verifier = createJwtVerifier({ issuers: [policy], clockTolerance: 0 });
    for (const [name, verify] of [
      ['access token', token => verifier.verify(token)],
      ['purpose-bound proof', token => verifySignedJwt(token, verificationKey, { audience: 'purpose', issuer, algorithms: [algorithm] })],
    ]) {
      await t.test(`${algorithm} ${name}`, async () => {
        for (const lifetime of [300, day]) {
          assert.equal((await verify(sign({ iat: now, exp: now + lifetime }))).sub, 'allowed');
        }
        for (const [description, claims] of cases) {
          await assert.rejects(async () => verify(sign(claims)), undefined, description);
        }
      });
    }
  }
});

test('HTTP middleware returns 401 for missing expiry and excessive lifetime', async () => {
  const now = Math.floor(Date.now() / 1000);
  const authenticate = createJwtAuthenticator({ issuers: [{
    issuer, algorithm: 'HS256', secret, audience: 'api',
    legacyHs256Until: new Date((now + day) * 1000).toISOString(),
  }] });
  for (const claims of [{ iat: now }, { iat: now, exp: now + day + 1 }]) {
    const token = jwt.sign({ email_verified: true, ...claims }, secret, { issuer, audience: 'api' });
    const request = { headers: { authorization: `Bearer ${token}` } };
    await new Promise((resolve, reject) => {
      const response = {
        status(code) { assert.equal(code, 401); return response; },
        json(body) { assert.equal(body.result.status, 401); assert.equal(request.authUser, undefined); resolve(); },
      };
      authenticate(request, response, () => reject(new Error('must not authorize')));
    });
  }
});
