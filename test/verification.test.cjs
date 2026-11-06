const { test } = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const { createServer } = require('node:http');
const jwt = require('jsonwebtoken');
const { createJwtVerifier, createJwtAuthenticator } = require('../dist');
const issuer = 'https://verification.example/';
const secret = 'verification-test-secret-at-least-32-characters';
const invalid = [undefined, false, 'true', 'false', 1, 0, null, [], {}];

test('human email verification is mandatory for HS256 and RS256; machine grants remain valid', async t => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const server = createServer((_req, res) => res.end(JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'test', alg: 'RS256', use: 'sig' }] })));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  for (const algorithm of ['HS256', 'RS256']) {
    const config = { issuers: [{ issuer, algorithm, audience: 'api', secret, legacyHs256Until: new Date(Date.now() + 86400000).toISOString(), jwksUri: `http://127.0.0.1:${server.address().port}/keys` }] };
    const verifier = createJwtVerifier(config);
    const sign = claims => jwt.sign(claims, algorithm === 'HS256' ? secret : privateKey, { algorithm, issuer, audience: 'api', expiresIn: 300, keyid: 'test' });
    for (const value of invalid) await assert.rejects(verifier.verify(sign({ userId: 42, email_verified: value })));
    for (const name of ['email_verified', 'emailVerified', 'emailActive', 'https://topcoder.com/emailVerified', 'https://api.topcoder-dev.com/v6/email_verified']) {
      assert.equal((await verifier.verify(sign({ userId: 42, [name]: true }))).userId, 42);
    }
    for (const claims of [
      { userId: 42, 'https://attacker.example/email_verified': true },
      { userId: 42, email_verified: false, emailVerified: true },
      { userId: 42, isMachine: true },
      { userId: 42, gty: 'client-credentials' },
      { userId: 42, roles: ['Administrator'], scope: 'all:things' },
    ]) await assert.rejects(verifier.verify(sign(claims)));
    assert.equal((await verifier.verify(sign({ sub: 'client@clients', gty: 'client-credentials', scope: 'read:things' }))).isMachine, true);
    await new Promise((resolve, reject) => {
      const req = { headers: { authorization: `Bearer ${sign({ userId: 42 })}` } };
      const res = { status(code) { assert.equal(code, 401); return res; }, json() { assert.equal(req.authUser, undefined); resolve(); } };
      createJwtAuthenticator(config)(req, res, () => reject(new Error('unverified request authorized')));
    });
  }
});
