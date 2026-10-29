const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const Bluebird = require('bluebird');
const { createM2MClient, createBusApiClient } = require('../dist');
const { postJson } = require('../dist/http');

/** Starts an isolated loopback HTTP server for a test and closes its connections afterward.
 * @param t Node test context. @param handler Request handler used by the test.
 * @returns The server's base URL. @throws Propagates server startup failures.
 */
async function listen(t, handler) {
  const server = createServer(handler);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise(resolve => {
    server.close(resolve);
    server.closeAllConnections();
  }));
  return `http://127.0.0.1:${server.address().port}`;
}

test('M2M and bus requests work when the host replaces global Promise with Bluebird', async (t) => {
  const requests = [];
  const url = await listen(t, (req, res) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      requests.push({ path: req.url, method: req.method, headers: req.headers, body: JSON.parse(body) });
      res.setHeader('Content-Type', 'application/json');
      if (req.url === '/token') res.end(JSON.stringify({ access_token: 'test-token', expires_in: 3600 }));
      else { res.statusCode = 202; res.end(JSON.stringify({ accepted: true })); }
    });
  });
  const nativePromise = globalThis.Promise;
  globalThis.Promise = Bluebird;
  try {
    assert.equal(typeof globalThis.Promise.withResolvers, 'undefined');
    const client = createM2MClient({ AUTH0_URL: `${url}/token`, AUTH0_AUDIENCE: 'api' });
    const tokens = await Bluebird.all([client.getMachineToken('client', 'secret'), client.getMachineToken('client', 'secret')]);
    assert.deepEqual(tokens, ['test-token', 'test-token']);
    const bus = createBusApiClient({ BUSAPI_URL: `${url}/v6`, getToken: () => client.getMachineToken('client', 'secret') });
    const event = { topic: 'test.event', originator: 'test', timestamp: '2026-10-29T00:00:00.000Z', 'mime-type': 'application/json', key: 'key', payload: { id: 1 } };
    assert.deepEqual(await bus.postEvent(event), { status: 202, body: { accepted: true } });
    assert.equal(requests.length, 2);
    assert.equal(requests[0].path, '/token');
    assert.equal(requests[0].method, 'POST');
    assert.equal(requests[0].headers['content-type'], 'application/json');
    assert.deepEqual(requests[0].body, { grant_type: 'client_credentials', client_id: 'client', client_secret: 'secret', audience: 'api' });
    assert.equal(requests[1].path, '/v6/bus/events');
    assert.equal(requests[1].headers.authorization, 'Bearer test-token');
    assert.deepEqual(requests[1].body, event);
    assert.equal(globalThis.Promise, Bluebird);
    assert.equal(typeof globalThis.Promise.withResolvers, 'undefined');
  } finally {
    globalThis.Promise = nativePromise;
  }
});

test('default transport rejects redirects and HTTP failures without retrying or disclosing response bodies', async (t) => {
  let requests = 0;
  const url = await listen(t, (req, res) => {
    requests++;
    res.statusCode = req.url === '/redirect' ? 302 : 503;
    res.setHeader('Location', '/target');
    res.end('sensitive-response');
  });
  for (const path of ['/redirect', '/failure']) {
    await assert.rejects(postJson(`${url}${path}`, { secret: 'sensitive-request' }, {}), error =>
      error.name === 'HttpError' && !error.message.includes('sensitive'));
  }
  assert.equal(requests, 2);
});

test('default transport bounds responses and sanitizes malformed JSON and truncated connections', async (t) => {
  const url = await listen(t, (req, res) => {
    if (req.url === '/oversized') res.end('x'.repeat(1024 * 1024 + 1));
    else if (req.url === '/truncated') {
      res.writeHead(200, { 'Content-Length': 100 });
      res.write('{');
      res.socket.destroy();
    } else res.end('sensitive-malformed-json');
  });
  await assert.rejects(postJson(`${url}/oversized`, {}, {}), /Response too large/);
  for (const path of ['/malformed', '/truncated']) {
    await assert.rejects(postJson(`${url}${path}`, {}, {}), { name: 'HttpError', message: 'Request failed or timed out' });
  }
});

test('default transport applies deadlines to headers and response bodies and honors caller cancellation', async (t) => {
  const url = await listen(t, (req, res) => {
    if (req.url === '/body') { res.writeHead(200); res.write('{'); }
  });
  for (const path of ['/headers', '/body']) {
    await assert.rejects(postJson(`${url}${path}`, {}, { timeoutMs: 50 }), { name: 'HttpError', message: 'Request failed or timed out' });
  }
  const controller = new globalThis.AbortController();
  controller.abort();
  await assert.rejects(postJson(url, {}, {}, undefined, controller.signal), { name: 'HttpError', message: 'Request failed or timed out' });
});

test('default transport accepts empty successful responses and counts UTF-8 request bytes', async (t) => {
  let requestBytes = 0;
  let declaredBytes;
  const url = await listen(t, (req, res) => {
    declaredBytes = Number(req.headers['content-length']);
    req.on('data', chunk => { requestBytes += chunk.length; });
    req.on('end', () => { res.statusCode = 204; res.end(); });
  });
  const body = { name: 'café ☕' };
  assert.deepEqual(await postJson(url, body, {}), { status: 204, body: undefined });
  assert.equal(requestBytes, Buffer.byteLength(JSON.stringify(body)));
  assert.equal(declaredBytes, requestBytes);
});
