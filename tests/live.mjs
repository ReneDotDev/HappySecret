import assert from 'node:assert/strict';
import { encryptSecret, decryptSecret, randomId } from '../public/crypto.js';

const origin = process.argv[2];
if (!origin?.startsWith('https://')) throw new Error('Pass the deployed HTTPS origin. Uses only generated test values.');
const endpoint = id => `${origin}/api/v1/secrets/${id}`;
async function create({ maxViews = 1, ttl = 60000 } = {}) {
  const secret = await encryptSecret(`HappySecret live test ${randomId()}`, { expiresAt: new Date(Date.now() + ttl).toISOString(), maxViews });
  const response = await fetch(endpoint(secret.id), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(secret.envelope) });
  assert.equal(response.status, 201, await response.text());
  return secret;
}
const consume = id => fetch(`${endpoint(id)}/consume`, { method: 'POST' });

for (const path of ['/', '/api', '/api/', '/security', '/llms.txt', '/llm.txt', '/crypto.js', '/app.js', '/style.css', '/happysecret.mjs']) {
  const response = await fetch(origin + path);
  assert.equal(response.status, 200, path);
  assert.match(response.headers.get('cache-control'), /no-store/);
  assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/);
}
assert.equal(await (await fetch(origin + '/llms.txt')).text(), await (await fetch(origin + '/llm.txt')).text());
console.log('PASS public website, docs, CLI, agent discovery, and security headers');

const one = await create();
assert.equal((await fetch(`${origin}/s/${one.id}`)).status, 200);
assert.equal((await fetch(`${origin}/s/${one.id}`, { method: 'HEAD' })).status, 200);
assert.equal((await fetch(endpoint(one.id))).status, 405);
assert.equal((await fetch(endpoint(one.id) + '/consume')).status, 405);
const first = await consume(one.id);
assert.equal(first.status, 200);
const envelope = await first.json();
await decryptSecret(one.id, one.key, envelope);
assert.equal(envelope.remainingViews, 0);
assert.equal((await consume(one.id)).status, 410);
console.log('PASS explicit reveal, successful decryption, and one-time deletion');

const single = await create();
const simultaneous = await Promise.all(Array.from({ length: 20 }, () => consume(single.id)));
assert.equal(simultaneous.filter(r => r.status === 200).length, 1);
assert.equal(simultaneous.filter(r => r.status === 410).length, 19);
console.log('PASS 20 simultaneous consumes release a one-time secret exactly once');

const multi = await create({ maxViews: 3 });
const many = await Promise.all(Array.from({ length: 10 }, () => consume(multi.id)));
const successful = many.filter(r => r.status === 200);
assert.equal(successful.length, 3);
assert.equal(many.filter(r => r.status === 410).length, 7);
const remaining = await Promise.all(successful.map(async r => (await r.json()).remainingViews));
assert.deepEqual(remaining.sort(), [0, 1, 2]);
console.log('PASS multi-view counter is atomic under concurrent requests');

const expires = await create({ ttl: 2500 });
await new Promise(resolve => setTimeout(resolve, 3200));
assert.equal((await consume(expires.id)).status, 410);
console.log('PASS expiration prevents retrieval');

const put = (id, body, headers = {}) => fetch(endpoint(id), { method: 'PUT', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
assert.equal((await put(single.id, single.envelope)).status, 409);
assert.equal((await put(randomId(), { ...one.envelope, plaintext: 'must never be accepted' })).status, 400);
assert.equal((await put(randomId(), { ...one.envelope, maxViews: 101 })).status, 400);
assert.equal((await put(randomId(), { ...one.envelope, expiresAt: new Date(Date.now() - 1000).toISOString() })).status, 400);
assert.equal((await put(randomId(), one.envelope, { Origin: 'https://untrusted.example' })).status, 403);
assert.equal((await put(randomId(), { ciphertext: 'x'.repeat(70000) })).status, 400);
console.log('PASS overwrite prevention, schema and size validation, expiry validation, cross-origin protection');

const defaults = await encryptSecret('default views', { expiresAt: new Date(Date.now() + 15000).toISOString() });
delete defaults.envelope.maxViews;
assert.equal((await put(defaults.id, defaults.envelope)).status, 201);
const defaultResponse = await (await consume(defaults.id)).json();
assert.equal(defaultResponse.maxViews, 1);
assert.equal(await decryptSecret(defaults.id, defaults.key, defaultResponse), 'default views');
assert.equal((await consume(defaults.id)).status, 410);
console.log('PASS API defaults to one authenticated view');
console.log('All live checks passed. Test secrets have been consumed or expired.');
