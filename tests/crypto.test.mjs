import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDecipheriv, createCipheriv, randomBytes } from 'node:crypto';
import { encryptSecret, decryptSecret, additionalData, fromBase64, encodeKey, decodeKey } from '../public/crypto.js';
import { validEnvelope } from '../src/protocol.js';

const options = () => ({ expiresAt: new Date(Date.now() + 3600000).toISOString(), maxViews: 1 });

test('Web Crypto ciphertext interoperates with the independent Node OpenSSL cipher interface', async () => {
  const text = 'A private note 🔐\n日本語\n<not html>\u0000';
  const { id, key, envelope } = await encryptSecret(text, options());
  const packed = fromBase64(envelope.ciphertext);
  const decipher = createDecipheriv('aes-256-gcm', decodeKey(key), fromBase64(envelope.nonce));
  decipher.setAAD(additionalData(id, envelope));
  decipher.setAuthTag(packed.slice(-16));
  const plaintext = Buffer.concat([decipher.update(packed.slice(0, -16)), decipher.final()]);
  assert.equal(plaintext.toString('utf8'), text);
  assert.equal(await decryptSecret(id, key, envelope), text);
  assert.equal(validEnvelope(envelope), true);
  assert.equal(JSON.stringify(envelope).includes(text), false);
});

test('independently generated ciphertext decrypts through the browser module', async () => {
  const id = randomBytes(32).toString('hex');
  const rawKey = randomBytes(32);
  const nonce = randomBytes(12);
  const envelope = { v: 1, algorithm: 'aes-256-gcm', nonce: nonce.toString('base64'), ...options() };
  const cipher = createCipheriv('aes-256-gcm', rawKey, nonce);
  cipher.setAAD(additionalData(id, envelope));
  envelope.ciphertext = Buffer.concat([cipher.update('independent producer'), cipher.final(), cipher.getAuthTag()]).toString('base64');
  assert.equal(await decryptSecret(id, encodeKey(rawKey), envelope), 'independent producer');
});

test('wrong keys, modified metadata, changed IDs, and altered ciphertext fail authentication', async () => {
  const { id, key, envelope } = await encryptSecret('integrity matters', options());
  await assert.rejects(decryptSecret(id, encodeKey(randomBytes(32)), envelope));
  await assert.rejects(decryptSecret(randomBytes(32).toString('hex'), key, envelope));
  await assert.rejects(decryptSecret(id, key, { ...envelope, maxViews: 2 }));
  await assert.rejects(decryptSecret(id, key, { ...envelope, expiresAt: new Date(Date.now() + 7200000).toISOString() }));
  const bytes = fromBase64(envelope.ciphertext);
  bytes[0] ^= 1;
  await assert.rejects(decryptSecret(id, key, { ...envelope, ciphertext: Buffer.from(bytes).toString('base64') }));
});

test('plaintext size limit counts UTF-8 bytes and accepts the boundary', async () => {
  await assert.rejects(encryptSecret('', options()));
  await assert.rejects(encryptSecret('🔐'.repeat(8193), options()));
  const { id, key, envelope } = await encryptSecret('a'.repeat(32768), options());
  assert.equal(validEnvelope(envelope), true);
  assert.equal((await decryptSecret(id, key, envelope)).length, 32768);
});

test('envelope rejects leaked fields and invalid formats; supports default view count', async () => {
  const { envelope } = await encryptSecret('test', options());
  const { maxViews, ...defaultViews } = envelope;
  assert.equal(validEnvelope(defaultViews), true);
  for (const change of [
    { key: 'must not upload' }, { plaintext: 'must not upload' }, { algorithm: 'aes-256-cbc' },
    { maxViews: 0 }, { maxViews: 101 }, { maxViews: 1.5 }, { maxViews: '1' }, { maxViews: null },
    { nonce: 'AAAAAAAAAAAAAAAAA===' }, { ciphertext: '' },
    { expiresAt: 'yesterday' }, { expiresAt: new Date(Date.now() - 1000).toISOString() },
    { expiresAt: new Date(Date.now() + 8 * 86400000).toISOString() },
    { expiresAt: envelope.expiresAt.replace('.000Z', 'Z').replace('Z', '+00:00') },
  ]) assert.equal(validEnvelope({ ...envelope, ...change }), false, JSON.stringify(change));
});

test('rejects malformed or noncanonical fragment keys', () => {
  assert.throws(() => decodeKey('missing'));
  const key = encodeKey(randomBytes(32));
  assert.equal(encodeKey(decodeKey(key)), key);
  assert.throws(() => decodeKey(key + '='));
});
