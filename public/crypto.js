// Shared, dependency-free Web Crypto implementation for browsers and Node.js.
export const MAX_BYTES = 32768;
const encoder = new TextEncoder();
export function toBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
export function fromBase64(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
export function encodeKey(bytes) {
  return toBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export function decodeKey(value) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('The link is missing a valid decryption key. Ask the sender for the complete link.');
  const bytes = fromBase64(value.replaceAll('-', '+').replaceAll('_', '/') + '=');
  if (encodeKey(bytes) !== value) throw new Error('The decryption key is invalid.');
  return bytes;
}
export function randomId() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
}
export function additionalData(id, envelope) {
  return encoder.encode(`happysecret:v1:${id}:${envelope.expiresAt}:${envelope.maxViews ?? 1}`);
}
export async function encryptSecret(text, { expiresAt, maxViews = 1 }, id = randomId()) {
  const plaintext = encoder.encode(text);
  if (!plaintext.length || plaintext.length > MAX_BYTES) throw new Error('Enter a secret of up to 32 KiB.');
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const envelope = { v: 1, algorithm: 'aes-256-gcm', nonce: toBase64(nonce), ciphertext: '', expiresAt, maxViews };
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128, additionalData: additionalData(id, envelope) }, key, plaintext);
  envelope.ciphertext = toBase64(new Uint8Array(ciphertext));
  return { id, key: encodeKey(rawKey), envelope };
}
export async function decryptSecret(id, encodedKey, envelope) {
  if (envelope.v !== 1 || envelope.algorithm !== 'aes-256-gcm') throw new Error('Unsupported encryption format.');
  const key = await crypto.subtle.importKey('raw', decodeKey(encodedKey), 'AES-GCM', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(envelope.nonce), tagLength: 128, additionalData: additionalData(id, envelope) }, key, fromBase64(envelope.ciphertext));
  return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
}
