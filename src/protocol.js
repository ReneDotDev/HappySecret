export const ALGORITHM = 'aes-256-gcm';
export const MAX_TTL = 7 * 24 * 60 * 60 * 1000;
export const MAX_BODY = 65536;
export const ID_PATTERN = /^[a-f0-9]{64}$/;
export function validEnvelope(body, now = Date.now()) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false;
  if (Object.keys(body).some(k => !['v', 'algorithm', 'nonce', 'ciphertext', 'expiresAt', 'maxViews'].includes(k))) return false;
  const base64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  if (body.v !== 1 || body.algorithm !== ALGORITHM) return false;
  if (typeof body.nonce !== 'string' || body.nonce.length !== 16 || !base64.test(body.nonce) || atob(body.nonce).length !== 12) return false;
  if (typeof body.ciphertext !== 'string' || body.ciphertext.length > 44000 || !base64.test(body.ciphertext)) return false;
  const length = atob(body.ciphertext).length;
  if (length < 17 || length > 32784) return false;
  const views = body.maxViews === undefined ? 1 : body.maxViews;
  if (!Number.isInteger(views) || views < 1 || views > 100) return false;
  if (typeof body.expiresAt !== 'string') return false;
  const expiry = Date.parse(body.expiresAt);
  return Number.isFinite(expiry) && new Date(expiry).toISOString() === body.expiresAt && expiry > now && expiry <= now + MAX_TTL;
}
