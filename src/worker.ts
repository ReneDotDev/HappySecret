import { DurableObject } from 'cloudflare:workers';
import { ID_PATTERN, MAX_BODY, MAX_TTL, validEnvelope } from './protocol.js';

interface Env { ASSETS: Fetcher; SECRETS: DurableObjectNamespace<Secret>; CREATE_LIMIT: RateLimit }
interface Envelope { v: number; algorithm: string; nonce: string; ciphertext: string; expiresAt: string; maxViews: number }
interface Record extends Envelope { remainingViews: number }
const security = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'Strict-Transport-Security': 'max-age=31536000',
};
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...security, 'Content-Type': 'application/json' } });
}
async function readBody(request: Request): Promise<unknown> {
  if (request.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json') throw new Error('Use application/json.');
  if (Number(request.headers.get('content-length')) > MAX_BODY) throw new Error('Payload is too large.');
  const reader = request.body?.getReader();
  if (!reader) throw new Error('Missing payload.');
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY) { await reader.cancel(); throw new Error('Payload is too large.'); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder().decode(bytes));
}

export class Secret extends DurableObject<Env> {
  async fetch(request: Request) {
    if (request.method === 'PUT') {
      const body = await request.json();
      if (!validEnvelope(body)) return json({ error: 'Invalid encrypted envelope.' }, 400);
      const envelope = { ...(body as Envelope), maxViews: (body as Envelope).maxViews ?? 1 };
      const created = await this.ctx.storage.transaction(async storage => {
        if (await storage.get('used')) return false;
        await storage.put('used', true);
        await storage.put('secret', { ...envelope, remainingViews: envelope.maxViews });
        await storage.setAlarm(Date.parse(envelope.expiresAt));
        return true;
      });
      return created ? json({ created: true }, 201) : json({ error: 'This ID is already used. Generate a fresh random ID.' }, 409);
    }
    if (request.method === 'POST') {
      const record = await this.ctx.storage.transaction(async storage => {
        const secret = await storage.get<Record>('secret');
        if (!secret) return null;
        if (Date.parse(secret.expiresAt) <= Date.now()) { await storage.delete('secret'); return null; }
        const remainingViews = secret.remainingViews - 1;
        if (remainingViews === 0) await storage.delete('secret');
        else await storage.put('secret', { ...secret, remainingViews });
        return { ...secret, remainingViews };
      });
      return record ? json(record) : json({ error: 'This secret is unavailable. It may have expired or reached its view limit.' }, 410);
    }
    return json({ error: 'Method not allowed.' }, 405);
  }
  async alarm() {
    // First alarm removes ciphertext; a second clears the temporary collision tombstone.
    if (await this.ctx.storage.get('cleanup')) { await this.ctx.storage.deleteAll(); return; }
    await this.ctx.storage.delete('secret');
    await this.ctx.storage.put('cleanup', true);
    await this.ctx.storage.setAlarm(Date.now() + MAX_TTL);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/') && url.pathname !== '/api/') {
      if (request.headers.get('origin') && request.headers.get('origin') !== url.origin) return json({ error: 'Cross-origin requests are not supported.' }, 403);
      const match = /^\/api\/v1\/secrets\/([a-f0-9]{64})(\/consume)?$/.exec(url.pathname);
      if (!match || !ID_PATTERN.test(match[1])) return json({ error: 'Unknown endpoint.' }, 404);
      const creation = !match[2] && request.method === 'PUT';
      const consume = !!match[2] && request.method === 'POST';
      if (!creation && !consume) return json({ error: 'Use PUT to create or POST /consume to retrieve. GET never consumes secrets.' }, 405);
      let body: unknown;
      if (creation) {
        const { success } = await env.CREATE_LIMIT.limit({ key: request.headers.get('cf-connecting-ip') || 'local' });
        if (!success) return json({ error: 'Too many requests. Try again in a minute.' }, 429);
        try { body = await readBody(request); } catch { return json({ error: 'Expected a JSON payload of at most 64 KiB.' }, 400); }
        if (!validEnvelope(body)) return json({ error: 'Invalid envelope. Use v1 authenticated encryption, 1–100 views, and expiry within 7 days.' }, 400);
        body = { ...(body as Envelope), maxViews: (body as Envelope).maxViews ?? 1 };
      }
      const object = env.SECRETS.get(env.SECRETS.idFromName(match[1]));
      const response = await object.fetch(new Request('https://secret.internal/', {
        method: creation ? 'PUT' : 'POST',
        ...(creation ? { body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } } : {}),
      }));
      if (creation && response.status === 201) return json({ id: match[1], path: `/s/${match[1]}`, expiresAt: (body as Envelope).expiresAt, maxViews: (body as Envelope).maxViews }, 201);
      return response;
    }
    if (!['GET', 'HEAD'].includes(request.method)) return json({ error: 'Method not allowed.' }, 405);
    const assetUrl = new URL(request.url);
    if (/^\/s\/[a-f0-9]{64}$/.test(url.pathname)) assetUrl.pathname = '/index.html';
    if (url.pathname === '/llm.txt') assetUrl.pathname = '/llms.txt';
    if (url.pathname === '/api' || url.pathname === '/api/') assetUrl.pathname = '/api.html';
    if (url.pathname === '/security') assetUrl.pathname = '/security.html';
    const response = await env.ASSETS.fetch(new Request(assetUrl, request));
    const headers = new Headers(response.headers);
    for (const [key, value] of Object.entries(security)) headers.set(key, value);
    headers.set('X-Robots-Tag', url.pathname.startsWith('/s/') ? 'noindex, nofollow, noarchive' : 'index');
    return new Response(response.body, { status: response.status, headers });
  },
} satisfies ExportedHandler<Env>;
