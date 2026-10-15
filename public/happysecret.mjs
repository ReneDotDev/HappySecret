#!/usr/bin/env node
// Node.js 22+. No npm dependencies. Download crypto.js alongside this file.
import { encryptSecret, decryptSecret, MAX_BYTES } from './crypto.js';

const DEFAULT_SERVER = 'https://happysecret.happysecret-renedotdev.workers.dev';
const args = process.argv.slice(2);
function option(name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  if (!args[index + 1] || args[index + 1].startsWith('--')) throw new Error(`Missing value for ${name}.`);
  const value = args[index + 1];
  args.splice(index, 2);
  return value;
}
async function stdin() {
  let size = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_BYTES) throw new Error('Input exceeds 32 KiB.');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}
function serverUrl(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('--server must be an HTTPS origin without a path or credentials.');
  return url.origin;
}
async function json(response) {
  const body = await response.json();
  if (!response.ok) throw new Error(`${response.status}: ${body.error || 'Request failed.'}`);
  return body;
}
try {
  const command = args.shift();
  if (!command || ['help', '--help', '-h'].includes(command)) {
    console.log(`HappySecret — encrypt locally, share temporarily.

Usage:
  node happysecret.mjs create [--expires 1h|1d|7d] [--views 1] [--server https://host] < secret.txt
  node happysecret.mjs get 'https://host/s/<id>#<key>'

Defaults: expiry 1d, views 1, server ${DEFAULT_SERVER}
Creation prints only the sharing link. Retrieval consumes one view and prints plaintext.
Read the source before running. Node.js 22 or later; no npm dependencies.`);
  } else if (command === 'create') {
    const expires = option('--expires', '1d');
    const views = Number(option('--views', '1'));
    const server = serverUrl(option('--server', process.env.HAPPYSECRET_URL || DEFAULT_SERVER));
    if (args.length) throw new Error(`Unknown arguments: ${args.join(' ')}`);
    const duration = /^(\d+)(s|m|h|d)$/.exec(expires);
    const seconds = duration ? Number(duration[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[duration[2]] : 0;
    if (!seconds || seconds > 604800) throw new Error('Expiry must be between 1s and 7d.');
    if (!Number.isInteger(views) || views < 1 || views > 100) throw new Error('Views must be an integer from 1 to 100.');
    const text = await stdin();
    const expiresAt = new Date(Date.now() + seconds * 1000 - (seconds === 604800 ? 1000 : 0)).toISOString();
    const { id, key, envelope } = await encryptSecret(text, { expiresAt, maxViews: views });
    await json(await fetch(`${server}/api/v1/secrets/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(envelope), signal: AbortSignal.timeout(20000), redirect: 'error' }));
    console.log(`${server}/s/${id}#${key}`);
  } else if (command === 'get') {
    if (args.length !== 1) throw new Error('Pass exactly one complete secret link, quoted.');
    const link = new URL(args[0]);
    const server = serverUrl(link.origin);
    const match = /^\/s\/([a-f0-9]{64})$/.exec(link.pathname);
    if (!match || !/^[A-Za-z0-9_-]{43}$/.test(link.hash.slice(1))) throw new Error('Invalid secret link.');
    const envelope = await json(await fetch(`${server}/api/v1/secrets/${match[1]}/consume`, { method: 'POST', signal: AbortSignal.timeout(20000), redirect: 'error' }));
    try { process.stdout.write(await decryptSecret(match[1], link.hash.slice(1), envelope)); }
    catch { throw new Error('Authentication/decryption failed. A view has been used; verify the link with the sender.'); }
  } else throw new Error('Unknown command. Run with --help for usage.');
} catch (error) {
  console.error(`HappySecret: ${error.message}`);
  process.exitCode = 1;
}
