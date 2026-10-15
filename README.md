# HappySecret

Client-encrypted, expiring text sharing on Cloudflare Workers. No accounts.

**Public test deployment:** https://happysecret.happysecret-renedotdev.workers.dev

Plaintext is encrypted on the sender's device with AES-256-GCM. A random 256-bit key lives in the URL fragment and is never included in the upload or retrieval request. An explicit reveal releases ciphertext and atomically consumes a view. Final views remove encrypted content from active storage; expiry is enforced on every retrieval and deletion is scheduled with an alarm.

## Stack

- Static HTML/CSS and native browser JavaScript modules, with no frontend dependencies or external scripts.
- TypeScript Cloudflare Worker and SQLite-backed Durable Objects using the transactional key-value API.
- Shared native Web Crypto implementation for browser and Node.js CLI.
- Node's built-in test runner plus live integration tests against the deployed Worker.

The small frontend needs no framework or bundling step. Wrangler bundles the TypeScript Worker and uploads static assets. Workers KV is intentionally not used: its eventual consistency cannot enforce a strict one-time view counter by itself.

## Use from a terminal

Node.js 22 or later; no npm packages needed. Review `public/happysecret.mjs` and `public/crypto.js`, then run:

```sh
node public/happysecret.mjs create --expires 1h --views 1 < secret.txt
node public/happysecret.mjs get 'https://host/s/<id>#<key>'
```

Creation prints the full sharing URL; retrieval prints plaintext and uses one view. Set `HAPPYSECRET_URL` or pass `--server https://host` to create on another instance.

## API and protocol

See `/api` for the readable guide and `/llms.txt` (also `/llm.txt`) for agent discovery.

- `PUT /api/v1/secrets/{id}`: create, returns 201. Caller generates an unguessable 64-character lowercase hex ID.
- `POST /api/v1/secrets/{id}/consume`: release the encrypted envelope and reduce remaining views, or return 410.
- `GET /s/{id}#<key>`: browser reveal page. GET/HEAD never consume a view.

AES-256-GCM uses a fresh 32-byte key and 12-byte nonce. The tag is 16 bytes, appended to ciphertext. Nonce and packed ciphertext use standard base64; fragment key uses unpadded base64url. Additional authenticated data is exactly UTF-8 `happysecret:v1:{id}:{expiresAt}:{maxViews}` (no newline). Timestamp must use UTC ISO 8601 with milliseconds. `maxViews` defaults to 1. See `public/crypto.js` for the reference implementation.

Limits: 32 KiB plaintext, 64 KiB JSON, 1–100 views, expiry within 7 days, 30 creation attempts per IP/minute per Cloudflare location. View consumption is not idempotent: failed decryption, lost responses, and retries can use views. Cross-origin browser API calls are blocked.

## Verify and deploy

```sh
npm ci
npm run check
npm test
npm run build
```

To self-host, remove or replace `account_id` in `wrangler.jsonc`, set a unique Worker name, and authenticate to your own Cloudflare account:

```sh
npx wrangler login
npm run deploy
node tests/live.mjs https://your-worker.your-subdomain.workers.dev
```

The first deployment creates the Durable Object class using the configured migration. A `workers.dev` subdomain must be enabled on the account. No database provisioning, domain purchase, API secret, or third-party service is required. Change the default server in the CLI/API guide and the source links when forking.

For optional local development, `npm run dev` starts Wrangler. Development and live storage are separate. This initial release is tested directly against its public deployment; no local preview server is needed.

## Privacy and operations

- A full link is a bearer secret. Recipients can keep copies, and the view count cannot revoke them.
- Source visibility does not prove deployed code; a compromised site/device can capture plaintext or keys. A reviewed local CLI reduces dependence on delivered browser code.
- Active ciphertext is removed on its final view or an expiry alarm. Expired records are inaccessible even if an alarm is delayed.
- Collision tombstones are deleted 7 days after expiry. Deletion is not a guarantee of instant physical erasure from provider backups/recovery systems.
- Application request logs/observability are disabled. Cloudflare still processes traffic metadata. There are no analytics, third-party fonts, cookies, or advertising scripts.
- Creation rate limits help with abuse but are not a global quota or cost cap. Review account limits and protection before larger-scale production use.
- Initial public test release; no independent security audit. Use test values while evaluating.

See `/security` for the end-user explanation. MIT licensed.
