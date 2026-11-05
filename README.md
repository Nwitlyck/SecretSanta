# Secret Santa

A Node.js 24 / Express application with an organizer portal, private invitations, and a 60-day remembered assignment. EJS views and local CSS/JavaScript are included; no frontend build step, database, volume, or external service is needed.

The participant experience is in Spanish, including invitations, assignment reveals, shared-device controls, and error messages. The organizer portal remains in English.

## Run locally

1. Install [Node.js 24 LTS](https://nodejs.org/) and open a terminal in this directory.
2. Install dependencies and copy the environment template:

   ```sh
   npm ci
   cp .env.example .env
   ```

   In PowerShell use `Copy-Item .env.example .env` for the second command.

3. Generate a secret:

   ```sh
   node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
   ```

   Put its output in `SESSION_SECRET` in `.env`. Set `ADMIN_PASSWORD` to a different, unique password with at least 16 characters. Do not commit `.env`.

4. Run `npm start` (or `npm run dev` for automatic restarts). Open `http://localhost:3000`, then `/admin` to organize a draw.
5. Run `npm test` for the matching, cryptography, authentication, CSRF, persistence, and HTTP integration checks.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `PORT` | Listening port; defaults to `3000`. Railway injects this. |
| `ADMIN_PASSWORD` | Required. Unique organizer password, at least 16 characters. |
| `SESSION_SECRET` | Required. At least 32 bytes of randomly generated secret material; use the command above. Keep it stable across deploys and identical across replicas. |
| `PARTICIPANTS` | Optional comma-separated default list, e.g. `Alice,Bob,Charlie,Dave`. These names appear only after admin authentication. |
| `NODE_ENV` | Set to `production` on Railway to enable HTTPS enforcement, HSTS, and `__Host-` cookie names. Use `development` for local HTTP. |
| `APP_URL` | Canonical public origin, e.g. `https://santa.example.com`. No path or credentials. Defaults locally to `http://localhost:PORT`. In production, required unless `RAILWAY_PUBLIC_DOMAIN` is available. |
| `TRUST_PROXY` | Number of trusted proxy hops; defaults to `1` in production and `0` locally. Railway’s HTTPS proxy requires this to recognize HTTPS. Review this setting if you add another proxy or change hosts. |

Use the exact `APP_URL` origin when visiting the app: forms reject mismatched origins. On Railway, omit the localhost `APP_URL` value from `.env.example`. If using a custom domain, set `APP_URL` explicitly to that HTTPS origin.

The app fails on startup for missing secrets, an invalid preconfigured list, invalid ports, or an unsafe production origin. This is intentional; it never creates a temporary fallback secret.

## Deploy on Railway

1. Push this source and `package-lock.json` to a GitHub repository, excluding `.env` and downloaded link bundles.
2. Create a Railway project and select **Deploy from GitHub repo**, then select the repository. Railway installs dependencies; the included `railway.json` sets `npm start` and the `/health` deployment health check.
3. In the service’s **Variables**, add:

   ```dotenv
   NODE_ENV=production
   ADMIN_PASSWORD=<your-unique-long-password>
   SESSION_SECRET=<your-generated-random-secret>
   PARTICIPANTS=Alice,Bob,Charlie,Dave
   TRUST_PROXY=1
   ```

   `PARTICIPANTS` is optional. Let Railway supply `PORT`.

4. Generate a public domain under **Settings → Networking**. Railway supplies `RAILWAY_PUBLIC_DOMAIN`, which the app uses as its HTTPS origin. Alternatively set `APP_URL=https://your-public-domain` explicitly. Apply changes/redeploy after setting variables or generating the domain. A deployment before a public origin exists will fail safely until this is configured.
5. Visit the HTTPS domain, open `/admin`, sign in, generate the draw, **save the link bundle**, and privately share each person’s own link. No database or persistent volume needs to be provisioned.

The server binds to `0.0.0.0` and the assigned `PORT`. `/health` deliberately accepts Railway’s internal HTTP probe. All other production pages require HTTPS. Graceful shutdown handles Railway’s `SIGTERM`.

Railway documents its [Express deployment flow](https://railway.com/guides/express), [provided variables](https://docs.railway.com/variables/reference), and [deployment health checks](https://docs.railway.com/deployments/healthchecks).

## How to use it

- `/admin`: sign in with `ADMIN_PASSWORD`. Edit the default list or enter 2–100 unique names, separated by commas or newlines. Duplicate names are rejected ignoring case and Unicode compatibility differences; add initials to distinguish people.
- **Generate assignments**: each person gives to exactly one other person and receives exactly one gift. Matching uses cryptographically random Fisher–Yates shuffles and rejects any shuffle with a self match. This samples uniformly from all valid derangements, including mutual pairs.
- Save the JSON link bundle or copy the links before navigating away. The bundle contains participant names, encrypted invitation links, a draw ID, and the invitation expiry. Keep it private. It is downloaded to the admin’s device, never stored on the server. Open the JSON with a text editor to recover its original links; the app has no bundle-import feature.
- Give each participant only their own link. Opening it automatically reveals the match and redirects to `/reveal`. Without JavaScript, paste the complete invitation link or token into the landing form and submit it.
- Returning to `/` or `/reveal` shows the same match for 60 days after the latest successful visit in that browser. A late redemption still gets a fresh full 60-day cookie lifetime. A new personal invitation replaces that browser’s remembered match; use separate browser profiles for people sharing a device.
- **Forget my assignment on this device** removes the browser cookie. The original invitation remains usable until its expiry. Organizers sign out using the dashboard’s sign-out button.

## Security and stateless behavior

The server stores **no assignments, participant edits, sessions, generated bundles, or rate-limit counters** in files, databases, or shared memory. It processes a draw only for its response. Apart from the optional environment-provided roster, participant data lives only in encrypted invitations, browser cookies, and the admin’s downloaded bundle.

- Invitations and remembered assignments use AES-256-GCM authenticated encryption with random 96-bit IVs. HKDF derives separate keys for invitations, assignment cookies, admin sessions, and cookie signing. The implementation uses [Node’s built-in crypto API](https://nodejs.org/api/crypto.html).
- Invitation links expire 60 days after generation. The secret is in a URL fragment (`/reveal#token=...`), which browsers do not transmit in HTTP URLs. Local JavaScript removes it from the address bar and submits it in a CSRF-protected POST. Do not configure application monitoring or proxies to record request bodies or cookies.
- Assignment cookies are encrypted **and** signed using `cookie-parser`. They are `HttpOnly`, `SameSite=Lax`, host-only, and `Secure` in production, with a 60-day `Max-Age` and a matching encrypted expiry. Production uses the `__Host-` prefix and `Path=/`. Admin cookies expire after 8 hours, and changing the password also invalidates existing admin sessions.
- Forms use signed, random double-submit CSRF tokens, origin validation, and Fetch Metadata checks. EJS escapes participant names. Helmet sets a restrictive Content Security Policy with local assets only, blocks framing, and disables referrers. Responses have `Cache-Control: no-store`, and sensitive values are not logged. This follows [Express security guidance](https://expressjs.com/advanced/best-practice-security/).
- Password verification compares fixed-length digests with `timingSafeEqual`. A constant 600 ms delay slows individual login attempts. **There is deliberately no in-process login rate limiter** because it would add server-side state and would not work consistently across replicas. For an internet-facing admin portal, configure rate limiting for `POST /admin/login` at a trusted edge/WAF, or place `/admin` behind a private access gateway. The delay alone does not stop parallel or distributed guessing; use a high-entropy password.

Statelessness has a few practical consequences:

- A generated draw cannot be recovered from the server after navigation or redeployment. Refreshing the results page may prompt the browser to resubmit the generation form, creating a different draw. The environment roster can prefill names again; it cannot reproduce a past random draw. Save the original links before leaving or refreshing the page.
- Generating a new draw does **not** revoke previous invitations or remembered matches. There is no central “current draw,” one-time-use tracking, or per-link revocation. To invalidate all issued tokens and cookies, rotate `SESSION_SECRET`; then generate and distribute a new draw. Keep the original secret for at least as long as you want old links and remembered matches to keep working.
- Links are bearer credentials. Anyone holding a participant’s link can see that assignment, including an organizer with the bundle. Encryption hides contents from casual inspection; it cannot identify who is opening a forwarded link.
- Cookie retention depends on the browser: clearing cookies, private browsing, browser policies, or switching domains/devices can remove access before 60 days. Keep the original invitation as a backup. The server cannot enforce a browser’s storage retention.

There are no third-party analytics, CDN scripts, remote fonts, or externally hosted frontend assets.
