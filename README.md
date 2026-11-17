# Secret Santa

A Node.js 24 / Express app backed by SQLite. Participants, assignments, invitation links, gift wishes, and login sessions are saved in one database. Restarting the server or refreshing the dashboard keeps the same exchange.

Participant pages are in Spanish. The organizer dashboard is in English. The Santa video plays for two seconds when a page opens.

## Run locally

1. Install Node.js 24 and run `npm ci` in this directory.
2. Edit the existing `.env` file in the project root directly. The app loads it automatically. Keep this file local; it is ignored by Git.
3. Set the following values in `.env`:

   ```dotenv
   NODE_ENV=development
   PORT=3000
   ADMIN_PASSWORD=<a-unique-password-of-at-least-16-characters>
   SESSION_SECRET=<a-random-secret-of-at-least-32-bytes>
   APP_URL=http://localhost:3000
   ```

   Generate a secret with:

   ```sh
   node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
   ```

4. Run `npm start`, or `npm run dev` for automatic restarts.
5. Open `http://localhost:3000/admin`, sign in, enter the names, and generate an exchange.

The app creates `data/wishes.sqlite` automatically. The filename is retained from the previous version so an existing wishes database can be upgraded in place. The file now stores the whole application. Database files and `.env` are gitignored.

## Using the app

- **Generate assignments** saves a complete draw in a single database transaction. Everyone gives and receives exactly once, with no self matches. Matching uses cryptographically random Fisher–Yates shuffles and rejects self matches.
- The admin dashboard lists **Saved exchanges**. Reopen any exchange to retrieve its participant list and the same shared link. Refreshing the page never generates a new draw. Generating another exchange keeps previous ones available.
- **Copy exchange link** gives you one link for the whole group. Share that same link with everyone. Opening it shows **¿Quién eres?**; each person selects their name and chooses **Ver mi intercambio** to see their saved assignment and edit their own wishes. Selecting a name never reshuffles the exchange.
- Each shared link contains a random, unguessable credential and expires after 60 days. The credential stays in the URL fragment, is submitted in a CSRF-protected POST, and is removed from the address bar. Without JavaScript, paste the complete shared link into the landing-page form to open the name picker.
- Choosing a name creates a saved participant session. The signed, HttpOnly cookie contains only a random session ID. Returning to `/` or `/reveal` remembers that selection for 60 days after the latest visit. Reopen the shared link or use **Volver a la lista** to choose a different name. Switching names revokes the browser's previous session and rotates its form token.
- **Qué me gustaría recibir** lets each participant save and edit up to 2,000 characters of plain text. The person buying their gift sees those wishes. Updates appear on every visit, every 30 seconds while the page is visible, and when returning to the tab. With JavaScript disabled, reloading shows the latest wishes.
- Emptying the wishes box and saving clears it. Wishes otherwise remain saved with the exchange. The latest save wins when editing from multiple devices.
- **Borrar mi asignación de este dispositivo** signs the participant out and revokes that browser session. The original invitation still works until it expires. Wishes remain saved. Use separate browser profiles for people sharing a device.
- Admin sign-out also deletes the corresponding session from SQLite. Admin sessions expire after eight hours; changing the admin password invalidates them.

## Configuration

| Variable | Purpose |
| --- | --- |
| `PORT` | Defaults to `3000`; Railway supplies its assigned port. |
| `ADMIN_PASSWORD` | Required organizer password, at least 16 characters. |
| `SESSION_SECRET` | Required random secret of at least 32 bytes, used for cookie signatures. Keep the previous value during an upgrade to migrate old links and encrypted wishes. |
| `PARTICIPANTS` | Optional initial names, separated by commas. Once a draw is saved, its participant list comes from SQLite. |
| `DATABASE_PATH` | Optional SQLite file path. Relative paths resolve from the project root. Defaults to `./data/wishes.sqlite` locally, or `wishes.sqlite` inside Railway's attached volume. |
| `WISHLIST_DB_PATH` | Previous name for `DATABASE_PATH`; still accepted so existing configuration works. `DATABASE_PATH` takes precedence. |
| `NODE_ENV` | Use `development` for local HTTP and `production` for Railway HTTPS. |
| `APP_URL` | Exact public origin, without a path, e.g. `https://santa.example.com`. Defaults to local HTTP or Railway's provided public domain. Production requires HTTPS. |
| `TRUST_PROXY` | Number of trusted reverse-proxy hops: defaults to zero locally and one in production. |
| `RAILWAY_VOLUME_MOUNT_PATH` | Provided by Railway when a persistent volume is attached; used to locate the database automatically. |

Production requires an attached volume or an explicit persistent `DATABASE_PATH`. An in-memory production database is rejected. The app also rejects missing secrets, invalid origins, and inaccessible database files.

## Railway

1. Deploy the repository as a Railway service. The included `railway.json` runs `npm start` and checks `/health`.
2. Set `NODE_ENV=production`, `ADMIN_PASSWORD`, and `SESSION_SECRET` in the service's Variables. Let Railway supply `PORT`. Optional: set `PARTICIPANTS` for the initial roster.
3. Attach a **persistent volume mounted at `/data`** to the app service. The app automatically uses `/data/wishes.sqlite`. If you set `DATABASE_PATH` explicitly, point it to a file on this volume. Setting a path alone does not create persistent storage.
4. Generate a public domain or set `APP_URL` to your HTTPS domain. Remove any localhost `APP_URL` and local `TRUST_PROXY=0` values when copying local configuration to production.
5. Redeploy. Keep the service at one instance and back up the database volume. [Railway volumes](https://docs.railway.com/volumes/reference) preserve files across deployments and do not support replicas.

No separate database server or extra npm database package is needed. The app uses Node's built-in SQLite module. It binds to `0.0.0.0`, uses the assigned port, and closes the database on graceful shutdown.

## Upgrading an existing exchange

Keep the same `.env`, `SESSION_SECRET`, database file, and Railway volume. The upgrade adds tables to the existing database; it does not erase old wish records.

Previously issued encrypted invitation links and remembered cookies remain usable until their original expiry. As someone returns, the app imports their original assignment and any available saved wishes into SQLite. The old server did not keep the complete draw, so an imported exchange fills in as each participant opens their invitation. The admin dashboard labels these exchanges as imported. A newly generated exchange is saved completely from the start.

Existing SQLite exchanges automatically receive one shared group link without changing their pairings or wishes. Previously issued individual links still work, while the dashboard now shows only the shared link. In partially imported exchanges, names with an unknown original assignment are marked **pendiente** until that participant opens their original invitation.

Before an old participant returns, their original link is still the way to recover their assignment. Keep the old link bundle until everyone has migrated. Older encrypted wishes must still be within their original 60-day lifetime to be imported.

## Security and verification

SQLite is the source of truth. Names, pairings, and new wishes use ordinary database columns; protect the database file and its backups. Login session IDs are stored as hashes, cookies are signed, and the admin password is read from the environment rather than saved in SQLite.

The shared link grants access to the group. Choosing a name is not identity verification: anyone with that link can choose any participant's name, view that assignment, and edit that name's wishes. Share it only with your trusted group. The name picker itself lists names without showing pairings or wishes.

Prepared SQL statements, database constraints, and transactions protect data integrity. Session checks tie the editor to the selected name and show that name's assigned recipient's wishes. Changing the owner through a wish form field is not allowed. Forms use signed CSRF tokens and origin checks. EJS escapes names and wishes, live updates use `textContent`, Helmet applies a restrictive Content Security Policy, and private responses are not cached. Production cookies require HTTPS.

There is no built-in login rate limiter. Use a strong password and configure rate limiting for `POST /admin/login` at your trusted edge if exposing it publicly.

Run `npm test` for matching, database restart persistence, saved exchange recovery, session expiry/revocation, authorization, plain-text safety, and migration checks. Tests use isolated databases, not your real `.env` or application data.
