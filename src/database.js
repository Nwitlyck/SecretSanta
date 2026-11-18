import path from 'node:path';
import { mkdirSync, openSync, closeSync } from 'node:fs';
import { createHash, createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createAssignments, parseParticipants } from './matching.js';
import { ADMIN_TTL, ASSIGNMENT_TTL, createTokenService } from './tokens.js';
import { normalizeWishes } from './wishes.js';
import { hashPin, samePinHash, validPin } from './pins.js';

export const PIN_MAX_ATTEMPTS = 5;
export const PIN_LOCK_SECONDS = 15 * 60;

const randomToken = prefix => `${prefix}.${randomBytes(32).toString('base64url')}`;
const sessionHash = token => createHash('sha256').update(token).digest('hex');

export function createDatabase(filename, secret, { now = () => Math.floor(Date.now() / 1000) } = {}) {
  if (filename !== ':memory:') {
    mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
    closeSync(openSync(filename, 'a', 0o600));
  }
  const db = new DatabaseSync(filename, { timeout: 5000 });
  try {
    db.exec(`
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS draws (
        id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        imported INTEGER NOT NULL DEFAULT 0,
        shared_token TEXT,
        shared_expires_at INTEGER
      ) STRICT;
      CREATE TABLE IF NOT EXISTS participants (
        draw_id TEXT NOT NULL REFERENCES draws(id),
        name TEXT NOT NULL,
        recipient_name TEXT,
        invitation_token TEXT UNIQUE,
        invitation_expires_at INTEGER,
        position INTEGER NOT NULL,
        wishes TEXT NOT NULL DEFAULT '',
        wishes_updated_at INTEGER,
        pin_hash TEXT,
        pin_salt TEXT,
        pin_failures INTEGER NOT NULL DEFAULT 0,
        pin_locked_until INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (draw_id, name),
        UNIQUE (draw_id, recipient_name),
        CHECK (recipient_name IS NULL OR recipient_name <> name),
        FOREIGN KEY (draw_id, recipient_name) REFERENCES participants(draw_id, name)
          DEFERRABLE INITIALLY DEFERRED
      ) STRICT;
      CREATE TABLE IF NOT EXISTS sessions (
        id_hash TEXT PRIMARY KEY,
        role TEXT NOT NULL CHECK (role IN ('admin', 'participant')),
        draw_id TEXT,
        participant_name TEXT,
        admin_fingerprint TEXT,
        expires_at INTEGER NOT NULL,
        pin_verified INTEGER NOT NULL DEFAULT 0 CHECK (pin_verified IN (0, 1)),
        FOREIGN KEY (draw_id, participant_name) REFERENCES participants(draw_id, name),
        CHECK ((role = 'admin' AND draw_id IS NULL AND participant_name IS NULL AND admin_fingerprint IS NOT NULL)
          OR (role = 'participant' AND draw_id IS NOT NULL AND participant_name IS NOT NULL AND admin_fingerprint IS NULL))
      ) STRICT;
      CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires_at);
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
    `);
    const transaction = action => {
      db.exec('BEGIN IMMEDIATE');
      try { const result = action(); db.exec('COMMIT'); return result; }
      catch (error) { db.exec('ROLLBACK'); throw error; }
    };
    // Upgrade existing SQLite files in place and retain one stable group link.
    transaction(() => {
      const columns = new Set(db.prepare('PRAGMA table_info(draws)').all().map(column => column.name));
      if (!columns.has('shared_token')) db.exec('ALTER TABLE draws ADD COLUMN shared_token TEXT');
      if (!columns.has('shared_expires_at')) db.exec('ALTER TABLE draws ADD COLUMN shared_expires_at INTEGER');
      const participantColumns = new Set(db.prepare('PRAGMA table_info(participants)').all().map(column => column.name));
      if (!participantColumns.has('pin_hash')) db.exec('ALTER TABLE participants ADD COLUMN pin_hash TEXT');
      if (!participantColumns.has('pin_salt')) db.exec('ALTER TABLE participants ADD COLUMN pin_salt TEXT');
      if (!participantColumns.has('pin_failures')) db.exec('ALTER TABLE participants ADD COLUMN pin_failures INTEGER NOT NULL DEFAULT 0');
      if (!participantColumns.has('pin_locked_until')) db.exec('ALTER TABLE participants ADD COLUMN pin_locked_until INTEGER NOT NULL DEFAULT 0');
      const sessionColumns = new Set(db.prepare('PRAGMA table_info(sessions)').all().map(column => column.name));
      if (!sessionColumns.has('pin_verified')) db.exec('ALTER TABLE sessions ADD COLUMN pin_verified INTEGER NOT NULL DEFAULT 0');
      db.exec('CREATE UNIQUE INDEX IF NOT EXISTS draw_shared_token ON draws(shared_token)');
      const update = db.prepare('UPDATE draws SET shared_token = ?, shared_expires_at = ? WHERE id = ?');
      for (const draw of db.prepare('SELECT id FROM draws WHERE shared_token IS NULL').all()) {
        update.run(randomToken('e2'), now() + ASSIGNMENT_TTL, draw.id);
      }
    });
    const getParticipant = db.prepare('SELECT * FROM participants WHERE draw_id = ? AND name = ?');
    const participantAssignment = row => row?.recipient_name ? {
      drawId: row.draw_id, giver: row.name, recipient: row.recipient_name,
    } : null;
    const pruneSessions = db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
    pruneSessions.run(now());
    const getWishes = (drawId, name) => {
      const row = getParticipant.get(drawId, name);
      return { text: row?.wishes || '', updatedAt: row?.wishes_updated_at ?? null };
    };
    const createSession = (role, drawId, name, fingerprint, ttl, pinVerified = false) => {
      const token = randomToken('s2');
      pruneSessions.run(now());
      db.prepare(`INSERT INTO sessions (id_hash, role, draw_id, participant_name, admin_fingerprint, expires_at, pin_verified)
        VALUES (?, ?, ?, ?, ?, ?, ?)`).run(sessionHash(token), role, drawId, name, fingerprint, now() + ttl, pinVerified ? 1 : 0);
      return token;
    };
    const readSession = (token, role) => {
      if (typeof token !== 'string' || !/^s2\.[A-Za-z0-9_-]{43}$/u.test(token)) return null;
      return db.prepare('SELECT * FROM sessions WHERE id_hash = ? AND role = ? AND expires_at > ?')
        .get(sessionHash(token), role, now()) || null;
    };

    // Compatibility only: previously issued v1 links/cookies can populate their
    // existing draw as participants return, without changing anyone's match.
    const legacyTokens = createTokenService(secret, now);
    const oldWishesExist = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'wishes'").get();
    const legacyWishQuery = oldWishesExist
      ? db.prepare('SELECT encrypted_text FROM wishes WHERE entry_key = ? AND expires_at > ?') : null;
    const lookupKey = Buffer.from(hkdfSync('sha256', secret, 'secret-santa/v1', 'wish-lookup', 32));
    function legacyWishes(drawId, name) {
      if (!legacyWishQuery) return { text: '', updatedAt: null };
      const key = createHmac('sha256', lookupKey).update(JSON.stringify([drawId, name])).digest('hex');
      const row = legacyWishQuery.get(key, now());
      const data = row && legacyTokens.open('wishlist', row.encrypted_text);
      return data?.key === key && typeof data.text === 'string'
        ? { text: normalizeWishes(data.text), updatedAt: data.iat } : { text: '', updatedAt: null };
    }
    function pinState(drawId, name) {
      const person = getParticipant.get(drawId, name);
      return person ? { setupRequired: !person.pin_hash, retryAfter: Math.max(0, person.pin_locked_until - now()) } : null;
    }
    function pinIdentity(sharedToken, name, existingSession) {
      if (typeof name !== 'string') return null;
      const draw = typeof sharedToken === 'string' && /^e2\.[A-Za-z0-9_-]{43}$/u.test(sharedToken)
        ? db.prepare('SELECT id FROM draws WHERE shared_token = ? AND shared_expires_at > ?').get(sharedToken, now()) : null;
      if (draw) return participantAssignment(getParticipant.get(draw.id, name));
      // A still-valid remembered session can unlock even after the group link expires.
      const session = readSession(existingSession, 'participant');
      return session && session.participant_name === name
        ? participantAssignment(getParticipant.get(session.draw_id, name)) : null;
    }
    let closed = false;
    return {
      createDraw(input) {
        const names = parseParticipants(input.join('\n'));
        const assignments = createAssignments(names);
        const id = randomBytes(16).toString('hex');
        transaction(() => {
          db.prepare('INSERT INTO draws (id, created_at, shared_token, shared_expires_at) VALUES (?, ?, ?, ?)')
            .run(id, now(), randomToken('e2'), now() + ASSIGNMENT_TTL);
          const insert = db.prepare(`INSERT INTO participants
            (draw_id, name, recipient_name, position) VALUES (?, ?, ?, ?)`);
          assignments.forEach(({ giver, recipient }, position) => {
            insert.run(id, giver, recipient, position);
          });
          db.prepare("INSERT INTO settings VALUES ('active_draw', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(id);
        });
        return id;
      },
      listDraws() {
        return db.prepare(`SELECT d.id, d.created_at AS createdAt, d.imported,
          count(p.name) AS participantCount FROM draws d LEFT JOIN participants p ON p.draw_id = d.id
          GROUP BY d.id ORDER BY d.created_at DESC, d.rowid DESC`).all();
      },
      getDraw(id) {
        const selectedId = id || db.prepare("SELECT value FROM settings WHERE key = 'active_draw'").get()?.value;
        if (typeof selectedId !== 'string') return null;
        const draw = db.prepare(`SELECT id, created_at AS createdAt, imported,
          shared_token AS sharedToken, shared_expires_at AS sharedExpiresAt FROM draws WHERE id = ?`).get(selectedId);
        if (!draw) return null;
        return { ...draw, participants: db.prepare('SELECT * FROM participants WHERE draw_id = ? ORDER BY position, name').all(selectedId) };
      },
      findInvitation(token) {
        if (typeof token !== 'string' || !/^i2\.[A-Za-z0-9_-]{43}$/u.test(token)) return null;
        return participantAssignment(db.prepare('SELECT * FROM participants WHERE invitation_token = ? AND invitation_expires_at > ?').get(token, now()));
      },
      findExchange(token) {
        if (typeof token !== 'string' || !/^e2\.[A-Za-z0-9_-]{43}$/u.test(token)) return null;
        const draw = db.prepare('SELECT id FROM draws WHERE shared_token = ? AND shared_expires_at > ?').get(token, now());
        if (!draw) return null;
        // The name picker receives no matches, wishes, or personal credentials.
        return { id: draw.id, participants: db.prepare(`SELECT name, recipient_name IS NOT NULL AS available
          FROM participants WHERE draw_id = ? ORDER BY position, name`).all(draw.id) };
      },
      chooseParticipant(token, name) {
        if (typeof name !== 'string') return null;
        const draw = this.findExchange(token);
        return draw ? participantAssignment(getParticipant.get(draw.id, name)) : null;
      },
      getPinState: pinState,
      async unlockParticipant({ token, name, pin, confirmation, mode, existingSession }) {
        const assignment = pinIdentity(token, name, existingSession);
        if (!assignment) return { ok: false, status: 400, code: 'invalid' };
        const person = getParticipant.get(assignment.drawId, assignment.giver);
        const reject = (status, code, retryAfter = 0) => ({ ok: false, assignment, status, code, retryAfter });
        if (person.pin_locked_until > now()) return reject(429, 'locked', person.pin_locked_until - now());
        if (!validPin(pin)) return reject(400, 'format');
        const setup = !person.pin_hash;
        if (mode !== (setup ? 'setup' : 'login')) return reject(409, 'changed');
        if (setup && pin !== confirmation) return reject(400, 'confirmation');
        const candidate = await hashPin(secret, assignment.drawId, assignment.giver, pin, setup ? undefined : person.pin_salt);
        return transaction(() => {
          // Recheck after the async hash so concurrent first claims cannot overwrite a PIN.
          const currentAssignment = pinIdentity(token, name, existingSession);
          if (!currentAssignment || currentAssignment.drawId !== assignment.drawId) return reject(400, 'invalid');
          const current = getParticipant.get(assignment.drawId, assignment.giver);
          if (current.pin_locked_until > now()) return reject(429, 'locked', current.pin_locked_until - now());
          if (current.pin_hash !== person.pin_hash || current.pin_salt !== person.pin_salt) return reject(409, 'changed');
          if (!setup && !samePinHash(candidate.hash, current.pin_hash)) {
            const failures = (current.pin_locked_until ? 0 : current.pin_failures) + 1;
            const lockedUntil = failures >= PIN_MAX_ATTEMPTS ? now() + PIN_LOCK_SECONDS : 0;
            db.prepare('UPDATE participants SET pin_failures = ?, pin_locked_until = ? WHERE draw_id = ? AND name = ?')
              .run(failures, lockedUntil, assignment.drawId, assignment.giver);
            return reject(lockedUntil ? 429 : 401, lockedUntil ? 'locked' : 'incorrect', lockedUntil ? PIN_LOCK_SECONDS : 0);
          }
          if (setup) {
            db.prepare('UPDATE participants SET pin_hash = ?, pin_salt = ? WHERE draw_id = ? AND name = ?')
              .run(candidate.hash, candidate.salt, assignment.drawId, assignment.giver);
            db.prepare("DELETE FROM sessions WHERE role = 'participant' AND draw_id = ? AND participant_name = ?")
              .run(assignment.drawId, assignment.giver);
          }
          db.prepare('UPDATE participants SET pin_failures = 0, pin_locked_until = 0 WHERE draw_id = ? AND name = ?')
            .run(assignment.drawId, assignment.giver);
          const sessionToken = createSession('participant', assignment.drawId, assignment.giver, null, ASSIGNMENT_TTL, true);
          return { ok: true, assignment, sessionToken };
        });
      },
      resetPin(drawId, name) {
        if (typeof drawId !== 'string' || typeof name !== 'string') return false;
        return transaction(() => {
          const changed = db.prepare('UPDATE participants SET pin_hash = NULL, pin_salt = NULL, pin_failures = 0, pin_locked_until = 0 WHERE draw_id = ? AND name = ?')
            .run(drawId, name);
          if (!changed.changes) return false;
          db.prepare("DELETE FROM sessions WHERE role = 'participant' AND draw_id = ? AND participant_name = ?").run(drawId, name);
          return true;
        });
      },
      importLegacyAssignment(data) {
        if (!data || typeof data.drawId !== 'string' || !data.drawId || data.drawId.length > 128) return null;
        try {
          const checked = parseParticipants(`${data.giver}\n${data.recipient}`);
          if (checked.length !== 2 || checked[0] !== data.giver || checked[1] !== data.recipient) return null;
          return transaction(() => {
            db.prepare(`INSERT INTO draws (id, created_at, imported, shared_token, shared_expires_at)
              VALUES (?, ?, 1, ?, ?) ON CONFLICT(id) DO NOTHING`)
              .run(data.drawId, data.iat || now(), randomToken('e2'), now() + ASSIGNMENT_TTL);
            const insert = db.prepare(`INSERT INTO participants
              (draw_id, name, position, wishes, wishes_updated_at) VALUES (?, ?, ?, ?, ?)
              ON CONFLICT(draw_id, name) DO NOTHING`);
            for (const name of checked) {
              const old = legacyWishes(data.drawId, name);
              const position = db.prepare('SELECT count(*) AS count FROM participants WHERE draw_id = ?').get(data.drawId).count;
              insert.run(data.drawId, name, position, old.text, old.updatedAt);
            }
            const existing = getParticipant.get(data.drawId, data.giver);
            if (existing.recipient_name && existing.recipient_name !== data.recipient) throw new Error('Conflicting old assignment.');
            db.prepare('UPDATE participants SET recipient_name = ? WHERE draw_id = ? AND name = ?')
              .run(data.recipient, data.drawId, data.giver);
            db.prepare("INSERT INTO settings VALUES ('active_draw', ?) ON CONFLICT(key) DO NOTHING").run(data.drawId);
            return participantAssignment(getParticipant.get(data.drawId, data.giver));
          });
        } catch { return null; }
      },
      createAdminSession(fingerprint) { return createSession('admin', null, null, fingerprint, ADMIN_TTL); },
      hasAdminSession(token, fingerprint) { return readSession(token, 'admin')?.admin_fingerprint === fingerprint; },
      createParticipantSession(assignment) {
        const row = getParticipant.get(assignment.drawId, assignment.giver);
        if (!row?.recipient_name) throw new Error('Participant has no saved assignment.');
        return createSession('participant', assignment.drawId, assignment.giver, null, ASSIGNMENT_TTL);
      },
      readParticipantSession(token, { renew = false } = {}) {
        const session = readSession(token, 'participant');
        if (!session) return null;
        if (renew) db.prepare('UPDATE sessions SET expires_at = ? WHERE id_hash = ?').run(now() + ASSIGNMENT_TTL, sessionHash(token));
        const person = getParticipant.get(session.draw_id, session.participant_name);
        const assignment = participantAssignment(person);
        return assignment ? { ...assignment, pinVerified: session.pin_verified === 1 && Boolean(person.pin_hash) } : null;
      },
      deleteSession(token) {
        if (typeof token === 'string') db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(sessionHash(token));
      },
      getWishes,
      setWishes(drawId, name, input) {
        const result = db.prepare('UPDATE participants SET wishes = ?, wishes_updated_at = ? WHERE draw_id = ? AND name = ?')
          .run(normalizeWishes(input), now(), drawId, name);
        if (!result.changes) throw new Error('Participant not found.');
      },
      close() { if (!closed) { db.close(); closed = true; } },
    };
  } catch (error) { db.close(); throw error; }
}
