import path from 'node:path';
import { mkdirSync, openSync, closeSync } from 'node:fs';
import { createHmac, hkdfSync } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { ASSIGNMENT_TTL, createTokenService } from './tokens.js';

export const MAX_WISH_LENGTH = 2000;

export function normalizeWishes(input) {
  if (typeof input !== 'string') throw new Error('Escribe tus deseos en el cuadro de texto.');
  const text = input.replace(/\r\n?/gu, '\n').trim();
  if (text.length > MAX_WISH_LENGTH) throw new Error(`Puedes escribir hasta ${MAX_WISH_LENGTH} caracteres.`);
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(text)) {
    throw new Error('Usa texto normal, sin caracteres de control.');
  }
  return text;
}

// Only wishes are stored. Names and pairings stay in the encrypted credentials.
export function createWishStore(dbPath, secret, { now = () => Math.floor(Date.now() / 1000) } = {}) {
  if (dbPath !== ':memory:') {
    mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
    closeSync(openSync(dbPath, 'a', 0o600));
  }
  const db = new DatabaseSync(dbPath, { timeout: 5000 });
  try {
    db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS wishes (
        entry_key TEXT PRIMARY KEY,
        encrypted_text TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      ) STRICT;
      CREATE INDEX IF NOT EXISTS wishes_expiry ON wishes(expires_at);
    `);
    const tokens = createTokenService(secret, now);
    const lookupKey = Buffer.from(hkdfSync('sha256', secret, 'secret-santa/v1', 'wish-lookup', 32));
    const entryKey = (drawId, participant) => createHmac('sha256', lookupKey)
      .update(JSON.stringify([drawId, participant])).digest('hex');
    const select = db.prepare('SELECT encrypted_text FROM wishes WHERE entry_key = ? AND expires_at > ?');
    const remove = db.prepare('DELETE FROM wishes WHERE entry_key = ?');
    const prune = db.prepare('DELETE FROM wishes WHERE expires_at <= ?');
    const upsert = db.prepare(`
      INSERT INTO wishes (entry_key, encrypted_text, expires_at) VALUES (?, ?, ?)
      ON CONFLICT(entry_key) DO UPDATE SET encrypted_text = excluded.encrypted_text, expires_at = excluded.expires_at
    `);
    prune.run(now());
    let closed = false;
    return {
      get(drawId, participant) {
        const key = entryKey(drawId, participant);
        const row = select.get(key, now());
        const data = row ? tokens.open('wishlist', row.encrypted_text) : null;
        if (!data || data.key !== key || typeof data.text !== 'string') return { text: '', updatedAt: null };
        return { text: data.text, updatedAt: data.iat };
      },
      set(drawId, participant, input) {
        const text = normalizeWishes(input);
        const key = entryKey(drawId, participant);
        prune.run(now());
        if (!text) { remove.run(key); return; }
        const encrypted = tokens.seal('wishlist', { key, text }, ASSIGNMENT_TTL);
        upsert.run(key, encrypted, now() + ASSIGNMENT_TTL);
      },
      close() {
        if (!closed) { db.close(); closed = true; }
      },
    };
  } catch (error) {
    db.close();
    throw error;
  }
}
