import { parseParticipants } from './matching.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));

export function loadConfig(env = process.env) {
  const production = env.NODE_ENV === 'production';
  const port = Number(env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535.');
  }
  if (typeof env.ADMIN_PASSWORD !== 'string' || env.ADMIN_PASSWORD.length < 16) {
    throw new Error('ADMIN_PASSWORD must contain at least 16 characters.');
  }
  if (typeof env.SESSION_SECRET !== 'string' || Buffer.byteLength(env.SESSION_SECRET) < 32) {
    throw new Error('SESSION_SECRET must contain at least 32 bytes; use a randomly generated secret.');
  }
  if (env.ADMIN_PASSWORD === env.SESSION_SECRET) {
    throw new Error('ADMIN_PASSWORD and SESSION_SECRET must be different.');
  }

  const rawOrigin = env.APP_URL || (env.RAILWAY_PUBLIC_DOMAIN ? `https://${env.RAILWAY_PUBLIC_DOMAIN}` : '');
  if (production && !rawOrigin) {
    throw new Error('Set APP_URL to your HTTPS origin or generate a Railway public domain.');
  }
  let origin;
  try {
    origin = new URL(rawOrigin || `http://localhost:${port}`);
  } catch {
    throw new Error('APP_URL must be a valid HTTP(S) origin.');
  }
  if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password ||
      origin.pathname !== '/' || origin.search || origin.hash || (production && origin.protocol !== 'https:')) {
    throw new Error('APP_URL must be an HTTP(S) origin without credentials or a path; production requires HTTPS.');
  }
  const proxyHops = Number(env.TRUST_PROXY ?? (production ? 1 : 0));
  if (!Number.isInteger(proxyHops) || proxyHops < 0 || proxyHops > 10) {
    throw new Error('TRUST_PROXY must be a number of trusted reverse proxy hops from 0 to 10.');
  }
  const participants = env.PARTICIPANTS?.trim() ? parseParticipants(env.PARTICIPANTS) : [];
  const configuredDbPath = env.DATABASE_PATH?.trim() || env.WISHLIST_DB_PATH?.trim();
  if (production && ((!configuredDbPath && !env.RAILWAY_VOLUME_MOUNT_PATH) || configuredDbPath === ':memory:')) {
    throw new Error('Attach a Railway persistent volume or set DATABASE_PATH to a persistent SQLite file.');
  }
  const databasePath = configuredDbPath === ':memory:' ? configuredDbPath
    : path.resolve(projectRoot, configuredDbPath || path.join(env.RAILWAY_VOLUME_MOUNT_PATH || 'data', 'wishes.sqlite'));
  return Object.freeze({
    port, production, origin: origin.origin, proxyHops, participants, databasePath,
    adminPassword: env.ADMIN_PASSWORD,
    sessionSecret: env.SESSION_SECRET,
  });
}
