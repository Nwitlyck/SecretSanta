import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

export const DAY = 24 * 60 * 60;
export const ASSIGNMENT_TTL = 60 * DAY;
export const ADMIN_TTL = 8 * 60 * 60;
const PURPOSES = new Set(['invitation', 'assignment', 'admin']);

export function createTokenService(secret, now = () => Math.floor(Date.now() / 1000)) {
  const keys = new Map([...PURPOSES].map(purpose => [purpose,
    Buffer.from(hkdfSync('sha256', secret, 'secret-santa/v1', purpose, 32)),
  ]));
  const cookieSecret = Buffer.from(hkdfSync('sha256', secret, 'secret-santa/v1', 'cookie-signing', 32)).toString('hex');

  function seal(purpose, data, ttl) {
    if (!keys.has(purpose) || !Number.isInteger(ttl) || ttl <= 0) throw new Error('Invalid token configuration.');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', keys.get(purpose), iv);
    cipher.setAAD(Buffer.from(`secret-santa/v1/${purpose}`));
    const iat = now();
    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify({ ...data, iat, exp: iat + ttl }), 'utf8'), cipher.final(),
    ]);
    return `v1.${Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url')}`;
  }

  function open(purpose, token) {
    try {
      if (!keys.has(purpose) || typeof token !== 'string' || token.length > 3500 || !/^v1\.[A-Za-z0-9_-]+$/u.test(token)) return null;
      const encoded = token.slice(3);
      const bytes = Buffer.from(encoded, 'base64url');
      if (bytes.length < 29 || bytes.toString('base64url') !== encoded) return null;
      const decipher = createDecipheriv('aes-256-gcm', keys.get(purpose), bytes.subarray(0, 12));
      decipher.setAAD(Buffer.from(`secret-santa/v1/${purpose}`));
      decipher.setAuthTag(bytes.subarray(12, 28));
      const data = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8'));
      const maxTtl = purpose === 'admin' ? ADMIN_TTL : ASSIGNMENT_TTL;
      if (!Number.isInteger(data.iat) || !Number.isInteger(data.exp) || data.iat > now() ||
          data.exp <= now() || data.exp <= data.iat || data.exp - data.iat > maxTtl) return null;
      return data;
    } catch {
      return null;
    }
  }
  return { seal, open, cookieSecret };
}
