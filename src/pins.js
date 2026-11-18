import { createHmac, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(scrypt);
export const validPin = pin => typeof pin === 'string' && /^[0-9]{4}$/u.test(pin);

export async function hashPin(secret, drawId, name, pin, salt = randomBytes(16).toString('hex')) {
  if (!validPin(pin) || !/^[a-f0-9]{32}$/u.test(salt)) throw new Error('Invalid PIN input.');
  // A server-side pepper keeps a database copy alone from testing all 10,000 PINs.
  const input = createHmac('sha256', secret).update(JSON.stringify(['participant-pin', drawId, name, pin])).digest();
  const hash = await derive(input, Buffer.from(salt, 'hex'), 32, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 });
  return { salt, hash: hash.toString('hex') };
}

export function samePinHash(actual, expected) {
  return typeof expected === 'string' && /^[a-f0-9]{64}$/u.test(expected) &&
    timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}
