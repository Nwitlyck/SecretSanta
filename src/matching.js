import { randomInt } from 'node:crypto';

export const MAX_PARTICIPANTS = 100;
export const MAX_NAME_LENGTH = 80;

export function parseParticipants(input) {
  if (typeof input !== 'string') throw new Error('Enter participant names.');
  const names = input.split(/[,\r\n]+/u).map(name => name.trim().normalize('NFC')).filter(Boolean);
  if (names.length < 2 || names.length > MAX_PARTICIPANTS) {
    throw new Error(`Add between 2 and ${MAX_PARTICIPANTS} participants.`);
  }
  const seen = new Set();
  for (const name of names) {
    if ([...name].length > MAX_NAME_LENGTH || /[\p{Cc}\p{Cf}]/u.test(name)) {
      throw new Error(`Names must have at most ${MAX_NAME_LENGTH} characters and no control characters.`);
    }
    const normalized = name.normalize('NFKC').toLowerCase();
    if (seen.has(normalized)) throw new Error('Each name must be unique. Add a surname or initial for people with the same name.');
    seen.add(normalized);
  }
  return names;
}

// Uniform Fisher–Yates samples, rejecting any permutation with a fixed point.
// Unlike a single cyclic rotation, this allows every possible derangement.
export function createAssignments(participants) {
  const names = parseParticipants(participants.join('\n'));
  let recipients;
  do {
    recipients = [...names];
    for (let i = recipients.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [recipients[i], recipients[j]] = [recipients[j], recipients[i]];
    }
  } while (recipients.some((name, i) => name === names[i]));
  return names.map((giver, i) => ({ giver, recipient: recipients[i] }));
}
