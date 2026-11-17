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
