import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { createAssignments, parseParticipants } from './matching.js';
import { ADMIN_TTL, ASSIGNMENT_TTL, createTokenService } from './tokens.js';
import { createWishStore, MAX_WISH_LENGTH, normalizeWishes } from './wishes.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const digest = value => createHash('sha256').update(value).digest();
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && timingSafeEqual(digest(a), digest(b));

export function createApp(config, { wishStore } = {}) {
  const app = express();
  const wishes = wishStore ?? createWishStore(config.wishlistDbPath, config.sessionSecret);
  app.locals.closeDatabase = () => wishes.close();
  const tokens = createTokenService(config.sessionSecret);
  const names = Object.fromEntries(['admin', 'assignment', 'csrf'].map(name => [name, `${config.production ? '__Host-' : ''}santa_${name}`]));
  const cookieOptions = {
    httpOnly: true, secure: config.production || config.origin.startsWith('https:'),
    sameSite: 'lax', path: '/', signed: true,
  };
  const adminFingerprint = digest(config.adminPassword).toString('hex');
  const setCookie = (res, name, value, ttl) => res.cookie(names[name], value, { ...cookieOptions, maxAge: ttl * 1000 });
  const clearCookie = (res, name) => res.clearCookie(names[name], cookieOptions);

  app.disable('x-powered-by');
  app.disable('etag');
  app.set('trust proxy', config.proxyHops);
  app.set('view engine', 'ejs');
  app.set('views', path.join(root, 'views'));
  app.use(helmet({
    contentSecurityPolicy: { directives: {
      defaultSrc: ["'none'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'], mediaSrc: ["'self'"], fontSrc: ["'self'"], connectSrc: ["'self'"],
      formAction: ["'self'"], baseUri: ["'none'"], frameAncestors: ["'none'"],
      upgradeInsecureRequests: config.production ? [] : null,
    } },
    referrerPolicy: { policy: 'no-referrer' },
    strictTransportSecurity: config.production ? { maxAge: 31536000 } : false,
  }));
  app.use((req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()', 'X-Robots-Tag': 'noindex, nofollow' });
    // Error views must also render when the body parser rejects a request early.
    res.locals.lang = /^\/admin(?:\/|$)/u.test(req.path) ? 'en' : 'es';
    res.locals.page = '';
    res.locals.title = res.locals.lang === 'es'
      ? 'Amigo secreto — Un poco de misterio. Mucha alegría.'
      : 'Secret Santa — A little mystery. A lot of joy.';
    next();
  });
  // Railway health probes can use HTTP and a special hostname.
  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.use((req, res, next) => {
    if (config.production && !req.secure) return res.redirect(308, `${config.origin}${req.path}`);
    next();
  });
  app.use('/assets', express.static(path.join(root, 'public'), { etag: false, index: false, maxAge: 0 }));
  app.use(express.urlencoded({ extended: false, limit: '128kb', parameterLimit: 10 }));
  app.use(cookieParser(tokens.cookieSecret));
  app.use((req, res, next) => {
    let csrf = req.signedCookies[names.csrf];
    if (typeof csrf !== 'string' || !/^[a-f0-9]{64}$/u.test(csrf)) {
      csrf = randomBytes(32).toString('hex');
      setCookie(res, 'csrf', csrf, ADMIN_TTL);
    }
    res.locals.csrf = csrf;
    next();
  });
  const renderError = (res, status, messages) => {
    const [title, message] = messages[res.locals.lang];
    return res.status(status).render('error', { title, message });
  };
  const csrfProtection = (req, res, next) => {
    const origin = req.get('origin');
    const fetchSite = req.get('sec-fetch-site');
    // With Referrer-Policy: no-referrer, browsers may send Origin: null on
    // same-origin form navigations. Accept that only with affirmative Fetch
    // Metadata plus the signed double-submit token, never for other null origins.
    const allowedOrigin = !origin || origin === config.origin || (origin === 'null' && fetchSite === 'same-origin');
    if (!allowedOrigin || fetchSite === 'cross-site' ||
        !equal(req.body?._csrf, req.signedCookies[names.csrf])) {
      return renderError(res, 403, {
        en: ['Let’s try that again', 'This form has expired or came from another site. Return to the page and try again.'],
        es: ['Intentémoslo de nuevo', 'Este formulario venció o se envió desde otro sitio. Vuelve a la página e inténtalo de nuevo.'],
      });
    }
    next();
  };
  const requireAdmin = (req, res, next) => {
    const session = tokens.open('admin', req.signedCookies[names.admin]);
    if (!session || !equal(session.fingerprint, adminFingerprint)) {
      clearCookie(res, 'admin');
      return res.redirect(303, '/admin');
    }
    next();
  };
  function renderDashboard(res, options = {}) {
    res.render('admin', {
      page: 'admin', title: 'The organizer’s desk — Secret Santa',
      participants: config.participants.join('\n'), error: null, links: [], drawId: null, expiresAt: null,
      ...options,
    });
  }
  function validAssignment(data) {
    return data && typeof data.giver === 'string' && typeof data.recipient === 'string' &&
      typeof data.drawId === 'string' && data.giver !== data.recipient;
  }
  function renderReveal(req, res, assignment, options = {}) {
    const ownWishes = wishes.get(assignment.drawId, assignment.giver);
    return res.render('reveal', {
      page: 'reveal', assignment, error: null,
      myWishes: ownWishes.text,
      recipientWishes: wishes.get(assignment.drawId, assignment.recipient),
      maxWishLength: MAX_WISH_LENGTH,
      wishesError: null,
      wishesSaved: req.query.saved === '1',
      ...options,
    });
  }
  const requireParticipant = (req, res, next) => {
    const assignment = tokens.open('assignment', req.signedCookies[names.assignment]);
    if (!validAssignment(assignment)) {
      if (req.path === '/wishes/recipient') return res.status(401).json({ error: 'Abre tu invitación de nuevo para ver los deseos.' });
      return res.redirect(303, '/reveal');
    }
    req.assignment = assignment;
    next();
  };
  function showPortal(req, res) {
    const assignment = tokens.open('assignment', req.signedCookies[names.assignment]);
    if (validAssignment(assignment)) {
      // A fresh 60-day window on every visit; no dependency on the invitation expiry.
      const value = { giver: assignment.giver, recipient: assignment.recipient, drawId: assignment.drawId };
      setCookie(res, 'assignment', tokens.seal('assignment', value, ASSIGNMENT_TTL), ASSIGNMENT_TTL);
      return renderReveal(req, res, assignment);
    }
    if (req.cookies[names.assignment] || req.signedCookies[names.assignment] !== undefined) clearCookie(res, 'assignment');
    return res.render('landing', { error: null, page: 'home' });
  }
  app.get(['/', '/reveal'], showPortal);
  app.post('/reveal', csrfProtection, (req, res) => {
    let token = typeof req.body.token === 'string' ? req.body.token.trim() : '';
    // Pasted complete links work without JavaScript. Tokens are never accepted in query strings.
    if (token.startsWith('http://') || token.startsWith('https://')) {
      try { token = new URLSearchParams(new URL(token).hash.slice(1)).get('token') || ''; }
      catch { token = ''; }
    }
    const assignment = tokens.open('invitation', token);
    if (!validAssignment(assignment)) {
      return res.status(400).render('landing', { page: 'home', error: 'Esta invitación no es válida o ya venció. Pídele el enlace original a quien organiza el intercambio.' });
    }
    const data = { giver: assignment.giver, recipient: assignment.recipient, drawId: assignment.drawId };
    setCookie(res, 'assignment', tokens.seal('assignment', data, ASSIGNMENT_TTL), ASSIGNMENT_TTL);
    return res.redirect(303, '/reveal');
  });
  app.post('/forget', csrfProtection, (_req, res) => {
    clearCookie(res, 'assignment');
    res.redirect(303, '/');
  });
  app.post('/wishes', requireParticipant, csrfProtection, (req, res) => {
    let text;
    try { text = normalizeWishes(req.body.wishes); }
    catch (error) {
      return renderReveal(req, res.status(400), req.assignment, {
        myWishes: typeof req.body.wishes === 'string' ? req.body.wishes : '',
        wishesError: error.message, wishesSaved: false,
      });
    }
    // Identity comes exclusively from the encrypted cookie, never a form field.
    wishes.set(req.assignment.drawId, req.assignment.giver, text);
    return res.redirect(303, '/reveal?saved=1#wishes-editor');
  });
  app.get('/wishes/recipient', requireParticipant, (req, res) => {
    res.json(wishes.get(req.assignment.drawId, req.assignment.recipient));
  });
  app.get('/admin', (req, res) => {
    const session = tokens.open('admin', req.signedCookies[names.admin]);
    if (session && equal(session.fingerprint, adminFingerprint)) return renderDashboard(res);
    return res.render('login', { page: 'admin', title: 'Organizer sign in — Secret Santa', error: null });
  });
  app.post('/admin/login', csrfProtection, async (req, res) => {
    const supplied = typeof req.body.password === 'string' ? req.body.password : '';
    // No shared counter or session store: a constant delay slows individual attempts.
    // Distributed brute-force protection belongs at the edge (see README).
    await delay(600);
    if (!equal(supplied, config.adminPassword)) {
      return res.status(401).render('login', { page: 'admin', title: 'Organizer sign in — Secret Santa', error: 'That password doesn’t match. Please try again.' });
    }
    setCookie(res, 'admin', tokens.seal('admin', { fingerprint: adminFingerprint }, ADMIN_TTL), ADMIN_TTL);
    setCookie(res, 'csrf', randomBytes(32).toString('hex'), ADMIN_TTL);
    return res.redirect(303, '/admin');
  });
  app.post('/admin/logout', requireAdmin, csrfProtection, (_req, res) => {
    clearCookie(res, 'admin');
    clearCookie(res, 'csrf');
    res.redirect(303, '/admin');
  });
  app.post('/admin/generate', requireAdmin, csrfProtection, (req, res) => {
    const input = typeof req.body.participants === 'string' ? req.body.participants : '';
    let participants;
    try { participants = parseParticipants(input); }
    catch (error) { return renderDashboard(res.status(400), { participants: input, error: error.message }); }
    const drawId = randomBytes(16).toString('hex');
    const links = createAssignments(participants).map(({ giver, recipient }) => ({
      participant: giver,
      url: `${config.origin}/reveal#token=${tokens.seal('invitation', { giver, recipient, drawId }, ASSIGNMENT_TTL)}`,
    }));
    return renderDashboard(res, {
      participants: participants.join('\n'), links, drawId,
      expiresAt: new Date(Date.now() + ASSIGNMENT_TTL * 1000).toISOString(),
    });
  });
  app.use((_req, res) => renderError(res, 404, {
    en: ['A little lost?', 'This page doesn’t exist. Your invitation link will take you to the right place.'],
    es: ['¿Te perdiste?', 'Esta página no existe. Usa tu enlace de invitación para llegar al lugar correcto.'],
  }));
  app.use((error, _req, res, _next) => {
    const badRequest = error.type === 'entity.too.large' || error.type === 'parameters.too.many' || error.status === 400;
    if (!badRequest) console.error('Request failed:', error.name); // Never log bodies, cookies, URLs, or tokens.
    if (res.headersSent) return res.end();
    return renderError(res, badRequest ? 400 : 500, {
      en: ['Something went wrong', badRequest ? 'That request is too large or malformed. Please check the form and try again.' : 'Please try again in a moment.'],
      es: ['Algo salió mal', badRequest ? 'La solicitud es demasiado grande o tiene un formato incorrecto. Revisa el formulario e inténtalo de nuevo.' : 'Inténtalo de nuevo en unos momentos.'],
    });
  });
  return app;
}
