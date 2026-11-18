import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { parseParticipants } from './matching.js';
import { ADMIN_TTL, ASSIGNMENT_TTL, createTokenService } from './tokens.js';
import { MAX_WISH_LENGTH, normalizeWishes } from './wishes.js';
import { createDatabase } from './database.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const digest = value => createHash('sha256').update(value).digest();
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && timingSafeEqual(digest(a), digest(b));

export function createApp(config, { database } = {}) {
  const app = express();
  const store = database ?? createDatabase(config.databasePath, config.sessionSecret);
  app.locals.closeDatabase = () => store.close();
  const tokens = createTokenService(config.sessionSecret);
  const names = Object.fromEntries(['admin', 'participant', 'assignment', 'csrf'].map(name => [name, `${config.production ? '__Host-' : ''}santa_${name}`]));
  const cookieOptions = {
    httpOnly: true, secure: config.production || config.origin.startsWith('https:'),
    sameSite: 'lax', path: '/', signed: true,
  };
  const adminFingerprint = createHmac('sha256', config.sessionSecret).update('admin-password:').update(config.adminPassword).digest('hex');
  const legacyAdminFingerprint = digest(config.adminPassword).toString('hex');
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
  // The second key accepts signed cookies from the previous stateless version.
  app.use(cookieParser([config.sessionSecret, tokens.cookieSecret]));
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
  function adminSession(req, res) {
    const token = req.signedCookies[names.admin];
    if (store.hasAdminSession(token, adminFingerprint)) return token;
    const legacy = tokens.open('admin', token);
    if (!legacy || !equal(legacy.fingerprint, legacyAdminFingerprint)) return null;
    const sessionToken = store.createAdminSession(adminFingerprint);
    setCookie(res, 'admin', sessionToken, ADMIN_TTL);
    return sessionToken;
  }
  const requireAdmin = (req, res, next) => {
    req.adminSession = adminSession(req, res);
    if (!req.adminSession) {
      clearCookie(res, 'admin');
      return res.redirect(303, '/admin');
    }
    next();
  };
  function renderDashboard(req, res, options = {}) {
    const selectedId = typeof req.query.draw === 'string' ? req.query.draw : undefined;
    const draw = store.getDraw(selectedId);
    if (selectedId && !draw) return renderError(res, 404, {
      en: ['Exchange not found', 'Choose an existing exchange from the organizer dashboard.'],
      es: ['No encontramos el intercambio', 'Selecciona un intercambio guardado.'],
    });
    const sharedUrl = draw ? `${config.origin}/reveal#token=${draw.sharedToken}` : null;
    return res.render('admin', {
      page: 'admin', title: 'The organizer’s desk — Secret Santa',
      participants: draw ? draw.participants.map(person => person.name).join('\n') : config.participants.join('\n'),
      error: null, sharedUrl, drawId: draw?.id || null,
      participantCount: draw?.participants.length || 0,
      expiresAt: draw ? new Date(draw.sharedExpiresAt * 1000).toISOString().slice(0, 10) : null,
      draws: store.listDraws(), imported: Boolean(draw?.imported),
      pinParticipants: draw?.participants.map(person => ({ name: person.name, hasPin: Boolean(person.pin_hash) })) || [],
      pinReset: req.query.pinreset === '1',
      ...options,
    });
  }
  function participantSession(req, res, renew = false) {
    let token = req.signedCookies[names.participant];
    let assignment = store.readParticipantSession(token, { renew });
    if (!assignment) {
      const old = tokens.open('assignment', req.signedCookies[names.assignment]);
      assignment = old ? store.importLegacyAssignment(old) : null;
      if (assignment) {
        token = store.createParticipantSession(assignment);
        setCookie(res, 'participant', token, ASSIGNMENT_TTL);
        clearCookie(res, 'assignment');
      }
    }
    return assignment ? { token, assignment } : null;
  }
  function renderReveal(req, res, assignment, options = {}) {
    const ownWishes = store.getWishes(assignment.drawId, assignment.giver);
    const draw = store.getDraw(assignment.drawId);
    return res.render('reveal', {
      page: 'reveal', assignment, error: null,
      myWishes: ownWishes.text,
      recipientWishes: store.getWishes(assignment.drawId, assignment.recipient),
      maxWishLength: MAX_WISH_LENGTH,
      wishesError: null,
      wishesSaved: req.query.saved === '1',
      sharedUrl: draw?.sharedExpiresAt > Date.now() / 1000 ? `/reveal#token=${draw.sharedToken}` : null,
      ...options,
    });
  }
  function renderPin(req, res, assignment, options = {}) {
    const state = store.getPinState(assignment.drawId, assignment.giver);
    const draw = store.getDraw(assignment.drawId);
    return res.render('participant-pin', {
      page: 'home', name: assignment.giver, token: draw.sharedToken,
      setupRequired: state.setupRequired, retryAfter: state.retryAfter,
      error: null, ...options,
    });
  }
  const requireParticipant = (req, res, next) => {
    const session = participantSession(req, res);
    if (!session?.assignment.pinVerified) {
      if (req.path === '/wishes/recipient') return res.status(401).json({ error: 'Abre tu invitación e ingresa tu PIN para ver los deseos.' });
      return res.redirect(303, '/reveal');
    }
    req.assignment = session.assignment;
    req.participantSession = session.token;
    next();
  };
  function showPortal(req, res) {
    const session = participantSession(req, res, true);
    if (session) {
      setCookie(res, 'participant', session.token, ASSIGNMENT_TTL);
      if (!session.assignment.pinVerified) return renderPin(req, res, session.assignment);
      return renderReveal(req, res, session.assignment);
    }
    if (req.cookies[names.participant] || req.signedCookies[names.participant] !== undefined) clearCookie(res, 'participant');
    if (req.cookies[names.assignment] || req.signedCookies[names.assignment] !== undefined) clearCookie(res, 'assignment');
    return res.render('landing', { error: null, page: 'home' });
  }
  app.get(['/', '/reveal'], showPortal);
  function startParticipantSession(req, res, sessionToken) {
    store.deleteSession(req.signedCookies[names.participant]);
    setCookie(res, 'participant', sessionToken, ASSIGNMENT_TTL);
    setCookie(res, 'csrf', randomBytes(32).toString('hex'), ADMIN_TTL);
    clearCookie(res, 'assignment');
    return res.redirect(303, '/reveal');
  }
  app.post('/reveal', csrfProtection, (req, res) => {
    let token = typeof req.body.token === 'string' ? req.body.token.trim() : '';
    // Pasted complete links work without JavaScript. Tokens are never accepted in query strings.
    if (token.startsWith('http://') || token.startsWith('https://')) {
      try { token = new URLSearchParams(new URL(token).hash.slice(1)).get('token') || ''; }
      catch { token = ''; }
    }
    const exchange = store.findExchange(token);
    if (exchange) return res.render('choose-participant', { page: 'home', exchange, token, error: null });
    const legacy = tokens.open('invitation', token);
    const assignment = store.findInvitation(token) || (legacy ? store.importLegacyAssignment(legacy) : null);
    if (!assignment) {
      return res.status(400).render('landing', { page: 'home', error: 'Esta invitación no es válida o ya venció. Pídele el enlace original a quien organiza el intercambio.' });
    }
    // Old personal links migrate to an unverified session, never around the PIN.
    store.deleteSession(req.signedCookies[names.participant]);
    setCookie(res, 'participant', store.createParticipantSession(assignment), ASSIGNMENT_TTL);
    clearCookie(res, 'assignment');
    return renderPin(req, res, assignment);
  });
  app.post('/exchange/join', csrfProtection, (req, res) => {
    const token = typeof req.body.token === 'string' ? req.body.token : '';
    const exchange = store.findExchange(token);
    if (!exchange) return res.status(400).render('landing', {
      page: 'home', error: 'Este enlace de intercambio no es válido o ya venció. Pídele el enlace a quien organiza.',
    });
    const assignment = store.chooseParticipant(token, req.body.name);
    if (!assignment) return res.status(400).render('choose-participant', {
      page: 'home', exchange, token, error: 'Elige tu nombre de la lista. Si aparece pendiente, abre tu invitación original para recuperar tu asignación.',
    });
    return renderPin(req, res, assignment);
  });
  app.post('/exchange/unlock', csrfProtection, async (req, res) => {
    const result = await store.unlockParticipant({
      token: req.body.token, name: req.body.name, pin: req.body.pin,
      confirmation: req.body.confirmation, mode: req.body.mode,
      existingSession: req.signedCookies[names.participant],
    });
    if (!result.ok) {
      if (!result.assignment || result.code === 'invalid') return res.status(400).render('landing', {
        page: 'home', error: 'Este enlace no es válido o ya venció. Abre tu invitación de nuevo.',
      });
      const messages = {
        format: 'El PIN debe tener exactamente 4 números.',
        confirmation: 'Los PIN no coinciden. Escríbelos de nuevo.',
        changed: 'El PIN de este nombre cambió. Ingresa el PIN actual para continuar.',
        incorrect: 'Ese PIN no coincide. Inténtalo de nuevo.',
        locked: `Demasiados intentos. Inténtalo de nuevo en ${Math.ceil(result.retryAfter / 60)} minutos.`,
      };
      if (result.retryAfter) res.set('Retry-After', String(result.retryAfter));
      return renderPin(req, res.status(result.status), result.assignment, { error: messages[result.code] });
    }
    return startParticipantSession(req, res, result.sessionToken);
  });
  app.post('/forget', csrfProtection, (req, res) => {
    store.deleteSession(req.signedCookies[names.participant]);
    clearCookie(res, 'participant');
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
    // The saved session identifies the owner; form fields cannot select one.
    store.setWishes(req.assignment.drawId, req.assignment.giver, text);
    return res.redirect(303, '/reveal?saved=1#wishes-editor');
  });
  app.get('/wishes/recipient', requireParticipant, (req, res) => {
    res.json({
      ...store.getWishes(req.assignment.drawId, req.assignment.recipient),
      viewer: { drawId: req.assignment.drawId, name: req.assignment.giver },
    });
  });
  app.get('/admin', (req, res) => {
    if (adminSession(req, res)) return renderDashboard(req, res);
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
    store.deleteSession(req.signedCookies[names.admin]);
    setCookie(res, 'admin', store.createAdminSession(adminFingerprint), ADMIN_TTL);
    setCookie(res, 'csrf', randomBytes(32).toString('hex'), ADMIN_TTL);
    return res.redirect(303, '/admin');
  });
  app.post('/admin/logout', requireAdmin, csrfProtection, (req, res) => {
    store.deleteSession(req.adminSession);
    clearCookie(res, 'admin');
    clearCookie(res, 'csrf');
    res.redirect(303, '/admin');
  });
  app.post('/admin/generate', requireAdmin, csrfProtection, (req, res) => {
    const input = typeof req.body.participants === 'string' ? req.body.participants : '';
    let participants;
    try { participants = parseParticipants(input); }
    catch (error) { return renderDashboard(req, res.status(400), { participants: input, error: error.message }); }
    const drawId = store.createDraw(participants);
    return res.redirect(303, `/admin?draw=${drawId}`);
  });
  app.post('/admin/reset-pin', requireAdmin, csrfProtection, (req, res) => {
    if (!store.resetPin(req.body.drawId, req.body.name)) return renderError(res, 404, {
      en: ['Participant not found', 'Open the saved exchange and try again.'],
      es: ['No encontramos a esa persona', 'Abre el intercambio guardado e inténtalo de nuevo.'],
    });
    return res.redirect(303, `/admin?draw=${encodeURIComponent(req.body.drawId)}&pinreset=1`);
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
