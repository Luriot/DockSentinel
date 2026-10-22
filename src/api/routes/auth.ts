import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context.ts';
import {
  assertCsrf,
  clearSessionCookie,
  clientIp,
  requireSession,
  setSessionCookie,
} from '../http.ts';
import { ApiError, badRequest, conflict, unauthorized } from '../errors.ts';
import {
  SESSION_COOKIE,
  createSession,
  deleteAllSessions,
  deleteOtherSessions,
  deleteSession,
  getPasswordHash,
  getUser,
  resolveSession,
  setCredentials,
} from '../../auth.ts';
import { hashPassword, validatePassword, verifyPassword } from '../../passwords.ts';
import { constantTimeEquals } from '../../secrets.ts';
import { RateLimiter } from '../../security/rate-limit.ts';

const USERNAME_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

function assertUsername(value: unknown): string {
  if (typeof value !== 'string' || !USERNAME_PATTERN.test(value)) {
    badRequest('Username must be 1-64 characters: letters, numbers, dot, dash or underscore');
  }
  return value;
}

function sessionPayload(db: AppContext['db'], token: string | undefined) {
  const session = token ? resolveSession(db, token) : null;
  return {
    needsSetup: getUser(db) === null,
    authenticated: Boolean(session),
    user: session ? { username: session.user.username } : null,
    csrfToken: session?.csrfToken ?? null,
  };
}

export function registerAuthRoutes(app: FastifyInstance, ctx: AppContext): void {
  const loginLimiter = new RateLimiter(10, 5 * 60_000);
  const setupLimiter = new RateLimiter(10, 5 * 60_000);

  app.get('/auth/session', async (req) => sessionPayload(ctx.db, req.cookies[SESSION_COOKIE]));

  app.post(
    '/auth/setup',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['setupToken', 'username', 'password'],
          properties: {
            setupToken: { type: 'string', maxLength: 200 },
            username: { type: 'string', maxLength: 64 },
            password: { type: 'string', maxLength: 200 },
          },
        },
      },
    },
    async (req, reply) => {
      const limit = setupLimiter.hit(clientIp(req));
      if (!limit.allowed) {
        throw new ApiError(429, 'rate_limited', 'Too many attempts. Try again shortly.', {
          retryAfterMs: limit.retryAfterMs,
        });
      }
      if (getUser(ctx.db)) conflict('DockSentinel is already set up');
      const expected = ctx.setupToken();
      if (!expected) throw new ApiError(409, 'setup_unavailable', 'Setup is not available');
      const body = req.body as { setupToken: string; username: string; password: string };
      if (!constantTimeEquals(body.setupToken, expected)) unauthorized('Invalid setup token');
      const username = assertUsername(body.username);
      const passwordError = validatePassword(body.password);
      if (passwordError) badRequest(passwordError);

      setCredentials(ctx.db, username, await hashPassword(body.password));
      deleteAllSessions(ctx.db);
      const session = createSession(ctx.db, 1, { ip: clientIp(req), userAgent: req.headers['user-agent'] ?? null });
      setSessionCookie(req, reply, ctx.config, session.token, session.expiresAt);
      ctx.log.info({ username }, 'administrator account created');
      return { authenticated: true, user: { username }, csrfToken: session.csrfToken, needsSetup: false };
    },
  );

  app.post(
    '/auth/login',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['username', 'password'],
          properties: {
            username: { type: 'string', maxLength: 64 },
            password: { type: 'string', maxLength: 200 },
          },
        },
      },
    },
    async (req, reply) => {
      const ip = clientIp(req);
      const limit = loginLimiter.hit(ip);
      if (!limit.allowed) {
        throw new ApiError(429, 'rate_limited', 'Too many login attempts. Try again shortly.', {
          retryAfterMs: limit.retryAfterMs,
        });
      }
      const body = req.body as { username: string; password: string };
      const user = getUser(ctx.db);
      const hash = getPasswordHash(ctx.db);

      if (!user || !hash || user.username !== body.username) {
        // Hash the candidate so a wrong username costs the same scrypt work as a wrong password.
        await hashPassword(body.password);
        unauthorized('Invalid username or password');
      }
      const valid = await verifyPassword(body.password, hash);
      if (!valid) unauthorized('Invalid username or password');

      loginLimiter.reset(ip);
      const session = createSession(ctx.db, user.id, { ip, userAgent: req.headers['user-agent'] ?? null });
      setSessionCookie(req, reply, ctx.config, session.token, session.expiresAt);
      ctx.log.info({ username: user.username, ip }, 'login succeeded');
      return { authenticated: true, user: { username: user.username }, csrfToken: session.csrfToken };
    },
  );

  app.post('/auth/logout', async (req, reply) => {
    const token = req.cookies[SESSION_COOKIE];
    const session = token ? resolveSession(ctx.db, token) : null;
    if (session) {
      assertCsrf(req, session);
      deleteSession(ctx.db, token);
    }
    clearSessionCookie(reply);
    return { ok: true };
  });

  app.post(
    '/auth/password',
    {
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['currentPassword', 'newPassword'],
          properties: {
            currentPassword: { type: 'string', maxLength: 200 },
            newPassword: { type: 'string', maxLength: 200 },
          },
        },
      },
    },
    async (req) => {
      const session = requireSession(req);
      assertCsrf(req, session);
      const body = req.body as { currentPassword: string; newPassword: string };
      const hash = getPasswordHash(ctx.db);
      if (!hash || !(await verifyPassword(body.currentPassword, hash))) {
        unauthorized('Current password is incorrect');
      }
      const passwordError = validatePassword(body.newPassword);
      if (passwordError) badRequest(passwordError);

      setCredentials(ctx.db, session.user.username, await hashPassword(body.newPassword));
      deleteOtherSessions(ctx.db, req.cookies[SESSION_COOKIE]);
      ctx.log.info({ username: session.user.username }, 'password changed');
      return { ok: true };
    },
  );
}
