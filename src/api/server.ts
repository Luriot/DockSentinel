import Fastify, { type FastifyError } from 'fastify';
import cookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import { existsSync } from 'node:fs';
import { sep as pathSeparator } from 'node:path';
import type { AppContext } from './context.ts';
import { ApiError } from './errors.ts';
import { enforceUnsafeRequestGuards, originFormTarget } from './http.ts';
import { SESSION_COOKIE, resolveSession } from '../auth.ts';
import { registerAuthRoutes } from './routes/auth.ts';
import { registerEnvironmentRoutes } from './routes/environments.ts';
import { registerInventoryRoutes } from './routes/inventory.ts';
import { registerFindingRoutes } from './routes/findings.ts';
import { registerScanRoutes } from './routes/scans.ts';
import { registerSystemRoutes } from './routes/system.ts';
import { registerContentRoutes } from './routes/content.ts';

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export async function buildServer(ctx: AppContext) {
  const app = Fastify({
    loggerInstance: ctx.log,
    trustProxy: ctx.config.trustProxy,
    bodyLimit: 512 * 1024,
    ajv: { customOptions: { removeAdditional: true, coerceTypes: true, allErrors: false } },
  });

  app.decorateRequest('dsSession', null);
  await app.register(cookie);

  app.addHook('onSend', async (req, reply, payload) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    reply.header('Content-Security-Policy', CSP);
    const routeUrl = req.routeOptions.url;
    if (typeof routeUrl === 'string' && routeUrl.startsWith('/api/')) reply.header('Cache-Control', 'no-store');
    if (req.protocol === 'https') reply.header('Strict-Transport-Security', 'max-age=15552000');
    return payload;
  });

  app.addHook('onRequest', async (req, reply) => {
    const target = originFormTarget(req);
    if (!target) {
      await reply.code(400).send({ error: { code: 'bad_request', message: 'Invalid request target' } });
      return;
    }
    // Use the router's matched route for known API routes. For unknown API paths there is no route
    // context, so fall back to the origin-form target (decoded) to keep unauthenticated API probing
    // at 401 instead of disclosing which routes exist.
    const routeUrl = req.routeOptions.url;
    const rawPath = target.split('?')[0] ?? '';
    let apiPath: string | null =
      typeof routeUrl === 'string' && routeUrl.startsWith('/api/') ? routeUrl : null;
    if (!apiPath && (rawPath === '/api' || rawPath.startsWith('/api/'))) apiPath = rawPath;
    if (!apiPath) {
      try {
        const decoded = decodeURIComponent(rawPath);
        if (decoded === '/api' || decoded.startsWith('/api/')) apiPath = decoded;
      } catch {
        // Malformed escapes are not an API route; the router will reject/404 them.
      }
    }
    if (!apiPath) return;
    if (apiPath === '/api/health' || apiPath === '/api') return;

    const token = req.cookies[SESSION_COOKIE];
    if (apiPath.startsWith('/api/auth/')) {
      // Auth routes manage their own requirements, but a valid session is still attached so
      // authenticated operations such as logout and password changes can verify CSRF.
      const session = token ? resolveSession(ctx.db, token) : null;
      if (session) req.dsSession = session;
      return;
    }

    const session = token ? resolveSession(ctx.db, token) : null;
    if (!session) {
      await reply.code(401).send({ error: { code: 'unauthorized', message: 'Authentication required' } });
      return;
    }
    req.dsSession = session;
    enforceUnsafeRequestGuards(req, session);
  });

  app.setErrorHandler((error: FastifyError, req, reply) => {
    if (error instanceof ApiError) {
      return reply.code(error.statusCode).send({
        error: { code: error.code, message: error.message, ...(error.details ? { details: error.details } : {}) },
      });
    }
    if (error.validation || error.statusCode === 400) {
      return reply.code(400).send({
        error: { code: 'validation_error', message: error.message || 'Invalid request' },
      });
    }
    if (typeof error.statusCode === 'number' && error.statusCode >= 400 && error.statusCode < 500) {
      return reply.code(error.statusCode).send({
        error: { code: 'request_error', message: error.message || 'Request rejected' },
      });
    }
    req.log.error({ err: error }, 'unhandled request error');
    return reply.code(500).send({ error: { code: 'internal_error', message: 'Internal server error' } });
  });

  await app.register(
    async (api) => {
      api.get('/health', async () => {
        ctx.db.get('SELECT 1 AS ok');
        return {
          status: 'ok',
          version: ctx.config.version,
          uptimeSeconds: Math.round((Date.now() - ctx.startedAt) / 1000),
        };
      });
      registerAuthRoutes(api, ctx);
      registerEnvironmentRoutes(api, ctx);
      registerInventoryRoutes(api, ctx);
      registerFindingRoutes(api, ctx);
      registerScanRoutes(api, ctx);
      registerSystemRoutes(api, ctx);
      registerContentRoutes(api, ctx);
    },
    { prefix: '/api' },
  );

  if (existsSync(ctx.config.webDist)) {
    await app.register(fastifyStatic, {
      root: ctx.config.webDist,
      wildcard: true,
      index: ['index.html'],
      maxAge: '1h',
      immutable: false,
      setHeaders: (response, path) => {
        // The SPA entry point must never be cached: a cached index.html can reference hashed
        // assets that a newer release no longer ships.
        if (path.endsWith('index.html')) response.header('Cache-Control', 'no-cache');
        else if (path.includes(`${pathSeparator}assets${pathSeparator}`)) {
          response.header('Cache-Control', 'public, max-age=31536000, immutable');
        }
      },
    });
  }

  app.setNotFoundHandler((req, reply) => {
    const target = originFormTarget(req);
    if (!target) {
      return reply.code(400).send({ error: { code: 'bad_request', message: 'Invalid request target' } });
    }
    const path = target.split('?')[0] ?? '';
    if (path === '/api' || path.startsWith('/api/')) {
      return reply.code(404).send({ error: { code: 'not_found', message: 'Endpoint not found' } });
    }
    if (req.method === 'GET' || req.method === 'HEAD') {
      if (!existsSync(ctx.config.webDist)) {
        return reply.code(503).send({
          error: {
            code: 'ui_unavailable',
            message: 'The web interface is not built. Run the web build or use the production container.',
          },
        });
      }
      return reply.sendFile('index.html');
    }
    return reply.code(404).send({ error: { code: 'not_found', message: 'Not found' } });
  });

  return app;
}
