import type { FastifyRequest } from 'fastify';
import { SESSION_COOKIE, type SessionContext } from '../auth.ts';
import { constantTimeEquals } from '../secrets.ts';
import type { Config } from '../config.ts';
import { badRequest, forbidden, unauthorized } from './errors.ts';

declare module 'fastify' {
  interface FastifyRequest {
    dsSession?: SessionContext | null;
  }
}

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function requireSession(req: FastifyRequest): SessionContext {
  if (!req.dsSession) throw unauthorized();
  return req.dsSession;
}

export function assertCsrf(req: FastifyRequest, session: SessionContext): void {
  const header = req.headers['x-csrf-token'];
  if (typeof header !== 'string' || !constantTimeEquals(header, session.csrfToken)) {
    throw forbidden('Missing or invalid CSRF token');
  }
}

/** Rejects state-changing requests whose Origin does not match the Host they were sent to. */
export function assertSameOrigin(req: FastifyRequest): void {
  const origin = req.headers.origin;
  if (!origin) return;
  const host = req.headers.host;
  if (!host) throw forbidden('Origin check failed');
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw forbidden('Origin check failed');
  }
  if (parsed.host !== host) throw forbidden('Origin check failed');
}

export function enforceUnsafeRequestGuards(req: FastifyRequest, session: SessionContext): void {
  if (!UNSAFE_METHODS.has(req.method)) return;
  assertCsrf(req, session);
  assertSameOrigin(req);
}

export function isSecureRequest(req: FastifyRequest, config: Config): boolean {
  if (config.cookieSecure === 'always') return true;
  if (config.cookieSecure === 'never') return false;
  return req.protocol === 'https';
}

export function setSessionCookie(
  req: FastifyRequest,
  reply: { setCookie(name: string, value: string, options?: Record<string, unknown>): unknown },
  config: Config,
  token: string,
  expiresAt: string,
): void {
  reply.setCookie(SESSION_COOKIE, token, {
    path: '/',
    httpOnly: true,
    sameSite: 'strict',
    secure: isSecureRequest(req, config),
    expires: new Date(expiresAt),
  });
}

export function clearSessionCookie(reply: {
  clearCookie(name: string, options?: Record<string, unknown>): unknown;
}): void {
  reply.clearCookie(SESSION_COOKIE, { path: '/', httpOnly: true, sameSite: 'strict' });
}

export function clientIp(req: FastifyRequest): string {
  return req.ip || 'unknown';
}

export interface Pagination {
  page: number;
  pageSize: number;
}

export function parsePagination(page: unknown, pageSize: unknown, maxPageSize = 100): Pagination {
  const parsedPage = Number.isFinite(Number(page)) ? Math.max(1, Math.trunc(Number(page))) : 1;
  const parsedSize = Number.isFinite(Number(pageSize))
    ? Math.min(maxPageSize, Math.max(1, Math.trunc(Number(pageSize))))
    : 25;
  return { page: parsedPage, pageSize: parsedSize };
}

export function parseBoolean(value: unknown): boolean {
  return value === true || value === 'true' || value === '1' || value === 1;
}

export function parseId(value: unknown, label: string): number {
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isInteger(parsed) || parsed <= 0) throw badRequest(`${label} must be a positive integer`);
  return parsed;
}

