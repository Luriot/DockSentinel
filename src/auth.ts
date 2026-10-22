import { createHash, randomBytes } from 'node:crypto';
import type { Db } from './db/index.ts';
import { nowIso } from './util/time.ts';

export const SESSION_COOKIE = 'ds_session';
export const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface AuthUser {
  id: number;
  username: string;
}

export interface SessionContext {
  user: AuthUser;
  csrfToken: string;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function getUser(db: Db): AuthUser | null {
  const row = db.get<{ id: number; username: string }>('SELECT id, username FROM users WHERE id = 1');
  return row ?? null;
}

export function setCredentials(db: Db, username: string, passwordHash: string): void {
  const now = nowIso();
  db.run(
    `INSERT INTO users (id, username, password_hash, created_at, updated_at) VALUES (1, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash,
       updated_at = excluded.updated_at`,
    [username, passwordHash, now, now],
  );
}

export function getPasswordHash(db: Db): string | null {
  return db.get<{ password_hash: string }>('SELECT password_hash FROM users WHERE id = 1')?.password_hash ?? null;
}

export function createSession(
  db: Db,
  userId: number,
  meta: { ip?: string | null; userAgent?: string | null },
): { token: string; csrfToken: string; expiresAt: string } {
  const token = randomBytes(32).toString('base64url');
  const csrfToken = randomBytes(32).toString('base64url');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS).toISOString();
  db.run(
    `INSERT INTO sessions (token_hash, csrf_token, user_id, created_at, expires_at, last_seen_at, user_agent, ip)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      hashToken(token),
      csrfToken,
      userId,
      now.toISOString(),
      expiresAt,
      now.toISOString(),
      (meta.userAgent ?? '').slice(0, 300) || null,
      (meta.ip ?? '').slice(0, 64) || null,
    ],
  );
  return { token, csrfToken, expiresAt };
}

export function resolveSession(db: Db, token: string | undefined | null): SessionContext | null {
  if (!token || token.length < 20) return null;
  const tokenHash = hashToken(token);
  const row = db.get<{
    csrf_token: string;
    expires_at: string;
    last_seen_at: string;
    id: number;
    username: string;
  }>(
    `SELECT s.csrf_token, s.expires_at, s.last_seen_at, u.id, u.username
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?`,
    [tokenHash],
  );
  if (!row) return null;
  if (Date.parse(row.expires_at) <= Date.now()) {
    db.run('DELETE FROM sessions WHERE token_hash = ?', [tokenHash]);
    return null;
  }
  // Sliding expiry, written at most every five minutes to avoid a write per request.
  if (Date.now() - Date.parse(row.last_seen_at) > 5 * 60_000) {
    db.run('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?', [nowIso(), tokenHash]);
  }
  return { user: { id: row.id, username: row.username }, csrfToken: row.csrf_token };
}

export function deleteSession(db: Db, token: string | undefined | null): void {
  if (!token) return;
  db.run('DELETE FROM sessions WHERE token_hash = ?', [hashToken(token)]);
}

export function deleteAllSessions(db: Db): void {
  db.run('DELETE FROM sessions');
}

export function deleteOtherSessions(db: Db, keepToken: string | undefined | null): void {
  if (!keepToken) {
    deleteAllSessions(db);
    return;
  }
  db.run('DELETE FROM sessions WHERE token_hash <> ?', [hashToken(keepToken)]);
}
