import { DatabaseSync as SqliteDatabase } from 'node:sqlite';
import { MIGRATIONS, SCHEMA_VERSION } from './migrations.ts';

export type SqlValue = string | number | bigint | null | Uint8Array;
export type SqlParams = readonly SqlValue[] | Record<string, SqlValue>;

interface BindableStatement {
  all(...params: SqlValue[]): unknown[];
  all(params: Record<string, SqlValue>): unknown[];
  get(...params: SqlValue[]): unknown;
  get(params: Record<string, SqlValue>): unknown;
  run(...params: SqlValue[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  run(params: Record<string, SqlValue>): { changes: number | bigint; lastInsertRowid: number | bigint };
}

function bind(params: SqlParams | undefined): SqlValue[] | Record<string, SqlValue> {
  if (params === undefined) return [];
  if (Array.isArray(params)) return [...(params as readonly SqlValue[])];
  return params as Record<string, SqlValue>;
}

function callAll<T>(statement: BindableStatement, params: SqlParams | undefined): T[] {
  const bound = bind(params);
  return (Array.isArray(bound) ? statement.all(...bound) : statement.all(bound)) as T[];
}

function callGet<T>(statement: BindableStatement, params: SqlParams | undefined): T | undefined {
  const bound = bind(params);
  return (Array.isArray(bound) ? statement.get(...bound) : statement.get(bound)) as T | undefined;
}

function callRun(
  statement: BindableStatement,
  params: SqlParams | undefined,
): { changes: number; lastInsertRowid: number } {
  const bound = bind(params);
  const result = Array.isArray(bound) ? statement.run(...bound) : statement.run(bound);
  return { changes: Number(result.changes), lastInsertRowid: Number(result.lastInsertRowid) };
}

export class Db {
  readonly raw: SqliteDatabase;
  private depth = 0;

  constructor(path: string) {
    this.raw = new SqliteDatabase(path, { timeout: 5000 });
    this.raw.exec('PRAGMA journal_mode = WAL');
    this.raw.exec('PRAGMA synchronous = NORMAL');
    this.raw.exec('PRAGMA foreign_keys = ON');
    this.raw.exec('PRAGMA busy_timeout = 5000');
    this.raw.exec('PRAGMA temp_store = MEMORY');
    this.raw.exec('PRAGMA cache_size = -16000');
  }

  static open(path: string): Db {
    const db = new Db(path);
    db.migrate();
    return db;
  }

  migrate(): number {
    this.raw.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
      ) STRICT;
    `);
    const applied = new Set(
      this.all<{ version: number }>('SELECT version FROM schema_migrations ORDER BY version').map((row) => row.version),
    );
    for (const migration of MIGRATIONS) {
      if (applied.has(migration.version)) continue;
      this.transaction(() => {
        this.raw.exec(migration.sql);
        this.run('INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)', [
          migration.version,
          migration.name,
          new Date().toISOString(),
        ]);
      });
    }
    const current = this.all<{ version: number }>('SELECT MAX(version) AS version FROM schema_migrations')[0]?.version;
    if (typeof current === 'number' && current > SCHEMA_VERSION) {
      throw new Error(`Database schema ${current} is newer than this build (${SCHEMA_VERSION})`);
    }
    return current ?? 0;
  }

  all<T>(sql: string, params?: SqlParams): T[] {
    return callAll<T>(this.raw.prepare(sql) as unknown as BindableStatement, params);
  }

  get<T>(sql: string, params?: SqlParams): T | undefined {
    return callGet<T>(this.raw.prepare(sql) as unknown as BindableStatement, params);
  }

  run(sql: string, params?: SqlParams): { changes: number; lastInsertRowid: number } {
    return callRun(this.raw.prepare(sql) as unknown as BindableStatement, params);
  }

  exec(sql: string): void {
    this.raw.exec(sql);
  }

  /**
   * Transactions are synchronous here on purpose: the single-threaded event loop owns all writes,
   * so no statement inside the callback can interleave with another writer.
   */
  transaction<T>(fn: () => T): T {
    if (this.depth > 0) {
      const savepoint = `sp_${this.depth}`;
      this.raw.exec(`SAVEPOINT ${savepoint}`);
      this.depth += 1;
      try {
        const result = fn();
        this.raw.exec(`RELEASE ${savepoint}`);
        return result;
      } catch (error) {
        this.raw.exec(`ROLLBACK TO ${savepoint}`);
        this.raw.exec(`RELEASE ${savepoint}`);
        throw error;
      } finally {
        this.depth -= 1;
      }
    }

    this.raw.exec('BEGIN IMMEDIATE');
    this.depth = 1;
    try {
      const result = fn();
      this.raw.exec('COMMIT');
      return result;
    } catch (error) {
      try {
        this.raw.exec('ROLLBACK');
      } catch {
        // A failed rollback means the transaction was already closed; surface the original error.
      }
      throw error;
    } finally {
      this.depth = 0;
    }
  }

  close(): void {
    this.raw.close();
  }
}
