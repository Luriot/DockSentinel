import { createWriteStream, mkdirSync, readdirSync, unlinkSync, type WriteStream } from 'node:fs';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import pino from 'pino';

export type Logger = pino.Logger;

export interface LoggerOptions {
  /** Directory for dated text log files; omit to log to stdout only. */
  logDir?: string;
  /** Days of log files to keep (one file per local day). */
  retentionDays?: number;
}

/** Local calendar day, sortable as `YYYY-MM-DD` (the container timezone applies). */
function dayStamp(date: Date): string {
  return date.toLocaleDateString('sv-SE');
}

/** Deletes dated log files older than the retention window. Best effort. */
export function pruneLogFiles(dir: string, retentionDays: number, now: Date = new Date()): number {
  const cutoff = dayStamp(new Date(now.getTime() - retentionDays * 86_400_000));
  let removed = 0;
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return 0;
  }
  for (const name of names) {
    const match = /^docksentinel-(\d{4}-\d{2}-\d{2})\.log$/.exec(name);
    if (!match?.[1] || match[1] >= cutoff) continue;
    try {
      unlinkSync(join(dir, name));
      removed += 1;
    } catch {
      // A file that cannot be removed is retried on the next rotation.
    }
  }
  return removed;
}

/**
 * Writes one text file per local day (`docksentinel-YYYY-MM-DD.log`) and prunes old ones.
 * Log I/O failures are swallowed on purpose: logging must never take the application down.
 */
export function createDailyLogStream(
  dir: string,
  retentionDays: number,
  now: () => Date = () => new Date(),
): Writable {
  let file: WriteStream | null = null;
  let day = '';

  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    pruneLogFiles(dir, retentionDays, now());
  } catch {
    // An unwritable log directory only disables file logging.
    return new Writable({
      write(_chunk, _encoding, callback) {
        callback();
      },
    });
  }

  const open = (nextDay: string): void => {
    file?.end();
    file = createWriteStream(join(dir, `docksentinel-${nextDay}.log`), { flags: 'a', mode: 0o600 });
    file.on('error', () => {
      file = null;
    });
  };

  return new Writable({
    write(chunk, _encoding, callback) {
      try {
        const nextDay = dayStamp(now());
        if (nextDay !== day) {
          day = nextDay;
          open(nextDay);
          pruneLogFiles(dir, retentionDays, now());
        }
        file?.write(chunk);
      } catch {
        // Never propagate log-write failures.
      }
      callback();
    },
    final(callback) {
      if (file) file.end(() => callback());
      else callback();
    },
  });
}

export function createLogger(level: string, options: LoggerOptions = {}): Logger {
  const pinoOptions = {
    level,
    base: undefined,
    timestamp: pino.stdTimeFunctions.isoTime,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'res.headers["set-cookie"]',
        'password',
        'token',
        'setupToken',
        'secret',
        '*.password',
        '*.token',
        '*.secret',
      ],
      censor: '[redacted]',
    },
  };

  if (!options.logDir) return pino(pinoOptions);

  const fileStream = createDailyLogStream(options.logDir, options.retentionDays ?? 14);
  // The logger level does the filtering; entry levels must not drop debug records.
  return pino(
    pinoOptions,
    pino.multistream([
      { level: 'trace', stream: process.stdout },
      { level: 'trace', stream: fileStream },
    ]),
  );
}
