/**
 * Creates a consistent snapshot of the DockSentinel database using SQLite's VACUUM INTO.
 *
 * Usage:
 *   npm run backup                      -> writes to <DATA_DIR>/backups
 *   npm run backup -- /path/to/folder   -> writes to an explicit folder
 *
 * The encryption key is copied next to the snapshot because TLS material and notification
 * credentials cannot be decrypted without it. Treat the output as a secret.
 */
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { loadConfig } from '../src/config.ts';
import { Db } from '../src/db/index.ts';

async function main(): Promise<void> {
  const config = loadConfig();
  const targetDir = resolve(process.argv[2] ?? join(config.dataDir, 'backups'));
  mkdirSync(targetDir, { recursive: true });

  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const target = join(targetDir, `docksentinel-${stamp}.db`);
  if (existsSync(target)) throw new Error(`Refusing to overwrite existing backup ${target}`);

  const db = Db.open(config.dbPath);
  try {
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    db.exec(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
  } finally {
    db.close();
  }

  const keyPath = join(config.dataDir, 'secret.key');
  let keyCopy: string | null = null;
  if (!process.env.DOCKSENTINEL_SECRET_KEY && existsSync(keyPath)) {
    keyCopy = join(targetDir, `secret-${stamp}.key`);
    copyFileSync(keyPath, keyCopy);
  }

  console.log(`Database backup written to ${target}`);
  if (keyCopy) console.log(`Encryption key copied to ${keyCopy}`);
  else console.log('The secret key comes from DOCKSENTINEL_SECRET_KEY; back it up separately.');
  console.log('Backups contain credentials and Docker endpoint TLS material. Store them encrypted.');
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
