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
import { loadConfig } from '../src/config.ts';
import { createBackup } from '../src/backup.ts';

const config = loadConfig();
const result = createBackup(config, process.argv[2]);
console.log(`Database backup written to ${result.databasePath}`);
if (result.keyPath) console.log(`Encryption key copied to ${result.keyPath}`);
else console.log('The secret key comes from DOCKSENTINEL_SECRET_KEY; back it up separately.');
console.log('Backups contain credentials and Docker endpoint TLS material. Store them encrypted.');
