/**
 * Emergency administrator password reset for a local instance.
 *
 * Preferred (non-interactive, useful inside a container):
 *   DOCKSENTINEL_NEW_PASSWORD='a-long-password' node scripts/reset-password.ts
 *
 * Interactive mode asks twice and warns that input is visible on the terminal:
 *   node scripts/reset-password.ts
 */
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { loadConfig } from '../src/config.ts';
import { Db } from '../src/db/index.ts';
import { deleteAllSessions, getUser, setCredentials } from '../src/auth.ts';
import { hashPassword, validatePassword } from '../src/passwords.ts';

async function promptPassword(): Promise<string> {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    stdout.write('Note: the password is visible while typing.\n');
    const first = await rl.question('New password: ');
    const second = await rl.question('Repeat new password: ');
    if (first !== second) throw new Error('Passwords do not match');
    return first;
  } finally {
    rl.close();
  }
}

async function main(): Promise<void> {
  const config = loadConfig();
  const db = Db.open(config.dbPath);
  try {
    const user = getUser(db);
    if (!user) {
      throw new Error('No administrator exists yet. Start DockSentinel and complete first-run setup instead.');
    }
    const password = process.env.DOCKSENTINEL_NEW_PASSWORD ?? (await promptPassword());
    const problem = validatePassword(password);
    if (problem) throw new Error(problem);

    setCredentials(db, user.username, await hashPassword(password));
    deleteAllSessions(db);
    console.log(`Password reset for "${user.username}". All sessions were invalidated.`);
  } finally {
    db.close();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
