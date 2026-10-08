// The gateway's control API hands out real values (restore, credentials), so local callers must
// present a token from a 0600 file only this user can read.
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import path from 'node:path';

export function apiTokenPath(home: string) { return path.join(home, 'api.token'); }

export function apiToken(home: string): string {
  const f = apiTokenPath(home);
  if (!existsSync(f)) {
    mkdirSync(home, { recursive: true, mode: 0o700 });
    writeFileSync(f, randomBytes(24).toString('hex'), { mode: 0o600 });
  }
  chmodSync(f, 0o600);
  return readFileSync(f, 'utf8').trim();
}
