// Project credentials: API keys the agent's commands need but the model must never see.
//
// The model asks for one by name (secret_request); the person types it into a masked dialog that the
// model never reads; commands get it as $AGENT_SECRET_<NAME>; any echo of the value is redacted to
// Hide(NAME) before it reaches the model. "Remember for this project" stores it encrypted, one file
// per project, under a key kept in the OS credential store (macOS Keychain, Linux Secret Service);
// without one, remembering fails closed and only this-session storage is offered.
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';

export const NAME_RE = /^[A-Z][A-Z0-9_]{1,63}$/;
export const envName = (name: string) => `AGENT_SECRET_${name}`;
export const refOf = (name: string) => `Hide(${name})`;

export function validateCredential(name: string, value: string) {
  if (!NAME_RE.test(name)) throw new Error('name must be UPPER_SNAKE_CASE, 2-64 characters (e.g. OPENROUTER_API_KEY)');
  if (/[\r\n]/.test(value)) throw new Error('value must be a single line');
  if (value.length < 8 || value.length > 8192) throw new Error('value must be 8-8192 characters');
}

/** A project is its git root (or the directory itself), by canonical path, so same-named repos don't share. */
export function projectOf(cwd: string): { root: string; id: string } {
  let root = cwd;
  const g = spawnSync('git', ['rev-parse', '--show-toplevel'], { cwd, encoding: 'utf8' });
  if (g.status === 0 && g.stdout.trim()) root = g.stdout.trim();
  try { root = realpathSync(root); } catch { /* keep as given */ }
  return { root, id: createHash('sha256').update(root).digest('hex').slice(0, 16) };
}

// ---- the vault key, kept in the OS credential store --------------------------------------------------

const SERVICE = 'agent-understudy';
const ACCOUNT = 'credentials-key';

/** Returns the 32-byte key, creating it on first use. Throws when no OS credential store is available. */
export function credentialsKey(create = true): Buffer {
  const fromEnv = process.env.AGENT_UNDERSTUDY_CREDENTIALS_KEY; // tests and headless setups
  if (fromEnv) return Buffer.from(fromEnv, 'hex');
  if (process.platform === 'darwin') {
    const r = spawnSync('security', ['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w'], { encoding: 'utf8' });
    if (r.status === 0 && r.stdout.trim()) return Buffer.from(r.stdout.trim(), 'hex');
    if (!create) throw new Error('no credentials key yet');
    const hex = randomBytes(32).toString('hex');
    // -U updates an existing item; the hex key is a one-time argument to the system tool.
    const w = spawnSync('security', ['add-generic-password', '-U', '-s', SERVICE, '-a', ACCOUNT, '-l', 'agent-understudy credentials key', '-w', hex]);
    if (w.status !== 0) throw new Error('could not store the credentials key in the macOS Keychain');
    return Buffer.from(hex, 'hex');
  }
  if (process.platform === 'linux') {
    const r = spawnSync('secret-tool', ['lookup', 'service', SERVICE, 'account', ACCOUNT], { encoding: 'utf8' });
    if (r.status === 0 && r.stdout.trim()) return Buffer.from(r.stdout.trim(), 'hex');
    if (r.error) throw new Error('no Secret Service (install libsecret-tools) — remembering credentials is unavailable; use this-session storage');
    if (!create) throw new Error('no credentials key yet');
    const hex = randomBytes(32).toString('hex');
    const w = spawnSync('secret-tool', ['store', '--label=agent-understudy credentials key', 'service', SERVICE, 'account', ACCOUNT], { input: hex });
    if (w.status !== 0) throw new Error('could not store the credentials key in the Secret Service');
    return Buffer.from(hex, 'hex');
  }
  throw new Error(`no supported OS credential store on ${process.platform}; use this-session storage`);
}

function seal(key: Buffer, s: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(s, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function open(key: Buffer, b64: string): string {
  const b = Buffer.from(b64, 'base64');
  const d = createDecipheriv('aes-256-gcm', key, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
}

// ---- the store ----------------------------------------------------------------------------------------

export interface CredentialInfo { name: string; scope: 'project' | 'session'; project: string; createdAt: string }

interface ProjectFile { root: string; entries: Record<string, { v: string; createdAt: string }> }

/**
 * Remembered credentials on disk (one encrypted file per project) plus this-session ones in memory.
 * The gateway owns the only instance, so hooks, the MCP server and the CLI all see the same set.
 */
export class CredentialStore {
  private readonly dir: string;
  private readonly session = new Map<string, Map<string, { value: string; createdAt: string; root: string }>>();
  private key?: Buffer;

  constructor(home: string) {
    this.dir = path.join(home, 'credentials');
  }

  private keyOrThrow(create: boolean): Buffer { return (this.key ??= credentialsKey(create)); }

  private file(id: string) { return path.join(this.dir, `${id}.json`); }

  private readProject(id: string): ProjectFile | undefined {
    const f = this.file(id);
    return existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) as ProjectFile : undefined;
  }

  // Session values die with the gateway, but agents' local history (opencode storage, codex rollouts) keeps raw
  // command output that is re-sent when a session resumes. A keyed fingerprint (HMAC + length, never the value)
  // outlives the gateway so such echoes are still recognised and redacted.
  private fpKeyCache?: Buffer;
  private fpKey(): Buffer {
    if (this.fpKeyCache) return this.fpKeyCache;
    const f = path.join(this.dir, 'fingerprint.key');
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (!existsSync(f)) writeFileSync(f, randomBytes(32).toString('hex'), { mode: 0o600 });
    return (this.fpKeyCache = Buffer.from(readFileSync(f, 'utf8').trim(), 'hex'));
  }
  fingerprintOf(value: string): string { return createHmac('sha256', this.fpKey()).update(value).digest('hex'); }
  private fpFile() { return path.join(this.dir, 'session-fingerprints.json'); }
  fingerprints(): Array<{ name: string; h: string; len: number; at: string }> {
    if (!existsSync(this.fpFile())) return [];
    const all = JSON.parse(readFileSync(this.fpFile(), 'utf8')) as Array<{ name: string; h: string; len: number; at: string }>;
    return all.filter((f) => Date.now() - Date.parse(f.at) < 30 * 86_400_000);
  }
  private addFingerprint(name: string, value: string) {
    const list = this.fingerprints().filter((f) => !(f.name === name && f.h === this.fingerprintOf(value)));
    list.push({ name, h: this.fingerprintOf(value), len: value.length, at: new Date().toISOString() });
    writeFileSync(this.fpFile(), JSON.stringify(list), { mode: 0o600 });
  }

  set(cwd: string, name: string, value: string, scope: 'project' | 'session'): CredentialInfo {
    validateCredential(name, value);
    const { root, id } = projectOf(cwd);
    const createdAt = new Date().toISOString();
    if (scope === 'session') {
      this.addFingerprint(name, value);
      if (!this.session.has(id)) this.session.set(id, new Map());
      this.session.get(id)!.set(name, { value, createdAt, root });
    } else {
      const key = this.keyOrThrow(true);
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      const pf = this.readProject(id) ?? { root, entries: {} };
      pf.entries[name] = { v: seal(key, value), createdAt };
      const tmp = this.file(id) + '.tmp';
      writeFileSync(tmp, JSON.stringify(pf, null, 2), { mode: 0o600 });
      renameSync(tmp, this.file(id));
      chmodSync(this.file(id), 0o600);
      this.session.get(id)?.delete(name); // a remembered value supersedes a session one
    }
    return { name, scope, project: root, createdAt };
  }

  /** Names (never values) visible from cwd. */
  list(cwd: string): CredentialInfo[] {
    const { root, id } = projectOf(cwd);
    const out: CredentialInfo[] = [];
    for (const [name, e] of Object.entries(this.readProject(id)?.entries ?? {})) out.push({ name, scope: 'project', project: root, createdAt: e.createdAt });
    for (const [name, e] of this.session.get(id) ?? []) if (!out.some((o) => o.name === name)) out.push({ name, scope: 'session', project: root, createdAt: e.createdAt });
    return out.sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Values for commands run in cwd. Only the names asked for. */
  values(cwd: string, names: string[]): Record<string, string> {
    const { id } = projectOf(cwd);
    const out: Record<string, string> = {};
    const pf = this.readProject(id);
    for (const n of names) {
      const s = this.session.get(id)?.get(n);
      if (s) { out[n] = s.value; continue; }
      const e = pf?.entries[n];
      if (e) out[n] = open(this.keyOrThrow(false), e.v);
    }
    return out;
  }

  remove(cwd: string, name: string): boolean {
    const { id } = projectOf(cwd);
    let hit = this.session.get(id)?.delete(name) ?? false;
    if (existsSync(this.fpFile())) writeFileSync(this.fpFile(), JSON.stringify(this.fingerprints().filter((f) => f.name !== name)), { mode: 0o600 });
    const pf = this.readProject(id);
    if (pf?.entries[name]) {
      delete pf.entries[name];
      if (Object.keys(pf.entries).length) writeFileSync(this.file(id), JSON.stringify(pf, null, 2), { mode: 0o600 });
      else rmSync(this.file(id));
      hit = true;
    }
    return hit;
  }

  /** Changes whenever another engine stores or removes a credential (files in the credentials dir). */
  stamp(): string {
    if (!existsSync(this.dir)) return '';
    return readdirSync(this.dir).sort().map((f) => { const s = statSync(path.join(this.dir, f)); return `${f}:${s.size}:${s.mtimeMs}`; }).join('|');
  }

  /** Every value this machine knows (all projects), for redaction: redacting too widely is safe. */
  allValues(): Array<{ name: string; value: string }> {
    const out: Array<{ name: string; value: string }> = [];
    for (const m of this.session.values()) for (const [name, e] of m) out.push({ name, value: e.value });
    if (!existsSync(this.dir)) return out;
    const files = readdirSync(this.dir).filter((f) => f.endsWith('.json'));
    if (!files.length) return out;
    let key: Buffer;
    try { key = this.keyOrThrow(false); } catch { return out; }
    for (const f of files) {
      const pf = JSON.parse(readFileSync(path.join(this.dir, f), 'utf8')) as ProjectFile;
      for (const [name, e] of Object.entries(pf.entries)) {
        try { out.push({ name, value: open(key, e.v) }); } catch { /* a file sealed under another key */ }
      }
    }
    return out;
  }
}
