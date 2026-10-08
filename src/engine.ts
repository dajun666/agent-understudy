// The engine: redaction, restore, credentials and the redacting proxy, for one agent session at a time.
//
// There is no daemon. Each agent gets its own engine for as long as it runs: opencode's plugin starts one
// inside opencode, the Claude Code mod starts `understudy engine` as a child of the session, and
// `understudy run codex` starts one in its own process. Engines listen on a random localhost port and share
// state through files: the vault (stand-ins stay the same across sessions), remembered credentials and
// session-credential fingerprints. Models live in one shared sidecar that starts on first need and exits
// when idle. `understudy up` still runs a long-lived engine on a fixed port for setups that want one.
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { loadConfig, type Config } from './config.ts';
import { CredentialStore } from './core/credentials.ts';
import { SidecarClient } from './core/sidecar.ts';
import { createGateway } from './gateway/server.ts';
import { buildRedactor } from './runtime.ts';

/** How long the shared sidecar stays up with no requests before it exits. */
export const SIDECAR_IDLE_SECONDS = 15 * 60;

/**
 * A client for the shared model sidecar, starting it (detached, idle-exiting) when nobody has yet. Requests
 * wait until it is ready rather than going out without model votes.
 */
export function sharedSidecar(config: Config, log: (s: string) => void = () => {}): SidecarClient {
  const url = `http://127.0.0.1:${config.sidecarPort}`;
  const ready = (async () => {
    const probe = new SidecarClient(url);
    if (await probe.health().then(() => true, () => false)) return;
    const dir = path.resolve(import.meta.dirname, '../sidecar');
    const py = path.join(dir, '.venv/bin/python');
    if (!existsSync(py)) throw new Error(`model sidecar not installed (run \`uv sync\` in ${dir}, or \`understudy setup\`)`);
    mkdirSync(config.home, { recursive: true, mode: 0o700 });
    const logFile = path.join(config.home, 'sidecar.log');
    const argv = [py, 'server.py', '--port', String(config.sidecarPort), '--idle-exit', String(SIDECAR_IDLE_SECONDS), '--preload', ...config.models];
    log(`starting the model sidecar (${config.models.join(', ')})`);
    // It serves every engine and outlives the one that started it, until it has been idle a while. Hosts end a
    // child together with its descendants (Claude Code does, for the session engine), so it must not be one:
    // a shell starts it in the background and exits, and it is reparented to init. Two engines starting it at
    // once is fine: the second one cannot bind the port and exits.
    const env = { ...process.env, TOKENIZERS_PARALLELISM: 'false' };
    if (process.platform === 'win32') {
      const out = openSync(logFile, 'a', 0o600);
      spawn(argv[0]!, argv.slice(1), { cwd: dir, detached: true, stdio: ['ignore', out, out], env }).unref();
    } else {
      spawn('/bin/sh', ['-c', 'log="$1"; shift; "$@" </dev/null >>"$log" 2>&1 &', 'sh', logFile, ...argv], { cwd: dir, detached: true, stdio: 'ignore', env }).unref();
    }
    const deadline = Date.now() + 600_000; // first load of big models can take minutes
    // Ready when every model is loaded, or can't be (not pulled, failed to load: its votes then go missing).
    const settled = (s?: { loaded: boolean; pulled: boolean; error: string | null }) => !s || s.loaded || !s.pulled || !!s.error;
    while (!(await probe.health().then((h) => config.models.every((m) => settled(h.models[m])), () => false))) {
      if (Date.now() > deadline) throw new Error('model sidecar did not come up; see sidecar.log');
      await new Promise((r) => setTimeout(r, 500));
    }
    log('model sidecar ready');
  })();
  ready.catch((e) => log(`model sidecar: ${(e as Error).message}`));
  return new SidecarClient(url, undefined, ready);
}

export interface Engine { url: string; port: number; close(): Promise<void> }

/** Starts an engine in this process on a random localhost port (or opts.port). */
export async function startEngine(opts: { config?: Config; port?: number; log?: (s: string) => void } = {}): Promise<Engine> {
  const config = opts.config ?? loadConfig();
  const log = opts.log ?? (() => {});
  const sidecar = config.models.length ? sharedSidecar(config, log) : undefined;
  const { redactor } = buildRedactor(config, { models: sidecar ? config.models : [], sidecar });
  const credentials = new CredentialStore(config.home);
  const { server } = createGateway({ config, redactor, sidecar, credentials, log });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port ?? 0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  // An engine must never keep its host's process alive on its own.
  server.unref();
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    close: () => new Promise<void>((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}

/** Where an engine started for an agent process announces itself, for that agent's other children (its MCP server). */
export function rendezvousFile(home: string, agentPid: number) { return path.join(home, 'engines', `${agentPid}.json`); }

/** The engine of the agent process `agentPid`, if one announced itself and is still up. */
export function engineFor(home: string, agentPid: number): string | undefined {
  try {
    const { url, pid } = JSON.parse(readFileSync(rendezvousFile(home, agentPid), 'utf8')) as { url: string; pid: number };
    process.kill(pid, 0); // throws when that engine is gone
    return url;
  } catch { return undefined; }
}

/**
 * `understudy engine`: an engine as a child of an agent (the Claude Code mod spawns it for the session).
 * Prints `{"url": ...}` on its first line, then runs until its parent goes away.
 */
export async function engineMain() {
  const parent = process.ppid;
  const config = loadConfig();
  const engine = await startEngine({ config, log: (s) => process.stderr.write(`[understudy] ${s}\n`) });
  // The agent's MCP server is a sibling: it finds this engine by the parent they share.
  const rv = rendezvousFile(config.home, parent);
  mkdirSync(path.dirname(rv), { recursive: true, mode: 0o700 });
  writeFileSync(rv, JSON.stringify({ url: engine.url, pid: process.pid }), { mode: 0o600 });
  process.on('exit', () => rmSync(rv, { force: true }));
  process.stdout.write(JSON.stringify({ url: engine.url }) + '\n');
  // Orphaned (the parent died without killing us): we are reparented, and leave too.
  setInterval(() => { if (process.ppid !== parent) process.exit(0); }, 2000);
  const bye = () => void engine.close().finally(() => process.exit(0));
  process.on('SIGTERM', bye);
  process.on('SIGINT', bye);
  process.on('SIGHUP', bye);
}
