// agent-understudy CLI.
import { spawn, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { loadConfig, saveConfig, type Config } from './config.ts';
import { buildRedactor } from './runtime.ts';
import { createGateway } from './gateway/server.ts';
import { SIDECAR_MODELS, SidecarClient, startSidecar } from './core/sidecar.ts';
import type { Finding } from './core/types.ts';
import { CredentialStore } from './core/credentials.ts';
import { shq } from './core/secret-input.ts';
import { gatewayClient } from './client.ts';

const HELP = `agent-understudy — keep secrets and PII out of coding-agent API traffic

  understudy setup                        guided first run: what to protect, models, your names, connecting agents
  understudy up [--no-sidecar]            optional: a long-lived gateway on a fixed port (and the model sidecar)
  understudy status                       gateway stats, active detectors, model status
  understudy models                       list detector models
  understudy models pull <id...>          download model weights
  understudy models use <id...>           choose which models vote (saved to config)
  understudy scan <file|->                show every detector's vote on a file, nothing is sent anywhere
  understudy check <file...>              find stand-ins left in files (use before committing); exit 1 if any
  understudy run <claude|codex> [args]    launch an agent with its own engine (no daemon; gone when it exits)
  understudy engine                       an engine for one agent session (the Claude Code mod starts it)
  understudy env <claude|codex|opencode>  print the settings that route a host through the gateway
  understudy mcp                          MCP server (stdio) with redact_* and secret_* tools
  understudy secret list                  credentials for this project (names only)
  understudy secret set NAME [--session]  type a credential (hidden); remembered for this project unless --session
  understudy secret rm NAME               forget a credential
  understudy secret env NAME...           print export lines (what agent commands eval; needs the gateway)

Config: ~/.agent-understudy/config.json (AGENT_UNDERSTUDY_HOME to relocate).`;

function gatewayUrl(c: Config) { return `http://127.0.0.1:${c.port}`; }

async function up(args: string[]) {
  const config = loadConfig();
  const log = (s: string) => process.stderr.write(`[agent-understudy] ${s}\n`);
  let sidecar: SidecarClient | undefined;
  let proc: ReturnType<typeof spawn> | undefined;
  let stopping = false;
  if (!args.includes('--no-sidecar') && config.models.length) {
    const health = await new SidecarClient(`http://127.0.0.1:${config.sidecarPort}`).health().catch(() => undefined);
    if (health) { sidecar = new SidecarClient(`http://127.0.0.1:${config.sidecarPort}`); log('sidecar already running'); }
    else {
      const sidecarLog = (s: string) => { if (!/warn|Loading weights/i.test(s)) log(`sidecar: ${s}`); };
      const launch = async (): Promise<void> => {
        log(`starting sidecar, preloading ${config.models.join(', ')} ...`);
        ({ client: sidecar, proc } = await startSidecar({ port: config.sidecarPort, preload: config.models, log: sidecarLog }));
        // Model votes go missing (not "no") while it is down; bring it back.
        proc.once('exit', (code, sig) => {
          if (stopping) return;
          log(`sidecar exited (${code ?? sig}); restarting in 2s`);
          setTimeout(() => launch().catch((e) => log(`sidecar restart failed: ${e.message}`)), 2000);
        });
      };
      await launch();
    }
  }
  const { redactor } = buildRedactor(config, { models: sidecar ? config.models : [], sidecar });
  const credentials = new CredentialStore(config.home);
  const { server } = createGateway({ config, redactor, sidecar, credentials, log });
  server.listen(config.port, '127.0.0.1', () => {
    log(`gateway on ${gatewayUrl(config)}  detectors: ${redactor.detectors.map((d) => d.id).join(', ')}  mode: ${redactor.policy.mode}`);
    log(`claude:  ANTHROPIC_BASE_URL=${gatewayUrl(config)}/anthropic`);
    log(`codex:   -c openai_base_url="${gatewayUrl(config)}/backend-api/codex"`);
  });
  const bye = () => { stopping = true; proc?.kill(); server.close(); process.exit(0); };
  process.on('SIGINT', bye);
  process.on('SIGTERM', bye);
}

async function status() {
  const c = loadConfig();
  const { readdirSync, readFileSync: read } = await import('node:fs');
  const g = await fetch(`${gatewayUrl(c)}/api/status`).then((r) => r.json()).catch(() => undefined);
  console.log(g ? `long-lived gateway (understudy up): ${gatewayUrl(c)}` : 'no long-lived gateway (none needed: each agent session runs its own engine)');
  const dir = path.join(c.home, 'engines');
  let engines: string[] = [];
  try { engines = readdirSync(dir).filter((f) => f.endsWith('.json')); } catch { /* none yet */ }
  const live = engines.map((f) => JSON.parse(read(path.join(dir, f), 'utf8')) as { url: string; pid: number })
    .filter((e) => { try { process.kill(e.pid, 0); return true; } catch { return false; } });
  console.log(`Claude Code session engines: ${live.length ? live.map((e) => e.url).join(', ') : 'none'}  (opencode and \`understudy run\` engines live inside their own process)`);
  const sc = await new SidecarClient(`http://127.0.0.1:${c.sidecarPort}`).health().catch(() => undefined);
  if (!c.models.length) console.log('models: none (rules only)');
  else if (!sc) console.log(`model sidecar: not running (starts when a session first needs ${c.models.join(', ')})`);
  else console.log(`model sidecar: up; ${c.models.map((m) => `${m} ${sc.models[m]?.loaded ? 'loaded' : sc.models[m]?.pulled ? 'loading' : 'not pulled'}`).join(', ')}`);
  if (g) console.log(JSON.stringify(g.stats));
}

async function models(args: string[]) {
  const c = loadConfig();
  const [sub, ...ids] = args;
  const sidecarDir = path.resolve(import.meta.dirname, '../sidecar');
  if (sub === 'pull') {
    for (const id of ids) {
      if (!SIDECAR_MODELS[id]) throw new Error(`unknown model ${id}; known: ${Object.keys(SIDECAR_MODELS).join(', ')}`);
      console.log(`pulling ${id} ...`);
      const r = spawnSync(path.join(sidecarDir, '.venv/bin/python'), ['-c', `import server; server.pull(server.MODELS[${JSON.stringify(id)}])`], { cwd: sidecarDir, stdio: 'inherit' });
      if (r.status !== 0) throw new Error(`pull ${id} failed`);
    }
    return;
  }
  if (sub === 'use') {
    for (const id of ids) if (!SIDECAR_MODELS[id]) throw new Error(`unknown model ${id}`);
    saveConfig({ models: ids });
    console.log(`voting models: ${ids.join(', ') || '(regex only)'} — restart the gateway to apply`);
    return;
  }
  const out = spawnSync(path.join(sidecarDir, '.venv/bin/python'), ['-c', 'import server, json; print(json.dumps(server.status()))'], { cwd: sidecarDir, encoding: 'utf8' });
  const st = out.status === 0 ? JSON.parse(out.stdout) : {};
  for (const id of Object.keys(SIDECAR_MODELS)) {
    const m = st[id] ?? {};
    console.log(`${c.models.includes(id) ? '●' : '○'} ${id.padEnd(15)} ${(m.pulled ? 'pulled' : 'not pulled').padEnd(11)} ${String(m.size ?? '').padEnd(8)} ${m.license ?? ''}\n    ${m.note ?? ''}`);
  }
  console.log('\n● = votes (understudy models use <id...>). gitleaks + patterns always vote.');
}

function mask(v: string) { return v.length <= 4 ? '****' : v.slice(0, 2) + '…' + v.slice(-2) + ` (${v.length})`; }

async function scan(args: string[]) {
  const c = loadConfig();
  const files = args.length ? args : ['-'];
  const health = await new SidecarClient(`http://127.0.0.1:${c.sidecarPort}`).health().catch(() => undefined);
  if (!health && c.models.length) console.error('(sidecar not running: model detectors skipped; start with `understudy up`)');
  const { redactor } = buildRedactor(c, { models: health ? c.models : [] });
  for (const file of files) {
    const text = readFileSync(file === '-' ? 0 : file, 'utf8');
    if (files.length > 1) console.log(`\n== ${file}`);
    const r = await redactor.scan(text);
    printFindings(r.findings, text);
    for (const e of r.errors) console.error(`detector ${e.detector} failed: ${e.error}`);
  }
}

async function secret(args: string[]) {
  const [sub, ...rest] = args;
  const gw = gatewayClient(loadConfig());
  const cwd = process.cwd();
  if (sub === 'list') {
    const { credentials } = await gw.post<{ credentials: Array<{ name: string; scope: string; project: string }> }>('/api/secret/list', { cwd });
    if (!credentials.length) { console.log('no credentials for this project'); return; }
    for (const c of credentials) console.log(`${c.name.padEnd(28)} ${c.scope.padEnd(8)} $AGENT_SECRET_${c.name}`);
    return;
  }
  if (sub === 'set') {
    const name = rest.find((a) => !a.startsWith('--'));
    if (!name) throw new Error('usage: understudy secret set NAME [--session]');
    const value = await readHidden(`${name}: `);
    const r = await gw.post('/api/secret/put', { cwd, name, value, scope: rest.includes('--session') ? 'session' : 'project' });
    console.log(`stored ${r.name} (${r.scope === 'project' ? `remembered for ${r.project}` : 'this session only'}); commands read $${r.env}`);
    return;
  }
  if (sub === 'rm') {
    const r = await gw.post('/api/secret/remove', { cwd, name: rest[0] });
    console.log(r.removed ? `removed ${rest[0]}` : `${rest[0]} not found`);
    process.exitCode = r.removed ? 0 : 1;
    return;
  }
  if (sub === 'env') {
    // Printed for `eval` by the command prefix the hooks add; values never appear in the command itself.
    // Output is eval'd by the hook prefix: on failure print shell that reports and fails, so && stops.
    const fail = (msg: string) => { process.stdout.write(`echo ${shq(`agent-understudy: ${msg}`)} >&2; false\n`); process.exitCode = 1; };
    let r: { env: Record<string, string>; missing: string[] };
    try { r = await gw.post('/api/secret/env', { cwd, names: rest }); } catch (e) { return fail((e as Error).message); }
    if (r.missing.length) return fail(`no credential ${r.missing.join(', ')} for this project (understudy secret list / secret set NAME)`);
    for (const [k, v] of Object.entries(r.env)) process.stdout.write(`export ${k}=${shq(v)}\n`);
    return;
  }
  throw new Error('usage: understudy secret list|set|rm|env');
}

/** Reads a line without echoing it (TTY), or one line of stdin when piped. */
async function readHidden(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    let s = '';
    for await (const c of process.stdin) s += c;
    return s.split('\n')[0]!.trim();
  }
  process.stderr.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let s = '';
    const onData = (b: Buffer) => {
      for (const ch of b.toString('utf8')) {
        if (ch === '\r' || ch === '\n') { done(); resolve(s); return; }
        if (ch === '\u0003') { done(); reject(new Error('cancelled')); return; }
        if (ch === '\u007f') { if (s) { s = s.slice(0, -1); process.stderr.write('\b \b'); } continue; }
        s += ch; process.stderr.write('•');
      }
    };
    const done = () => { process.stdin.off('data', onData); process.stdin.setRawMode(false); process.stdin.pause(); process.stderr.write('\n'); };
    process.stdin.on('data', onData);
  });
}

/** Stand-ins left in files that are about to be committed or shared. Reads the vault directly. */
async function check(files: string[]) {
  const { Vault } = await import('./core/vault.ts');
  const c = loadConfig();
  const vault = new Vault(c.home, { styles: c.placeholders });
  let bad = 0;
  for (const f of files) {
    const res = vault.residue(readFileSync(f, 'utf8'));
    if (res.length) { bad++; console.log(`${f}: ${res.map((r) => JSON.stringify(r)).join(', ')}`); }
  }
  if (bad) { console.log(`\n${bad} file(s) contain stand-ins. Restore them by hand or re-run the step with the gateway up.`); process.exitCode = 1; }
  else console.log('no stand-ins found');
}

function printFindings(findings: Finding[], text: string) {
  if (!findings.length) { console.log('no findings'); return; }
  for (const f of findings) {
    const line = text.slice(0, f.start).split('\n').length;
    console.log(`${f.redact ? 'REDACT' : 'keep  '} ${f.label.padEnd(8)} L${String(line).padEnd(5)} ${mask(f.value).padEnd(22)} votes ${f.votes}/${f.threshold}  ` +
      `by ${f.voters.map((v) => `${v.detector}${v.source ? `(${v.source})` : ''}:${v.score}`).join(' ')}` +
      (f.abstained.length ? `  silent: ${f.abstained.join(',')}` : ''));
  }
}

function env(host: string) {
  const c = loadConfig();
  const g = gatewayUrl(c);
  switch (host) {
    case 'claude':
      return `export ANTHROPIC_BASE_URL=${g}/anthropic
# Works with a Claude subscription login: only the base URL changes, the OAuth login is still used.
# Do not set ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN / apiKeyHelper for this.`;
    case 'codex':
      return `# per run:
codex -c openai_base_url="${g}/backend-api/codex" ...
# or permanently in ~/.codex/config.toml:
openai_base_url = "${g}/backend-api/codex"`;
    case 'opencode':
      return `# opencode with ChatGPT login ignores baseURL; use the plugin instead:
#   understudy install opencode
# API-key providers can point at the gateway in opencode.json:
#   "provider": { "anthropic": { "options": { "baseURL": "${g}/anthropic/v1" } },
#                 "openai":    { "options": { "baseURL": "${g}/openai/v1" } } }`;
    default: throw new Error('host must be claude, codex or opencode');
  }
}

/** understudy names|addresses [on|off] */
function toggle(what: 'names' | 'addresses', state?: string) {
  if (state === 'on' || state === 'off') {
    saveConfig({ [what]: state === 'on' });
    console.log(`${what}: ${state} — restart the gateway to apply`);
    const c = loadConfig();
    if (!c.names && !c.addresses && c.models.length) {
      console.log(`names and addresses are both off: models now only add generic secrets (privacy-filter). ` +
        `\`understudy models use\` with no ids runs regex only and frees their memory.`);
    }
    return;
  }
  if (state) throw new Error(`usage: agent-understudy ${what} [on|off]`);
  console.log(`${what}: ${loadConfig()[what] ? 'on' : 'off'}`);
}

/**
 * Launches an agent with its own engine: started here, on a random port, gone when the agent exits. No daemon.
 * The agent's model traffic goes through it, and its hooks and MCP server find it via AGENT_UNDERSTUDY_GATEWAY.
 */
async function run(args: string[]) {
  const [host, ...rest] = args;
  if (host !== 'claude' && host !== 'codex') throw new Error('run supports claude and codex (opencode runs its engine inside its plugin)');
  const c = loadConfig();
  const { appendFileSync } = await import('node:fs');
  const logFile = path.join(c.home, 'engine.log');
  // The agent owns the terminal: engine messages go to a file.
  const log = (s: string) => { try { appendFileSync(logFile, `${new Date().toISOString()} [${host} ${process.pid}] ${s}\n`, { mode: 0o600 }); } catch { /* best effort */ } };
  const { startEngine } = await import('./engine.ts');
  const engine = await startEngine({ config: c, log });
  log(`engine on ${engine.url}`);
  const [cmd, argv, extraEnv] = host === 'claude'
    ? ['claude', rest, { ANTHROPIC_BASE_URL: `${engine.url}/anthropic` }]
    : ['codex', ['-c', `openai_base_url="${engine.url}/backend-api/codex"`, ...rest], {}];
  const child = spawn(cmd, argv as string[], { stdio: 'inherit', env: { ...process.env, ...extraEnv, AGENT_UNDERSTUDY_GATEWAY: engine.url } });
  // Ctrl-C belongs to the agent (it shares our terminal and gets the signal itself).
  process.on('SIGINT', () => {});
  child.on('exit', async (code, signal) => {
    await engine.close();
    process.exit(code ?? (signal ? 1 : 0));
  });
}

export async function main(argv = process.argv.slice(2)) {
  const [cmd, ...args] = argv;
  switch (cmd) {
    case 'setup': return (await import('./setup.ts')).setup();
    case 'engine': return (await import('./engine.ts')).engineMain();
    case 'up': return up(args);
    case 'status': return status();
    case 'models': return models(args);
    case 'scan': return scan(args);
    case 'check': return check(args);
    case 'env': console.log(env(args[0])); return;
    case 'run': return run(args);
    case 'mcp': return (await import('./mcp/server.ts')).main();
    case 'secret': return secret(args);
    case 'names': case 'addresses': return toggle(cmd, args[0]);
    default: console.log(HELP);
  }
}
