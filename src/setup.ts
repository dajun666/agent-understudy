// `understudy setup`: an interactive first run. Asks what to protect, picks and pulls models, collects the
// person's own names, and prints how to connect each agent. There is nothing to start afterwards: each agent
// session runs its own engine. Writes only ~/.agent-understudy/config.json;
// host configs (~/.claude, ~/.codex, opencode.json) are never touched, the steps are printed instead.
import * as p from '@clack/prompts';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig, saveConfig, type Config } from './config.ts';
import type { Label } from './core/types.ts';

const ROOT = path.resolve(import.meta.dirname, '..');
const SIDECAR = path.join(ROOT, 'sidecar');
const PYTHON = path.join(SIDECAR, '.venv/bin/python');
const PII: Label[] = ['PERSON', 'EMAIL', 'PHONE', 'ADDRESS', 'ACCOUNT', 'ID', 'IP'];

export interface ModelInfo { id: string; size: string; gb: number; note: string; license: string }
export const MODELS: ModelInfo[] = [
  { id: 'masker', size: '0.56 GB', gb: 0.56, license: 'Apache-2.0', note: 'fast; adds names the other misses, low precision on tool output' },
  { id: 'privacy-filter', size: '2.8 GB', gb: 2.8, license: 'Apache-2.0', note: 'strongest single model; also finds generic secrets' },
  { id: 'gliner-pii', size: '1.2 GB', gb: 1.2, license: 'NVIDIA Open Model License', note: 'slowest; small gain in the benchmark' },
  { id: 'piiranha', size: '1.1 GB', gb: 1.1, license: 'CC-BY-NC-ND-4.0, non-commercial', note: 'weakest on real sessions' },
];

export type Preset = 'pair' | 'privacy-filter' | 'masker' | 'none' | 'custom';
export const PRESETS: Record<Exclude<Preset, 'custom'>, string[]> = {
  pair: ['masker', 'privacy-filter'], 'privacy-filter': ['privacy-filter'], masker: ['masker'], none: [],
};

/** What fits: the pair needs ~3.5 GB on top of the agent and editor, so it wants a 16 GB machine. */
export function recommendedPreset(ramGb: number, names: boolean, addresses: boolean): Exclude<Preset, 'custom'> {
  if (!names && !addresses) return 'none';
  if (ramGb >= 15) return 'pair';
  if (ramGb >= 11) return 'privacy-filter';
  return 'masker';
}

export interface Answers {
  names: boolean; addresses: boolean; models: string[]; knownNames: string[];
  style: 'surrogate' | 'numbered' | 'token';
}

/** The config.json patch for a set of answers. Explicit per-label placeholder choices for secrets are kept. */
export function configPatch(a: Answers, current: Pick<Config, 'placeholders'>): Record<string, unknown> {
  const placeholders: Record<string, string> = { ...current.placeholders };
  for (const l of PII) {
    if (a.style === 'surrogate') delete placeholders[l];
    else placeholders[l] = a.style;
  }
  return { names: a.names, addresses: a.addresses, models: a.models, knownNames: [...new Set(a.knownNames)], placeholders };
}

/** Who this machine says you are: candidates for knownNames, never added without asking. */
export function identityCandidates(): Array<{ value: string; from: string }> {
  const out: Array<{ value: string; from: string }> = [];
  const add = (value: string | undefined, from: string) => {
    const v = value?.trim();
    if (v && v.length >= 2 && !out.some((o) => o.value.toLowerCase() === v.toLowerCase())) out.push({ value: v, from });
  };
  const git = (key: string) => spawnSync('git', ['config', '--global', key], { encoding: 'utf8' }).stdout?.trim();
  add(git('user.name'), 'git user.name');
  const email = git('user.email');
  if (email && !/noreply/i.test(email)) add(email.split('@')[0], 'git user.email');
  if (process.platform === 'darwin') add(spawnSync('id', ['-F'], { encoding: 'utf8' }).stdout, 'account full name');
  const user = os.userInfo().username;
  if (!['root', 'user', 'admin', 'ubuntu'].includes(user)) add(user, 'login name');
  return out;
}

function onPath(cmd: string): boolean {
  return spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmd], { stdio: 'ignore' }).status === 0;
}

function modelStatus(): Record<string, { pulled: boolean }> | undefined {
  if (!existsSync(PYTHON)) return undefined;
  const r = spawnSync(PYTHON, ['-c', 'import server, json; print(json.dumps(server.status()))'], { cwd: SIDECAR, encoding: 'utf8' });
  try { return r.status === 0 ? JSON.parse(r.stdout) : undefined; } catch { return undefined; }
}

/** Runs a command quietly behind a spinner; the last lines of its output are shown only if it fails. */
function quiet(cmd: string, args: string[], cwd: string): Promise<{ ok: boolean; tail: string }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let buf = '';
    const keep = (b: Buffer) => { buf = (buf + b.toString()).slice(-4000); };
    child.stdout.on('data', keep);
    child.stderr.on('data', keep);
    child.on('error', (e) => resolve({ ok: false, tail: e.message }));
    child.on('close', (code) => resolve({ ok: code === 0, tail: buf.trim().split('\n').slice(-6).join('\n') }));
  });
}

export function hostSteps(host: string): string {
  const ocPlugin = path.join(ROOT, 'hooks/opencode/agent-understudy.ts');
  const ocTui = path.join(ROOT, 'hooks/opencode/agent-understudy-tui.tsx');
  switch (host) {
    case 'claude':
      return [
        'Install the plugin once, inside Claude Code (each session then starts its own engine):',
        `  /plugin marketplace add ${ROOT}`,
        '  /plugin install agent-understudy@agent-understudy',
        'Then just run `claude`. Optional, to route the whole request through the engine too:',
        '  understudy run claude',
      ].join('\n');
    case 'codex':
      return [
        'Launch it through understudy (its own engine for that run; a plain `codex` is not protected):',
        '  understudy run codex',
        'Optional plugin (masked secret prompt), then trust its hooks once in /hooks:',
        `  codex plugin marketplace add ${ROOT}`,
        '  codex plugin add agent-understudy',
      ].join('\n');
    case 'opencode':
      return [
        'Add to opencode.json (the engine runs inside opencode):',
        `  { "plugin": ["file://${ocPlugin}"] }`,
        'Optional, masked secret prompt inside the TUI — add to tui.json:',
        `  { "plugin": ["file://${ocTui}"] }`,
      ].join('\n');
    default: return '';
  }
}

function bail<T>(v: T): Exclude<T, symbol> {
  if (p.isCancel(v)) { p.cancel('Setup cancelled. Nothing was changed.'); process.exit(0); }
  return v as Exclude<T, symbol>;
}

export async function setup() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('setup is interactive; run it in a terminal');
  const c = loadConfig();
  const ramGb = Math.round(os.totalmem() / 2 ** 30);

  p.intro(' Understudy setup ');
  p.note([
    'Understudy swaps your secrets and personal data for stand-ins before an agent\'s request leaves',
    'this machine, and swaps the real values back in when the answer returns.',
    '',
    'API keys, passwords, emails, phone numbers, card and ID numbers are always protected.',
  ].join('\n'), 'Welcome');

  // 1. What to protect
  const extra = bail(await p.multiselect({
    message: 'Also protect…',
    options: [
      { value: 'names', label: 'People\'s names', hint: 'needs a local model; misses handles and bare surnames' },
      { value: 'addresses', label: 'Postal addresses', hint: 'needs a local model' },
    ],
    initialValues: [...(c.names ? ['names'] : []), ...(c.addresses ? ['addresses'] : [])],
    required: false,
  })) as string[];
  const names = extra.includes('names');
  const addresses = extra.includes('addresses');

  // 2. Models
  const rec = recommendedPreset(ramGb, names, addresses);
  const label = (k: Exclude<Preset, 'custom'>, text: string) => (k === rec ? `${text}  (recommended for ${ramGb} GB)` : text);
  const preset = bail(await p.select<Preset>({
    message: 'Which local models should vote?',
    initialValue: rec,
    options: [
      { value: 'pair', label: label('pair', 'masker + privacy-filter'), hint: '~3.5 GB RAM, best in the benchmark' },
      { value: 'privacy-filter', label: label('privacy-filter', 'privacy-filter'), hint: '2.8 GB' },
      { value: 'masker', label: label('masker', 'masker'), hint: '0.56 GB, fastest, least precise' },
      { value: 'none', label: label('none', 'none — rules only'), hint: names || addresses ? 'names and addresses will not be found' : 'no model memory' },
      { value: 'custom', label: 'choose…' },
    ],
  }));
  let models = preset === 'custom'
    ? bail(await p.multiselect({
      message: 'Models (space to toggle)',
      options: MODELS.map((m) => ({ value: m.id, label: `${m.id}  ${m.size}`, hint: `${m.note}; ${m.license}` })),
      initialValues: c.models,
      required: false,
    })) as string[]
    : PRESETS[preset];
  const gb = models.reduce((s, id) => s + (MODELS.find((m) => m.id === id)?.gb ?? 0), 0);
  if (gb > ramGb / 3) p.log.warn(`These models take ~${gb.toFixed(1)} GB of ${ramGb} GB RAM; the machine may swap.`);

  // 2b. Sidecar environment and weights
  if (models.length) {
    if (!existsSync(PYTHON)) {
      if (!onPath('uv')) {
        p.log.warn('The model sidecar needs uv (https://docs.astral.sh/uv/). Install it, then run `understudy setup` again.\n' +
          'Continuing with rules only for now.');
        models = [];
      } else if (bail(await p.confirm({ message: 'Install the model sidecar? (Python packages into sidecar/.venv, ~2 GB)' }))) {
        const s = p.spinner();
        s.start('Installing the sidecar (uv sync)');
        const r = await quiet('uv', ['sync'], SIDECAR);
        if (r.ok) s.stop('Sidecar installed');
        else { s.error('Sidecar install failed'); p.log.error(r.tail); models = []; }
      } else models = [];
    }
    const st = models.length ? modelStatus() : undefined;
    const missing = models.filter((id) => !st?.[id]?.pulled);
    for (const id of missing) {
      const m = MODELS.find((x) => x.id === id)!;
      if (!bail(await p.confirm({ message: `Download ${id} (${m.size}) now?` }))) { models = models.filter((x) => x !== id); continue; }
      const s = p.spinner();
      s.start(`Downloading ${id} (${m.size})`);
      const r = await quiet(PYTHON, ['-c', `import server; server.pull(server.MODELS[${JSON.stringify(id)}])`], SIDECAR);
      if (r.ok) s.stop(`${id} ready`);
      else { s.error(`${id} download failed`); p.log.error(r.tail); models = models.filter((x) => x !== id); }
    }
  }

  // 3. Your own names
  let knownNames = [...c.knownNames];
  if (names) {
    const cands = identityCandidates().filter((x) => !knownNames.some((k) => k.toLowerCase() === x.value.toLowerCase()));
    p.log.info('Models miss usernames and handles. Names listed here are replaced everywhere, always.');
    if (cands.length) {
      const picked = bail(await p.multiselect({
        message: 'This machine knows you as… (pick the ones to hide)',
        options: cands.map((x) => ({ value: x.value, label: x.value, hint: x.from })),
        required: false,
      })) as string[];
      knownNames.push(...picked);
    }
    const more = bail(await p.text({
      message: 'Other names or handles to always hide (comma-separated, optional)',
      placeholder: 'e.g. Jane Roe, janeroe42',
      initialValue: '',
    }));
    knownNames.push(...String(more ?? '').split(',').map((s) => s.trim()).filter(Boolean));
    if (knownNames.length) p.log.info(`Always hidden: ${knownNames.join(', ')}`);
  }

  // 4. Stand-in style
  const current = c.placeholders.PERSON ?? 'surrogate';
  const style = bail(await p.select<Answers['style']>({
    message: 'What should the model see instead of your personal data?',
    initialValue: current,
    options: [
      { value: 'surrogate', label: 'Realistic stand-ins', hint: 'Maria Santos → Rubie Cremin; the model can still reason about it' },
      { value: 'numbered', label: 'Labels', hint: 'Maria Santos → Person A' },
      { value: 'token', label: 'Opaque tokens', hint: 'Maria Santos → RDX_PERSON_5cc16aa867' },
    ],
  }));

  // 5. Save
  const patch = configPatch({ names, addresses, models, knownNames, style }, c);
  p.note([
    `names        ${names ? 'on' : 'off'}`,
    `addresses    ${addresses ? 'on' : 'off'}`,
    `models       ${models.join(', ') || 'none (rules only)'}`,
    `always hide  ${(patch.knownNames as string[]).join(', ') || '—'}`,
    `stand-ins    ${({ surrogate: 'realistic', numbered: 'labels (Person A)', token: 'opaque tokens' } as const)[style]}`,
  ].join('\n'), 'Your settings');
  if (!bail(await p.confirm({ message: `Save to ${path.join(c.home, 'config.json')}?` }))) { p.cancel('Nothing saved.'); return; }
  saveConfig(patch, c.home);
  p.log.success('Saved');

  // 6. Connect agents
  const found = ['claude', 'codex', 'opencode'].filter(onPath);
  const hosts = bail(await p.multiselect({
    message: 'Which agents do you use?',
    options: [
      { value: 'claude', label: 'Claude Code', hint: onPath('claude') ? 'found' : 'not found' },
      { value: 'codex', label: 'Codex', hint: onPath('codex') ? 'found' : 'not found' },
      { value: 'opencode', label: 'opencode', hint: onPath('opencode') ? 'found' : 'not found' },
    ],
    initialValues: found,
    required: false,
  })) as string[];
  for (const h of hosts) p.note(hostSteps(h), `Connect ${h}`);

  // 7. PATH: the plugins start engines with `agent-understudy`.
  if (!onPath('agent-understudy') && hosts.some((h) => h !== 'opencode')) {
    p.note(`The plugins run \`agent-understudy\`. Put it on your PATH once:\n  (cd ${ROOT} && npm link)`, 'One more step');
  }

  p.outro('Done. Nothing to start: each agent session runs its own engine. `understudy setup` runs this again.');
}
