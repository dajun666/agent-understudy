import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { CHOICES, cleared, initialState, masked, onKey, onPaste, type Key, type MaskState } from '../hooks/opencode/masked-input.ts';
import { answer, askId, askOpen, askViaTui, claim, putSecret, readAsk } from '../hooks/opencode/secret-handoff.ts';

const VALUE = 'sk-or-v1-' + randomBytes(20).toString('hex');

// ---------------------------------------------------------------------------------------------
// Masked field

const k = (name: string, sequence = name, mods: Partial<Key> = {}): Key => ({ name, sequence, ...mods });
function typeAll(s: MaskState, text: string) {
  for (const ch of text) s = onKey(s, ch === ' ' ? k('space', ' ') : k(ch.toLowerCase(), ch, { shift: ch !== ch.toLowerCase() })).state;
  return s;
}

test('masked field: typing keeps the value and only bullets are drawn', () => {
  const s = typeAll(initialState(), 'Ab3 x-Y_z');
  assert.equal(s.value, 'Ab3 x-Y_z');
  assert.equal(masked(s), '•'.repeat(9));
  assert.ok(!masked(s).includes('A'));
  assert.equal(masked({ ...s, value: 'x'.repeat(100) }, 10), '•'.repeat(9) + '…');
});

test('masked field: unbound control keys and modified keys do not land in the value', () => {
  let s = typeAll(initialState(), 'abc');
  for (const key of [k('f1', '\x1bOP'), k('x', 'x', { ctrl: true }), k('v', 'v', { meta: true }), k('home', '\x1b[H'), k('delete', '\x1b[3~')]) {
    s = onKey(s, key).state;
  }
  assert.equal(s.value, 'abc');
});

test('masked field: backspace removes one character; ctrl/alt+backspace, ctrl+u, ctrl+w clear', () => {
  let s = typeAll(initialState(), 'abcdef');
  s = onKey(s, k('backspace', '\x7f')).state;
  assert.equal(s.value, 'abcde');
  for (const clear of [k('backspace', '\x17', { ctrl: true }), k('backspace', '\x1b\x7f', { meta: true }), k('u', '\x15', { ctrl: true }), k('w', '\x17', { ctrl: true })]) {
    assert.equal(onKey(s, clear).state.value, '', clear.name);
  }
  assert.equal(onKey(initialState(), k('backspace', '\x7f')).state.value, '');
  // Surrogate pairs go as one character.
  assert.equal(onKey(typeAll(initialState(), 'a😀'), k('backspace', '\x7f')).state.value, 'a');
});

test('masked field: paste appends, trims the copied line end, refuses multi-line values, strips control chars', () => {
  let s = typeAll(initialState(), 'sk-');
  s = onPaste(s, `${VALUE}\n`);
  assert.equal(s.value, `sk-${VALUE}`);
  const multi = onPaste(initialState(), 'line one\nline two');
  assert.equal(multi.value, '');
  assert.match(multi.error!, /single line/);
  assert.equal(onPaste(initialState(), 'abc\tdef').value, 'abcdef');
  assert.equal(onPaste(initialState(), 'x'.repeat(9000)).value.length, 8192);
});

test('masked field: enter submits with the highlighted scope; tab/arrows move; escape and the Cancel choice cancel', () => {
  let s = typeAll(initialState(), 'secret-value');
  assert.deepEqual(onKey(s, k('return', '\r')).action, { type: 'submit', scope: 'project' });
  s = onKey(s, k('tab', '\t')).state;
  assert.equal(CHOICES[s.choice]!.id, 'session');
  assert.deepEqual(onKey(s, k('return', '\r')).action, { type: 'submit', scope: 'session' });
  s = onKey(s, k('right', '\x1b[C')).state;
  assert.deepEqual(onKey(s, k('return', '\r')).action, { type: 'cancel' });
  s = onKey(s, k('tab', '\x1b[Z', { shift: true })).state;
  s = onKey(s, k('left', '\x1b[D')).state;
  assert.equal(CHOICES[s.choice]!.id, 'project');
  assert.deepEqual(onKey(s, k('escape', '\x1b')).action, { type: 'cancel' });
  assert.deepEqual(onKey(s, k('c', '\x03', { ctrl: true })).action, { type: 'cancel' });
});

test('masked field: enter on an empty field asks for a value; busy ignores everything but escape; cleared drops the value', () => {
  const empty = onKey(initialState(), k('return', '\r'));
  assert.equal(empty.action, undefined);
  assert.match(empty.state.error!, /first/);
  const busy = { ...typeAll(initialState(), 'abc'), busy: true };
  assert.equal(onKey(busy, k('d')).state.value, 'abc');
  assert.equal(onKey(busy, k('return', '\r')).action, undefined);
  assert.equal(onPaste(busy, 'more').value, 'abc');
  assert.deepEqual(onKey(busy, k('escape', '\x1b')).action, { type: 'cancel' });
  assert.equal(cleared(busy).value, '');
});

// ---------------------------------------------------------------------------------------------
// Server <-> TUI hand-off against a stub gateway

type Stub = { url: string; puts: any[]; asks: any[]; store: Map<string, { scope: string; createdAt: string }>; failPut?: string; close: () => Promise<void> };
const TOKEN = randomBytes(12).toString('hex');

async function stubGateway(): Promise<Stub> {
  const stub = { puts: [] as any[], asks: [] as any[], store: new Map<string, { scope: string; createdAt: string }>() } as Stub;
  const srv = http.createServer(async (req, res) => {
    let body = '';
    for await (const c of req) body += c;
    const b = body ? JSON.parse(body) : {};
    const json = (code: number, v: unknown) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, { error: 'bad token' });
    if (req.url === '/api/secret/put') {
      stub.puts.push(b);
      if (stub.failPut) { res.writeHead(500); return res.end(`agent-understudy: ${stub.failPut.replace('$VALUE', b.value)}`); }
      const createdAt = new Date().toISOString() + Math.random();
      stub.store.set(b.name, { scope: b.scope, createdAt });
      return json(200, { name: b.name, scope: b.scope, project: b.cwd, createdAt, ref: `Hide(${b.name})`, env: `AGENT_SECRET_${b.name}` });
    }
    if (req.url === '/api/secret/list') return json(200, { credentials: [...stub.store].map(([name, v]) => ({ name, ...v })) });
    if (req.url === '/api/secret/ask') { stub.asks.push(b); return json(200, { stored: false, reason: 'native dialog (stub)' }); }
    json(404, { error: 'not found' });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  stub.url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  stub.close = () => new Promise((r) => srv.close(() => r()));
  return stub;
}

let gw: Stub; let home = '';
before(async () => {
  home = mkdtempSync(path.join(os.tmpdir(), 'rdx-octui-'));
  writeFileSync(path.join(home, 'api.token'), TOKEN, { mode: 0o600 });
  process.env.AGENT_UNDERSTUDY_HOME = home;
  gw = await stubGateway();
});
after(() => gw.close());

const dirOf = (name: string) => path.join(home, name);
/** Everything the hand-off left on disk, as one string. */
const residue = (dir: string) => existsSync(dir) ? readdirSync(dir).map((f) => f + readFileSync(path.join(dir, f), 'utf8')).join('\n') : '';

/** What the TUI plugin does, minus the drawing. */
async function fakeTui(dir: string, sessionID: string, callID: string, reply: (ask: any) => Promise<any>) {
  const found = await readAsk(sessionID, callID, { dir, waitMs: 2000 });
  assert.ok(found, 'the TUI finds the request');
  if (!(await claim(dir, found.id, 'tui test'))) return 'not-claimed';
  const snapshot = residue(dir);
  const a = await reply(found.ask);
  await answer(found.id, a, dir);
  return snapshot;
}

test('hand-off: the TUI claims, sends the value to the gateway directly, and the server gets only the outcome', async () => {
  const dir = dirOf('asks1');
  const ask = { name: 'OPENROUTER_API_KEY', description: 'for the eval script', cwd: '/proj', gateway: gw.url, sessionID: 'ses_1', callID: 'call_1' };
  const [outcome, onDisk] = await Promise.all([
    askViaTui(ask, { dir, claimMs: 2000, pollMs: 20 }),
    fakeTui(dir, 'ses_1', 'call_1', async (a) => {
      assert.deepEqual({ ...a, at: 0 }, { ...ask, at: 0 });
      const r = await putSecret(a, VALUE, 'session');
      assert.ok(r.ok);
      return { stored: true, scope: r.scope, createdAt: r.createdAt };
    }),
  ]);
  assert.equal(outcome?.stored, true);
  assert.equal(outcome?.stored && outcome.scope, 'session');
  assert.deepEqual(gw.puts.at(-1), { cwd: '/proj', name: 'OPENROUTER_API_KEY', value: VALUE, scope: 'session' });
  assert.ok(!JSON.stringify(outcome).includes(VALUE));
  assert.ok(!String(onDisk).includes(VALUE), 'the request files never hold the value');
  assert.deepEqual(readdirSync(dir), [], 'cleaned up');
});

test('hand-off: cancel in the TUI reaches the server; nothing is stored', async () => {
  const dir = dirOf('asks2');
  const puts = gw.puts.length;
  const [outcome] = await Promise.all([
    askViaTui({ name: 'X_TOKEN', description: '', cwd: '/p', gateway: gw.url, sessionID: 's', callID: 'c' }, { dir, claimMs: 2000, pollMs: 20 }),
    fakeTui(dir, 's', 'c', async () => ({ stored: false, reason: 'the user cancelled' })),
  ]);
  assert.deepEqual(outcome, { stored: false, reason: 'the user cancelled' });
  assert.equal(gw.puts.length, puts);
});

test('hand-off: without a TUI the server takes the claim back (fallback), and a late TUI cannot claim', async () => {
  const dir = dirOf('asks3');
  const t0 = Date.now();
  const outcome = await askViaTui({ name: 'X_TOKEN', description: '', cwd: '/p', gateway: gw.url, sessionID: 's', callID: 'late' }, { dir, claimMs: 150, pollMs: 20 });
  assert.equal(outcome, undefined);
  assert.ok(Date.now() - t0 < 1500);
  // The race itself: once the server holds the claim, a TUI's O_EXCL create fails.
  const id = askId('s', 'race');
  writeFileSync(path.join(dir, `${id}.ask.json`), '{}');
  assert.equal(await claim(dir, id, 'server-fallback'), true);
  assert.equal(await claim(dir, id, 'tui'), false);
});

test('hand-off: an aborted tool call ends the wait and removes the request, so the TUI closes its dialog', async () => {
  const dir = dirOf('asks4');
  const ac = new AbortController();
  const id = askId('s', 'abort');
  const p = askViaTui({ name: 'X_TOKEN', description: '', cwd: '/p', gateway: gw.url, sessionID: 's', callID: 'abort' }, { dir, claimMs: 2000, pollMs: 20, signal: ac.signal });
  const found = await readAsk('s', 'abort', { dir });
  assert.ok(await claim(dir, found!.id, 'tui'));
  assert.equal(await askOpen(id, dir), true);
  ac.abort();
  assert.deepEqual(await p, { stored: false, reason: 'the tool call was aborted' });
  assert.equal(await askOpen(id, dir), false);
  assert.equal(await answer(id, { stored: false, reason: 'late' }, dir), false, 'a late answer is dropped');
});

test('hand-off: gateway errors reach the dialog without the value, and a bad token is reported', async () => {
  gw.failPut = 'value must be 8-8192 characters (got $VALUE)';
  const r = await putSecret({ gateway: gw.url, cwd: '/p', name: 'X_TOKEN' }, VALUE, 'project');
  gw.failPut = undefined;
  assert.equal(r.ok, false);
  assert.ok(!r.ok && !r.error.includes(VALUE) && r.error.includes('8-8192'));
  const bad = await putSecret({ gateway: gw.url, cwd: '/p', name: 'X_TOKEN' }, VALUE, 'project', { token: 'nope' });
  assert.equal(bad.ok, false);
  const down = await putSecret({ gateway: 'http://127.0.0.1:1', cwd: '/p', name: 'X_TOKEN' }, VALUE, 'project');
  assert.ok(!down.ok && /understudy up/.test(down.error));
});

// ---------------------------------------------------------------------------------------------
// The opencode server plugin's secret_request tool

async function pluginTool(options: Record<string, unknown>) {
  const { AgentUnderstudy } = await import('../hooks/opencode/agent-understudy.ts');
  const hooks = await AgentUnderstudy({} as any, { gateway: gw.url, ...options });
  return hooks.tool!.secret_request!;
}
const ctx = (callID: string) => ({ sessionID: 'ses_p', messageID: 'm', agent: 'build', directory: '/proj', worktree: '/proj', callID, abort: new AbortController().signal, metadata() {}, ask: async () => {} }) as any;

test('secret_request: TUI path returns Hide(NAME) and usage, never the value', async () => {
  const tool = await pluginTool({ tuiClaimMs: 2000 });
  const [res] = await Promise.all([
    tool.execute({ name: 'PLUGIN_KEY', description: 'for tests' }, ctx('call_p1')),
    fakeTui(path.join(home, 'opencode-asks'), 'ses_p', 'call_p1', async (a) => {
      const r = await putSecret(a, VALUE, 'project');
      return r.ok ? { stored: true, scope: r.scope, createdAt: r.createdAt } : { stored: false, reason: r.error };
    }),
  ]);
  const out = typeof res === 'string' ? res : res.output;
  assert.ok(!out.includes(VALUE));
  const parsed = JSON.parse(out);
  assert.equal(parsed.stored, true);
  assert.equal(parsed.ref, 'Hide(PLUGIN_KEY)');
  assert.equal(parsed.env, 'AGENT_SECRET_PLUGIN_KEY');
  assert.equal(parsed.scope, 'project');
  assert.match(parsed.usage, /\$AGENT_SECRET_PLUGIN_KEY/);
});

test('secret_request: a TUI claiming "stored" for a value the gateway lacks is not believed', async () => {
  const tool = await pluginTool({ tuiClaimMs: 2000 });
  const [res] = await Promise.all([
    tool.execute({ name: 'NEVER_PUT', description: '' }, ctx('call_p2')),
    fakeTui(path.join(home, 'opencode-asks'), 'ses_p', 'call_p2', async () => ({ stored: true, scope: 'session' })),
  ]);
  assert.equal(JSON.parse(typeof res === 'string' ? res : res.output).stored, false);
});

test('secret_request: no TUI -> the gateway native dialog (/api/secret/ask)', async () => {
  const tool = await pluginTool({ tuiClaimMs: 100 });
  const asks = gw.asks.length;
  const res = await tool.execute({ name: 'FALLBACK_KEY', description: 'd' }, ctx('call_p3'));
  assert.equal(gw.asks.length, asks + 1);
  assert.deepEqual(gw.asks.at(-1), { cwd: '/proj', name: 'FALLBACK_KEY', description: 'd' });
  assert.equal(JSON.parse(typeof res === 'string' ? res : res.output).reason, 'native dialog (stub)');
  // tuiAsk: false skips the hand-off entirely.
  const off = await pluginTool({ tuiAsk: false });
  const t0 = Date.now();
  await off.execute({ name: 'FALLBACK_KEY', description: 'd' }, ctx('call_p4'));
  assert.ok(Date.now() - t0 < 1000);
});
