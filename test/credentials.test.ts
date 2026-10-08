import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { CredentialStore, projectOf } from '../src/core/credentials.ts';
import { loadConfig } from '../src/config.ts';
import { buildRedactor } from '../src/runtime.ts';
import { createGateway } from '../src/gateway/server.ts';
import { apiToken } from '../src/core/api-token.ts';

process.env.AGENT_UNDERSTUDY_CREDENTIALS_KEY = randomBytes(32).toString('hex'); // never touch the real keychain in tests
const VALUE = 'sk-or-v1-' + randomBytes(24).toString('hex');

function repo() {
  const d = mkdtempSync(path.join(os.tmpdir(), 'rdx-proj-'));
  execFileSync('git', ['init', '-q'], { cwd: d });
  return d;
}

test('store: remembered credentials are encrypted, 0600, project-scoped and survive a restart; session ones do not', () => {
  const home = mkdtempSync(path.join(os.tmpdir(), 'rdx-cred-'));
  const a = repo(); const b = repo();
  const s1 = new CredentialStore(home);
  s1.set(a, 'OPENROUTER_API_KEY', VALUE, 'project');
  s1.set(a, 'TEMP_TOKEN', 'session-only-value-123', 'session');
  assert.throws(() => s1.set(a, 'bad-name', VALUE, 'session'), /UPPER_SNAKE_CASE/);
  assert.throws(() => s1.set(a, 'SHORT', 'abc', 'session'), /8-8192/);
  assert.deepEqual(s1.list(a).map((c) => [c.name, c.scope]), [['OPENROUTER_API_KEY', 'project'], ['TEMP_TOKEN', 'session']]);
  assert.deepEqual(s1.list(b), [], 'another repo sees nothing');
  const file = path.join(home, 'credentials', readdirSync(path.join(home, 'credentials'))[0]!);
  assert.ok(!readFileSync(file, 'utf8').includes(VALUE), 'no plaintext on disk');
  assert.equal(statSync(file).mode & 0o777, 0o600);
  // New process: the remembered one comes back, the session one is gone.
  const s2 = new CredentialStore(home);
  assert.deepEqual(s2.values(path.join(a, '.'), ['OPENROUTER_API_KEY', 'TEMP_TOKEN']), { OPENROUTER_API_KEY: VALUE });
  assert.equal(projectOf(a).id, projectOf(path.join(a, '.')).id);
  assert.ok(s2.remove(a, 'OPENROUTER_API_KEY'));
  assert.deepEqual(new CredentialStore(home).list(a), []);
});

let up: http.Server; let gw: http.Server; let base = ''; let home = ''; let seen: any[] = [];
const auth = () => ({ 'content-type': 'application/json', authorization: `Bearer ${apiToken(home)}` });

before(async () => {
  up = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
      seen.push(JSON.parse(b || '{}'));
      // The model answers with the reference; it must reach the client as the reference, not the value.
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ content: [{ type: 'text', text: 'I used Hide(OPENROUTER_API_KEY).' }] }));
    });
  });
  await new Promise<void>((r) => up.listen(0, '127.0.0.1', r));
  home = mkdtempSync(path.join(os.tmpdir(), 'rdx-gwc-'));
  const config = { ...loadConfig(home), upstreams: { anthropic: `http://127.0.0.1:${(up.address() as AddressInfo).port}`, codex: 'http://x', openai: 'http://x' } };
  const { redactor } = buildRedactor(config, { models: [] });
  gw = createGateway({ config, redactor, credentials: new CredentialStore(home) }).server;
  await new Promise<void>((r) => gw.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(gw.address() as AddressInfo).port}`;
  writeFileSync(path.join(home, 'config.json'), JSON.stringify({ port: (gw.address() as AddressInfo).port, models: [] }));
});
after(() => { gw.close(); up.close(); });

test('gateway: control api needs the token; credential values go out as Hide(NAME) and never come back', async () => {
  const proj = repo();
  assert.equal((await fetch(`${base}/api/secret/env`, { method: 'POST', body: JSON.stringify({ cwd: proj }) })).status, 401);
  assert.equal((await fetch(`${base}/api/restore`, { method: 'POST', body: '{"text":"x"}' })).status, 401);
  const put = await (await fetch(`${base}/api/secret/put`, { method: 'POST', headers: auth(), body: JSON.stringify({ cwd: proj, name: 'OPENROUTER_API_KEY', value: VALUE, scope: 'session' }) })).json();
  assert.equal(put.ref, 'Hide(OPENROUTER_API_KEY)');
  seen = [];
  const r = await fetch(`${base}/anthropic/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 't', content: `curl said: key=${VALUE}` }] }] }) });
  const out = await r.json();
  assert.ok(!JSON.stringify(seen[0]).includes(VALUE));
  assert.ok(JSON.stringify(seen[0]).includes('key=Hide(OPENROUTER_API_KEY)'));
  assert.equal(out.content[0].text, 'I used Hide(OPENROUTER_API_KEY).', 'references are never restored to values');
  const res = await (await fetch(`${base}/api/residue`, { method: 'POST', headers: auth(), body: JSON.stringify({ value: { command: 'curl -H "Bearer Hide(OPENROUTER_API_KEY)"' } }) })).json();
  assert.deepEqual(res.residue, ['Hide(OPENROUTER_API_KEY)']);
});

test('guard --inject: the command reads the value from the gateway at run time; the text never holds it', async () => {
  const proj = repo();
  await fetch(`${base}/api/secret/put`, { method: 'POST', headers: auth(), body: JSON.stringify({ cwd: proj, name: 'DEMO_TOKEN', value: VALUE, scope: 'session' }) });
  const guard = path.resolve(import.meta.dirname, '../hooks/codex/guard.mjs');
  const env = { ...process.env, AGENT_UNDERSTUDY_GATEWAY: base, AGENT_UNDERSTUDY_HOME: home };
  const run = (cmd: string, args: string[], input: string, cwd?: string) => new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
    const p = spawn(cmd, args, { env, cwd });
    let stdout = ''; let stderr = '';
    p.stdout.on('data', (d) => { stdout += d; }); p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (status) => resolve({ status, stdout, stderr }));
    p.stdin.end(input);
  });
  const original = `test "$AGENT_SECRET_DEMO_TOKEN" = "${VALUE}" && echo LOADED`; // the test knows the value; a model never would
  const hook = await run(process.execPath, [guard, '--inject'], JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd: proj, tool_input: { command: original } }));
  assert.equal(hook.status, 0, hook.stderr);
  const rewritten = JSON.parse(hook.stdout).hookSpecificOutput.updatedInput.command as string;
  const file = /^\. '([^']+)'/.exec(rewritten)![1]!;
  assert.match(rewritten, /^\. '[^']+agent-understudy-[0-9a-f]+\.env' && rm -f '[^']+' &&\n/);
  assert.equal(rewritten.split(VALUE).length - 1, 1, 'only the test\'s own comparison holds the value');
  assert.equal(statSync(file).mode & 0o777, 0o600);
  const sh = await run('bash', ['-c', rewritten], '', proj);
  assert.equal(sh.stdout.trim(), 'LOADED', sh.stderr);
  assert.throws(() => statSync(file), /ENOENT/, 'the command deletes the one-shot file');
  // A credential the project doesn't have: refused before anything runs, with the way to get it.
  const none = await run(process.execPath, [guard, '--inject'], JSON.stringify({ tool_name: 'Bash', cwd: proj, tool_input: { command: 'curl -H "x: $AGENT_SECRET_NOPE_TOKEN"' } }));
  assert.equal(none.status, 2);
  assert.match(none.stderr, /no credential NOPE_TOKEN.*secret_request/);
  // Using the reference as if it were the value is refused with the way out.
  const bad = await run(process.execPath, [guard, '--inject'], JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'curl -H "Authorization: Bearer Hide(DEMO_TOKEN)"' } }));
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /"\$AGENT_SECRET_DEMO_TOKEN"/);
});

test('secret env: a missing credential makes the eval prefix fail, so the command does not run', async () => {
  const proj = repo();
  const cli = path.resolve(import.meta.dirname, '../bin/understudy');
  const cmd = `eval "$('${process.execPath}' '${cli}' secret env NOPE_TOKEN)" &&\necho RAN`;
  const out = await new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
    const p = spawn('bash', ['-c', cmd], { cwd: proj, env: { ...process.env, AGENT_UNDERSTUDY_HOME: home } });
    let stdout = ''; let stderr = '';
    p.stdout.on('data', (d) => { stdout += d; }); p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (status) => resolve({ status, stdout, stderr }));
  });
  assert.notEqual(out.status, 0);
  assert.equal(out.stdout, '');
  assert.match(out.stderr, /no credential NOPE_TOKEN/);
});

test('codex masked prompt: Pre requires isSecret; Post stores the typed value and withholds it from the model', async () => {
  const proj = repo();
  const guard = path.resolve(import.meta.dirname, '../hooks/codex/guard.mjs');
  const env = { ...process.env, AGENT_UNDERSTUDY_GATEWAY: base, AGENT_UNDERSTUDY_HOME: home };
  const run = (args: string[], input: unknown) => new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
    const p = spawn(process.execPath, [guard, ...args], { env });
    let stdout = ''; let stderr = '';
    p.stdout.on('data', (d) => { stdout += d; }); p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (status) => resolve({ status, stdout, stderr }));
    p.stdin.end(JSON.stringify(input));
  });
  const q = { id: 'agent_secret__ROUTER_KEY', header: 'Credential', question: 'ROUTER_KEY?', options: [{ label: 'Remember for this project', description: '' }, { label: 'This session only', description: '' }] };
  // Pre: without isSecret it would be shown in clear text.
  const pre = await run(['--inject'], { tool_name: 'request_user_input', cwd: proj, tool_input: { questions: [q] } });
  assert.equal(pre.status, 2);
  assert.match(pre.stderr, /isSecret/);
  assert.equal((await run(['--inject'], { tool_name: 'request_user_input', cwd: proj, tool_input: { questions: [{ ...q, isSecret: true }] } })).status, 0);
  // Post: the answer carries the value as a note; the hook stores it and replaces the model-facing result.
  const answer = { answers: { agent_secret__ROUTER_KEY: { answers: ['This session only', `user_note: ${VALUE}`] } } };
  const postRun = await run(['--post'], { tool_name: 'request_user_input', cwd: proj, tool_input: { questions: [{ ...q, isSecret: true }] }, tool_response: JSON.stringify(answer) });
  assert.equal(postRun.status, 0);
  const out = JSON.parse(postRun.stdout);
  assert.equal(out.decision, 'block');
  assert.ok(!out.reason.includes(VALUE), 'the model-facing result never holds the value');
  assert.match(out.reason, /"stored":true.*\$AGENT_SECRET_ROUTER_KEY/);
  const env2 = await (await fetch(`${base}/api/secret/env`, { method: 'POST', headers: auth(), body: JSON.stringify({ cwd: proj, names: ['ROUTER_KEY'] }) })).json();
  assert.equal(env2.env.AGENT_SECRET_ROUTER_KEY, VALUE);
  // Gateway unreachable: still withheld.
  const down = await new Promise<{ stdout: string }>((resolve) => {
    const p = spawn(process.execPath, [guard, '--post'], { env: { ...env, AGENT_UNDERSTUDY_GATEWAY: 'http://127.0.0.1:9' } });
    let stdout = ''; p.stdout.on('data', (d) => { stdout += d; }); p.on('close', () => resolve({ stdout }));
    p.stdin.end(JSON.stringify({ tool_name: 'request_user_input', cwd: proj, tool_input: { questions: [{ ...q, isSecret: true }] }, tool_response: JSON.stringify(answer) }));
  });
  const d = JSON.parse(down.stdout);
  assert.equal(d.decision, 'block');
  assert.ok(!d.reason.includes(VALUE));
  assert.match(d.reason, /not reachable/);
});

test('codex masked-prompt route needs live hooks AND the session routed through the gateway', async () => {
  const proj = repo();
  const active = async () => (await (await fetch(`${base}/api/hook/active`, { method: 'POST', headers: auth(), body: JSON.stringify({ host: 'codex', cwd: proj }) })).json()).active;
  assert.equal(await active(), false);
  const guard = path.resolve(import.meta.dirname, '../hooks/codex/guard.mjs');
  await new Promise<void>((resolve) => {
    const p = spawn(process.execPath, [guard, '--session-start'], { env: { ...process.env, AGENT_UNDERSTUDY_GATEWAY: base, AGENT_UNDERSTUDY_HOME: home } });
    p.on('close', () => resolve()); p.stdin.end(JSON.stringify({ hook_event_name: 'SessionStart', cwd: proj, session_id: 's1' }));
  });
  assert.equal(await active(), false, 'hooks alone are not enough: the session must be routed through the gateway');
  await fetch(`${base}/anthropic/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json', 'session-id': 'other' }, body: JSON.stringify({ model: 'm', messages: [] }) });
  assert.equal(await active(), false, 'another session\'s traffic does not count');
  await fetch(`${base}/anthropic/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json', 'session-id': 's1' }, body: JSON.stringify({ model: 'm', messages: [] }) });
  assert.equal(await active(), true);
});

test('session credential is still recognised after the gateway restarts (fingerprint), and OpenRouter keys are caught', async () => {
  const home2 = mkdtempSync(path.join(os.tmpdir(), 'rdx-fp-'));
  const proj = repo();
  const v = 'sk-or-v1-' + randomBytes(32).toString('hex');
  new CredentialStore(home2).set(proj, 'ROUTER_KEY', v, 'session');
  // "Restart": a new store and a new gateway-side vault; the session value itself is gone.
  const store = new CredentialStore(home2);
  assert.deepEqual(store.values(proj, ['ROUTER_KEY']), {});
  const { Vault } = await import('../src/core/vault.ts');
  const { Redactor } = await import('../src/core/redactor.ts');
  const vault = new Vault();
  vault.setFingerprints(store.fingerprints(), (s) => store.fingerprintOf(s));
  const r = new Redactor({ detectors: [], vault });
  assert.equal((await r.redact(`Authorization: Bearer ${v}`)).text, 'Authorization: Bearer Hide(ROUTER_KEY)');
  assert.equal((await r.redact(`OPENROUTER_API_KEY=${v}`)).text, 'OPENROUTER_API_KEY=Hide(ROUTER_KEY)');
  const { PatternDetector } = await import('../src/core/patterns.ts');
  const spans = await new PatternDetector().detect(`key ${'sk-or-v1-' + randomBytes(32).toString('hex')}`);
  assert.ok(spans.some((s) => s.source === 'openrouter-api-key'));
});

test('codex routing guard fails closed when another session of the project is not routed', async () => {
  const proj = repo();
  const guard = path.resolve(import.meta.dirname, '../hooks/codex/guard.mjs');
  const hello = (session: string) => new Promise<void>((resolve) => {
    const p = spawn(process.execPath, [guard, '--session-start'], { env: { ...process.env, AGENT_UNDERSTUDY_GATEWAY: base, AGENT_UNDERSTUDY_HOME: home } });
    p.on('close', () => resolve()); p.stdin.end(JSON.stringify({ hook_event_name: 'SessionStart', cwd: proj, session_id: session }));
  });
  const active = async () => (await (await fetch(`${base}/api/hook/active`, { method: 'POST', headers: auth(), body: JSON.stringify({ host: 'codex', cwd: proj }) })).json());
  await hello('routed-1');
  await fetch(`${base}/anthropic/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json', 'session-id': 'routed-1' }, body: JSON.stringify({ model: 'm', messages: [] }) });
  assert.equal((await active()).active, true);
  await hello('unrouted-2');
  const a = await active();
  assert.equal(a.active, false, JSON.stringify(a));
});
