import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import type { AddressInfo } from 'node:net';
import { WebSocketServer, WebSocket } from 'ws';
import { loadConfig } from '../src/config.ts';
import { buildRedactor } from '../src/runtime.ts';
import { createGateway } from '../src/gateway/server.ts';
import { partialTail } from '../src/gateway/restore-stream.ts';
import { apiToken } from '../src/core/api-token.ts';

const alnum = (n: number) => Array.from(randomBytes(n), (b) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[b % 62]).join('');
const SECRET = 'ghp_' + alnum(36);
const EMAIL = 'dana.whitfield@fastmail.com';

let upstreamSeen: any[] = [];
let upstream: http.Server;
let gw: http.Server;
let base = '';
let wsSeen: any[] = [];
let gwHome = '';
let auth: Record<string, string> = {};

/** Splits s into n roughly equal chunks so placeholders straddle deltas. */
function shards(s: string, size = 7): string[] { const o = []; for (let i = 0; i < s.length; i += size) o.push(s.slice(i, i + size)); return o; }

/** Placeholders in a body, secrets first. */
function placeholdersIn(body: any): string[] {
  const all = JSON.stringify(body).match(/RDX_[A-Z]+_[0-9a-f]{10}/g) ?? [];
  return [...all.filter((p) => p.startsWith('RDX_SECRET_')), ...all.filter((p) => !p.startsWith('RDX_SECRET_'))];
}

before(async () => {
  const wss = new WebSocketServer({ noServer: true });
  upstream = http.createServer((req, res) => {
    const parts: Buffer[] = [];
    req.on('data', (c) => parts.push(c));
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(parts).toString() || '{}');
      upstreamSeen.push({ url: req.url, headers: req.headers, body });
      // Echo a secret token when there is one, else the last user message (which holds surrogates).
      const [ph] = placeholdersIn(body);
      const echo = ph ? `token is ${ph} ok` : String(body.messages?.at(-1)?.content ?? '');
      if (req.url!.endsWith('/v1/messages')) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        const ev = (e: string, d: unknown) => res.write(`event: ${e}\ndata: ${JSON.stringify(d)}\n\n`);
        ev('message_start', { type: 'message_start', message: { id: 'm', content: [] } });
        ev('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } });
        for (const s of shards(echo)) ev('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: s } });
        ev('content_block_stop', { type: 'content_block_stop', index: 0 });
        ev('content_block_start', { type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 't', name: 'Bash', input: {} } });
        for (const s of shards(JSON.stringify({ command: `echo ${ph}` }), 5)) ev('content_block_delta', { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: s } });
        ev('content_block_stop', { type: 'content_block_stop', index: 1 });
        ev('content_block_start', { type: 'content_block_start', index: 2, content_block: { type: 'text', text: '' } });
        ev('content_block_delta', { type: 'content_block_delta', index: 2, delta: { type: 'text_delta', text: 'ends with R' } });
        ev('content_block_stop', { type: 'content_block_stop', index: 2 });
        ev('message_stop', { type: 'message_stop' });
        res.end();
      } else if (req.url!.endsWith('/nocontent/responses')) {
        // chatgpt.com style: SSE body without a content-type header.
        res.writeHead(200, {});
        for (const sh of shards(echo)) res.write(`event: response.output_text.delta\ndata: ${JSON.stringify({ type: 'response.output_text.delta', item_id: 'n', content_index: 0, delta: sh })}\n\n`);
        res.write(`event: response.output_text.done\ndata: ${JSON.stringify({ type: 'response.output_text.done', item_id: 'n', content_index: 0, text: echo })}\n\n`);
        res.end();
      } else if (req.url!.endsWith('/responses')) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        const ev = (d: any) => res.write(`event: ${d.type}\ndata: ${JSON.stringify(d)}\n\n`);
        for (const s of shards(echo)) ev({ type: 'response.output_text.delta', item_id: 'i1', content_index: 0, delta: s });
        ev({ type: 'response.output_text.done', item_id: 'i1', content_index: 0, text: echo });
        ev({ type: 'response.output_item.done', item: { type: 'function_call', call_id: 'c', name: 'shell', arguments: JSON.stringify({ cmd: ph }) } });
        ev({ type: 'response.completed', response: { output: [{ type: 'message', content: [{ type: 'output_text', text: echo }] }] } });
        res.end();
      } else {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ content: [{ type: 'text', text: echo }] }));
      }
    });
  });
  upstream.on('upgrade', (req, socket, head) => wss.handleUpgrade(req, socket, head, (ws) => {
    ws.on('message', (d) => {
      const msg = JSON.parse(d.toString());
      wsSeen.push(msg);
      const [ph] = placeholdersIn(msg);
      for (const s of shards(`ws says ${ph}`, 4)) ws.send(JSON.stringify({ type: 'response.output_text.delta', item_id: 'w', content_index: 0, delta: s }));
      ws.send(JSON.stringify({ type: 'response.output_text.done', item_id: 'w', content_index: 0, text: `ws says ${ph}` }));
      ws.send(JSON.stringify({ type: 'response.completed', response: {} }));
    });
  }));
  await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
  const up = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;

  const home = mkdtempSync(path.join(os.tmpdir(), 'rdx-gw-'));
  const config = { ...loadConfig(home), upstreams: { anthropic: up, codex: up + '/backend-api/codex', openai: up, mine: up } };
  gwHome = home;
  auth = { authorization: `Bearer ${apiToken(home)}` };
  const { redactor } = buildRedactor(config, { models: [] }); // regex only: no sidecar needed
  gw = createGateway({ config, redactor }).server;
  await new Promise<void>((r) => gw.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(gw.address() as AddressInfo).port}`;
});

after(() => { gw.close(); upstream.close(); });

function readSse(text: string) {
  return text.split('\n\n').filter(Boolean).map((e) => JSON.parse(e.split('\n').find((l) => l.startsWith('data: '))!.slice(6)));
}

test('placeholder tail detection', () => {
  assert.equal(partialTail('hello RDX_SEC'), 'RDX_SEC'.length);
  assert.equal(partialTail('hello RDX_SECRET_01234'), 'RDX_SECRET_01234'.length);
  assert.equal(partialTail('hello RDX_SECRET_0123456789'), 0);
  assert.equal(partialTail('no tail here'), 0);
  assert.equal(partialTail('ends with R'), 1);
});

test('anthropic: request redacted, SSE restored across split deltas and tool json', async () => {
  upstreamSeen = [];
  const res = await fetch(`${base}/anthropic/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'anthropic-beta': 'oauth-2025-04-20', authorization: 'Bearer sub-token' },
    body: JSON.stringify({
      model: 'claude-x', stream: true,
      system: [{ type: 'text', text: 'x-anthropic-billing-header: cc_version=1' }, { type: 'text', text: `contact ${EMAIL}` }],
      messages: [
        { role: 'user', content: `my token is ${SECRET}, keep it safe` },
        { role: 'assistant', content: [{ type: 'thinking', thinking: `secret ${SECRET}`, signature: 'sig' }, { type: 'tool_use', id: 't0', name: 'Bash', input: { command: `curl -H "Authorization: token ${SECRET}"`, name: EMAIL } }] },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't0', content: [{ type: 'text', text: `owner: ${EMAIL}` }] }] },
      ],
    }),
  });
  const text = await res.text();
  const seen = upstreamSeen[0];
  const sent = JSON.stringify(seen.body);
  assert.equal(seen.headers['anthropic-beta'], 'oauth-2025-04-20');
  assert.equal(seen.headers.authorization, 'Bearer sub-token');
  // Content redacted everywhere except inside thinking (must stay byte-identical for its signature).
  assert.equal(sent.split(SECRET).length - 1, 1, 'only the thinking copy remains');
  assert.equal(seen.body.messages[1].content[0].thinking, `secret ${SECRET}`);
  assert.ok(!sent.includes(EMAIL));
  assert.equal(seen.body.system[0].text, 'x-anthropic-billing-header: cc_version=1');
  assert.match(seen.body.messages[1].content[1].input.name, /^[\w.+-]+@fastmail\.com$/);
  assert.notEqual(seen.body.messages[1].content[1].input.name, EMAIL);

  const events = readSse(text);
  const block = (i: number, f: 'text' | 'partial_json') => events.filter((e) => e.type === 'content_block_delta' && e.index === i).map((e) => e.delta[f]).join('');
  assert.equal(block(0, 'text'), `token is ${SECRET} ok`);
  assert.deepEqual(JSON.parse(block(1, 'partial_json')), { command: `echo ${SECRET}` });
  assert.equal(block(2, 'text'), 'ends with R', 'held tail released at block stop');
  assert.equal(events.at(-1).type, 'message_stop');
});

test('anthropic: same secret -> same placeholder on every turn', async () => {
  upstreamSeen = [];
  const send = () => fetch(`${base}/anthropic/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'm', stream: true, messages: [{ role: 'user', content: `k=${SECRET}` }] }) }).then((r) => r.text());
  await send(); await send();
  assert.equal(JSON.stringify(upstreamSeen[0].body), JSON.stringify(upstreamSeen[1].body));
});

test('codex: zstd request redacted, responses SSE restored incl. aggregates and arguments', async () => {
  upstreamSeen = [];
  const body = { model: 'gpt', instructions: 'be helpful', input: [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: `use ${SECRET}` }] }, { type: 'reasoning', encrypted_content: 'opaque' }] };
  const res = await fetch(`${base}/backend-api/codex/responses`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'content-encoding': 'zstd', 'chatgpt-account-id': 'acct' },
    body: zlib.zstdCompressSync(Buffer.from(JSON.stringify(body))),
  });
  const events = readSse(await res.text());
  const seen = upstreamSeen[0];
  assert.equal(seen.url, '/backend-api/codex/responses');
  assert.equal(seen.headers['chatgpt-account-id'], 'acct');
  assert.ok(!JSON.stringify(seen.body).includes(SECRET));
  assert.equal(seen.body.input[1].encrypted_content, 'opaque');
  const deltas = events.filter((e) => e.type === 'response.output_text.delta').map((e) => e.delta).join('');
  assert.equal(deltas, `token is ${SECRET} ok`);
  assert.equal(events.find((e) => e.type === 'response.output_text.done').text, `token is ${SECRET} ok`);
  assert.deepEqual(JSON.parse(events.find((e) => e.type === 'response.output_item.done').item.arguments), { cmd: SECRET });
  assert.equal(events.find((e) => e.type === 'response.completed').response.output[0].content[0].text, `token is ${SECRET} ok`);
});

test('codex: websocket redacts outgoing and restores incoming', async () => {
  wsSeen = [];
  const ws = new WebSocket(`${base.replace('http', 'ws')}/backend-api/codex/responses`);
  await new Promise((r) => ws.once('open', r));
  const got: any[] = [];
  const done = new Promise<void>((resolve) => ws.on('message', (d) => { const m = JSON.parse(d.toString()); got.push(m); if (m.type === 'response.completed') resolve(); }));
  ws.send(JSON.stringify({ type: 'response.create', input: [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: `ws ${SECRET}` }] }] }));
  await done;
  ws.close();
  assert.ok(!JSON.stringify(wsSeen).includes(SECRET));
  assert.equal(got.filter((m) => m.type === 'response.output_text.delta').map((m) => m.delta).join(''), `ws says ${SECRET}`);
});

test('named upstream + non-streaming json restore + control api', async () => {
  const r = await fetch(`${base}/u/mine/v1/chat/completions`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'x', messages: [{ role: 'user', content: `mail ${EMAIL}` }] }) });
  assert.equal((await r.json()).content[0].text.includes(EMAIL), true);
  const red = await (await fetch(`${base}/api/redact`, { method: 'POST', headers: auth, body: JSON.stringify({ text: `x ${EMAIL}` }) })).json();
  assert.match(red.text, /^x [\w.+-]+@fastmail\.com$/);
  assert.notEqual(red.text, `x ${EMAIL}`);
  assert.ok(!JSON.stringify(red).includes(EMAIL), 'control api never echoes values in findings');
  const back = await (await fetch(`${base}/api/restore`, { method: 'POST', headers: auth, body: JSON.stringify({ text: red.text }) })).json();
  assert.equal(back.text, `x ${EMAIL}`);
  const st = await (await fetch(`${base}/api/status`)).json();
  assert.ok(st.stats.requests >= 1);
});

test('anthropic: surrogate split across deltas is restored', async () => {
  const res = await fetch(`${base}/anthropic/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'm', stream: true, messages: [{ role: 'user', content: `please write to ${EMAIL} today` }] }) });
  const events = readSse(await res.text());
  const text = events.filter((e) => e.type === 'content_block_delta' && e.index === 0).map((e) => e.delta.text).join('');
  assert.equal(text, `please write to ${EMAIL} today`);
  assert.ok(events.filter((e) => e.type === 'content_block_delta' && e.index === 0).every((e) => !/@example\./.test(e.delta.text)), 'no surrogate fragment leaks to the client');
});

test('guard hook: blocks a tool call that still carries stand-ins, passes a clean one', async () => {
  const { spawn } = await import('node:child_process');
  const guard = path.resolve(import.meta.dirname, '../hooks/codex/guard.mjs');
  // Async: the gateway answering the guard runs in this same process.
  const run = (tool_input: unknown) => new Promise<{ status: number | null; stderr: string }>((resolve) => {
    const p = spawn(process.execPath, [guard], { env: { ...process.env, AGENT_UNDERSTUDY_GATEWAY: base, AGENT_UNDERSTUDY_HOME: gwHome } });
    let stderr = '';
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (status) => resolve({ status, stderr }));
    p.stdin.end(JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input }));
  });
  const bad = await run({ file_path: 'a.txt', content: 'key = RDX_SECRET_0123456789' });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /stand-ins that could not be mapped back \("RDX_SECRET_0123456789"\)/);
  const ok = await run({ file_path: 'a.txt', content: 'hello world' });
  assert.equal(ok.status, 0, ok.stderr);
});

test('codex: SSE without a content-type is still restored', async () => {
  const res = await fetch(`${base}/backend-api/codex/nocontent/responses`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'gpt', stream: true, input: [{ type: 'message', role: 'user', content: [{ type: 'input_text', text: `use ${SECRET}` }] }] }) });
  const events = readSse(await res.text());
  assert.equal(events.filter((e) => e.type === 'response.output_text.delta').map((e) => e.delta).join(''), `token is ${SECRET} ok`);
});

test('observe: a body that already carries our stand-ins does not make stand-ins ambiguous', async () => {
  const red = await (await fetch(`${base}/api/redact`, { method: 'POST', headers: auth, body: JSON.stringify({ text: `mail ${EMAIL}` }) })).json();
  const standIn = red.text.slice(5);
  // A client that redacted before us (mod/plugin) sends the stand-in through the proxy.
  await fetch(`${base}/anthropic/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'm', messages: [{ role: 'user', content: `write to ${standIn}` }] }) });
  const back = await (await fetch(`${base}/api/restore`, { method: 'POST', headers: auth, body: JSON.stringify({ text: standIn }) })).json();
  assert.equal(back.text, EMAIL);
});
