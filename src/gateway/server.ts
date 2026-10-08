// The local gateway: a redacting reverse proxy for coding-agent API traffic, plus a small control API
// that hooks and the MCP server use so everything shares one vault and one set of loaded models.
import http from 'node:http';
import { appendFile } from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import os from 'node:os';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { WebSocketServer, WebSocket } from 'ws';
import type { Config } from '../config.ts';
import type { Redactor } from '../core/redactor.ts';
import type { SidecarClient } from '../core/sidecar.ts';
import {
  anthropicStream, chatStream, redactBody, responsesStream, restoreDeep, type Protocol, type RedactOutcome, type StreamTransform,
} from './protocols.ts';
import { randomBytes } from 'node:crypto';
import { apiToken } from '../core/api-token.ts';
import { NAME_RE, projectOf, type CredentialStore } from '../core/credentials.ts';
import { hasGui, macDialog, openUrl, shq } from '../core/secret-input.ts';
import { SseParser, StreamRestorer, formatEvent, parseEvent, partialTail, type Hold } from './restore-stream.ts';

const HOP = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive', 'upgrade', 'accept-encoding', 'content-encoding', 'proxy-connection']);

export function protocolFor(p: string): Protocol | undefined {
  const bare = p.split('?')[0].replace(/\/+$/, '');
  if (/\/messages(\/count_tokens)?$/.test(bare)) return 'anthropic';
  if (/\/responses(\/compact)?$/.test(bare)) return 'responses';
  if (/\/chat\/completions$/.test(bare)) return 'chat';
  return undefined;
}

/** Maps a gateway path to an upstream URL. */
export function route(url: string, upstreams: Record<string, string>): { name: string; target: string } | undefined {
  const join = (base: string, rest: string) => base.replace(/\/+$/, '') + rest;
  let m: RegExpExecArray | null;
  if ((m = /^\/anthropic(\/.*)?$/.exec(url))) return { name: 'anthropic', target: join(upstreams.anthropic, m[1] ?? '/') };
  if ((m = /^\/backend-api\/codex(\/.*)?$/.exec(url))) return { name: 'codex', target: join(upstreams.codex, m[1] ?? '/') };
  if ((m = /^\/openai(\/.*)?$/.exec(url))) return { name: 'openai', target: join(upstreams.openai, m[1] ?? '/') };
  if ((m = /^\/u\/([\w.-]+)(\/.*)?$/.exec(url)) && upstreams[m[1]]) return { name: m[1], target: join(upstreams[m[1]], m[2] ?? '/') };
  return undefined;
}

function decode(buf: Buffer, enc: string | undefined): Buffer {
  switch ((enc ?? '').toLowerCase()) {
    case '': case 'identity': return buf;
    case 'zstd': return zlib.zstdDecompressSync(buf);
    case 'gzip': case 'x-gzip': return zlib.gunzipSync(buf);
    case 'br': return zlib.brotliDecompressSync(buf);
    case 'deflate': return zlib.inflateSync(buf);
    default: throw new Error(`unsupported content-encoding ${enc}`);
  }
}

function transformFor(p: Protocol, restore: Redactor['restore'], hold: Hold): StreamTransform {
  return p === 'anthropic' ? anthropicStream(restore, hold) : p === 'responses' ? responsesStream(restore, hold) : chatStream(restore, hold);
}

export interface GatewayDeps { config: Config; redactor: Redactor; sidecar?: SidecarClient; credentials?: CredentialStore; log?: (s: string) => void }

export function createGateway({ config, redactor, sidecar, credentials, log = () => {} }: GatewayDeps) {
  const token = apiToken(config.home);
  // Every credential this machine remembers is redacted everywhere, including ones another engine (another
  // agent session) stored after this one started: re-read whenever the credentials directory changes.
  let credStamp: string | undefined;
  const syncCredentials = () => {
    if (!credentials) return;
    const stamp = credentials.stamp();
    if (stamp === credStamp) return;
    credStamp = stamp;
    for (const c of credentials.allValues()) redactor.vault.addCredential(c.name, c.value);
    // Session values from other or earlier engines: known only by fingerprint, still redacted when they reappear.
    redactor.vault.setFingerprints(credentials.fingerprints(), (s) => credentials.fingerprintOf(s));
  };
  syncCredentials();
  // Hosts whose agent-understudy hooks are live, by project: "<host>:<project root>" -> last SessionStart.
  // A host's own masked TUI input is only offered when its hooks provably run (else the answer would reach the model).
  const hookSessions = new Map<string, { at: number; sessions: Map<string, number> }>();
  // Session ids seen on proxied model traffic (codex sends a session-id header). The masked TUI prompt is only
  // offered to a session whose traffic provably passes through here: codex re-sends request_user_input answers
  // (retained "verified answers") to its guardian model, so without the gateway in the path the value would leak.
  const proxiedSessions = new Map<string, number>();
  // Masked-input pages waiting for the person (fallback when no native dialog is available).
  const prompts = new Map<string, { name: string; description: string; cwd: string; done?: { scope: string } | { error: string }; at: number }>();
  const restore = (t: string, esc?: (v: string) => string) => redactor.restore(t, esc);
  // Hold back a stream tail that could still become a token or a surrogate.
  const hold: Hold = (s) => Math.max(partialTail(s), redactor.vault.holdLength(s));
  // Streams restored on behalf of hooks (the Claude Code mod's turn.step), keyed by the caller.
  const hookStreams = new Map<string, { r: StreamRestorer; at: number }>();
  const auditFile = path.join(config.home, 'audit.jsonl');
  const stats = { requests: 0, redacted: 0, findings: 0, errors: 0, scannedChars: 0, lastRequest: { strings: 0, chars: 0, ms: 0 }, startedAt: Date.now() };

  // Test aid: AGENT_UNDERSTUDY_DUMP_DIR=<dir> writes every request body exactly as it leaves for the upstream,
  // so an end-to-end test can grep what the model provider actually received. Never enable it in daily use.
  const dumpDir = process.env.AGENT_UNDERSTUDY_DUMP_DIR;
  let dumpN = 0;
  const dumpRun = new Date().toISOString().replace(/[:.]/g, '-'); // restarts don't overwrite earlier evidence
  const dump = (where: string, body: string) => {
    if (!dumpDir) return;
    mkdirSync(dumpDir, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(dumpDir, `${dumpRun}-${String(++dumpN).padStart(5, '0')}-${where.replace(/[^\w.-]+/g, '_')}.json`), body, { mode: 0o600 });
  };
  const audit = (entry: Record<string, unknown>) => appendFile(auditFile, JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n', { mode: 0o600 }).catch(() => {});

  /** Redacts a parsed request body; returns an error message if policy says to refuse it. */
  /** observe: body is the client's real outgoing content (proxy path), not a hook's mix of stand-ins and values. */
  async function redactRequest(body: any, protocol: Protocol, where: string, observe = false): Promise<{ outcome: RedactOutcome; refuse?: string }> {
    const t0 = performance.now();
    syncCredentials();
    const outcome = await redactBody(body, protocol, redactor, { observe });
    stats.requests++;
    stats.scannedChars += outcome.chars;
    stats.lastRequest = { strings: outcome.strings, chars: outcome.chars, ms: Math.round(performance.now() - t0) };
    log(`${where}: ${outcome.strings} strings, ${outcome.chars} chars, ${outcome.findings.length} findings, ${stats.lastRequest.ms} ms`);
    if (outcome.changed) stats.redacted++;
    stats.findings += outcome.findings.length;
    const errs = [...new Map(outcome.errors.map((e) => [e.detector, e])).values()];
    stats.errors += errs.length;
    if (outcome.findings.length || errs.length) {
      audit({
        where, protocol, errors: errs,
        findings: outcome.findings.map((f) => ({
          label: f.label, placeholder: redactor.vault.placeholder(f.value, f.label, f.parts), votes: f.votes, threshold: f.threshold,
          voters: f.voters.map((v) => v.detector), abstained: f.abstained,
        })),
      });
    }
    if (errs.length && config.onDetectorError === 'block') return { outcome, refuse: `agent-understudy: detector failed (${errs.map((e) => e.detector).join(', ')}); refusing to forward` };
    return { outcome };
  }

  async function control(req: http.IncomingMessage, res: http.ServerResponse, url: URL) {
    const json = (code: number, v: unknown) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(v)); };
    // Browsers can't be made to send the header, and pages on other origins must not reach us at all.
    if (url.pathname !== '/api/status' && req.headers.authorization !== `Bearer ${token}`) return json(401, { error: 'agent-understudy: missing or wrong api token (~/.agent-understudy/api.token)' });
    const body = req.method === 'POST' ? JSON.parse((await readBody(req)).toString() || '{}') : {};
    const needStore = () => { if (!credentials) throw new Error('credentials are not enabled on this gateway'); return credentials; };
    switch (url.pathname) {
      case '/api/secret/put': {
        // From the MCP server's native dialog or the CLI: store, then redact the value from now on.
        const info = needStore().set(String(body.cwd), String(body.name), String(body.value), body.scope === 'project' ? 'project' : 'session');
        redactor.vault.addCredential(info.name, String(body.value));
        return json(200, { ...info, ref: `Hide(${info.name})`, env: `AGENT_SECRET_${info.name}` });
      }
      case '/api/secret/list':
        return json(200, { credentials: needStore().list(String(body.cwd)) });
      case '/api/secret/env': {
        const names = (body.names as string[] | undefined) ?? needStore().list(String(body.cwd)).map((c) => c.name);
        const values = needStore().values(String(body.cwd), names);
        return json(200, { env: Object.fromEntries(Object.entries(values).map(([n, v]) => [`AGENT_SECRET_${n}`, v])), missing: names.filter((n) => !(n in values)) });
      }
      case '/api/secret/envfile': {
        // For hooks: agent sandboxes (codex workspace-write, Claude Code sandbox mode) block the network, so a
        // command can't fetch its credentials itself. The hook, outside the sandbox, asks for a one-shot file:
        // random name, 0600, in the temp dir sandboxes may read and delete; the command sources and removes it.
        const names = (body.names as string[] | undefined) ?? [];
        const values = needStore().values(String(body.cwd), names);
        const missing = names.filter((n) => !(n in values));
        if (missing.length) return json(404, { error: `no credential ${missing.join(', ')} for this project`, missing });
        const file = path.join(os.tmpdir(), `agent-understudy-${randomBytes(12).toString('hex')}.env`);
        writeFileSync(file, Object.entries(values).map(([n, v]) => `export AGENT_SECRET_${n}=${shq(v)}\n`).join(''), { mode: 0o600 });
        // Normally the command deletes it, and hooks release it once the tool has run; this covers a command that
        // never ran (refused, or an approval that took longer than anyone should wait).
        setTimeout(() => rmSync(file, { force: true }), 15 * 60_000).unref();
        return json(200, { file });
      }
      case '/api/secret/release': {
        const file = String(body.file ?? '');
        // Only our own one-shot files in the temp dir.
        if (path.dirname(file) === os.tmpdir() && /^agent-understudy-[0-9a-f]{24}\.env$/.test(path.basename(file))) rmSync(file, { force: true });
        return json(200, { ok: true });
      }
      case '/api/secret/remove': {
        const removed = needStore().remove(String(body.cwd), String(body.name));
        if (removed && !needStore().allValues().some((c) => c.name === body.name)) redactor.vault.removeCredential(String(body.name));
        return json(200, { removed });
      }
      case '/api/hook/hello': {
        const key = `${String(body.host)}:${projectOf(String(body.cwd)).root}`;
        const h = hookSessions.get(key) ?? { at: 0, sessions: new Map<string, number>() };
        h.at = Date.now();
        if (body.session) h.sessions.set(String(body.session), Date.now());
        hookSessions.set(key, h);
        return json(200, { ok: true });
      }
      case '/api/hook/active': {
        const h = hookSessions.get(`${String(body.host)}:${projectOf(String(body.cwd)).root}`);
        const hooks = !!h && Date.now() - h.at < 24 * 3600_000;
        // The MCP server can't tell which session is asking, so fail closed: every session of this project that
        // started recently must be routed through here. A second, unrouted codex in the same project turns the
        // masked TUI path off for all of them (they get the system dialog instead).
        const recent = h ? [...h.sessions].filter(([, at]) => Date.now() - at < 12 * 3600_000).map(([s]) => s) : [];
        const routed = recent.length > 0 && recent.every((s) => proxiedSessions.has(s));
        return json(200, { active: hooks && routed, hooks, routed });
      }
      case '/api/secret/ask': {
        // The whole "ask the person" flow, for every front-end (MCP tool, opencode tool): a native masked
        // dialog where there is a desktop, else a one-time local page opened in the browser.
        const store = needStore();
        const name = String(body.name); const cwd = String(body.cwd); const description = String(body.description ?? '');
        if (!NAME_RE.test(name)) return json(400, { error: 'name must be UPPER_SNAKE_CASE, e.g. OPENROUTER_API_KEY' });
        const finish = (scope: string) => json(200, { stored: true, ref: `Hide(${name})`, env: `AGENT_SECRET_${name}`, scope });
        if (hasGui()) {
          for (;;) {
            const ans = await macDialog(name, description, projectOf(cwd).root);
            if (!ans) return json(200, { stored: false, reason: 'the user cancelled' });
            try { store.set(cwd, name, ans.value, ans.scope); } catch (e) {
              // Bad value (too short, multi-line) or no keychain: say why and ask again.
              const why = (e as Error).message;
              const again = await macDialog(name, `${why}\n\n${description}`, projectOf(cwd).root);
              if (!again) return json(200, { stored: false, reason: `the user cancelled (${why})` });
              try { store.set(cwd, name, again.value, again.scope); } catch (e2) { return json(200, { stored: false, reason: (e2 as Error).message }); }
              redactor.vault.addCredential(name, again.value);
              return finish(again.scope);
            }
            redactor.vault.addCredential(name, ans.value);
            return finish(ans.scope);
          }
        }
        const id = randomBytes(18).toString('base64url');
        const p = { name, description, cwd, at: Date.now() } as { name: string; description: string; cwd: string; at: number; done?: { scope: string } | { error: string } };
        prompts.set(id, p);
        const pageUrl = `http://127.0.0.1:${config.port}/secret/${id}`;
        openUrl(pageUrl);
        const deadline = Date.now() + 600_000;
        while (!p.done && Date.now() < deadline) await new Promise((r) => setTimeout(r, 300));
        prompts.delete(id);
        if (!p.done) return json(200, { stored: false, reason: `no answer within 10 minutes (the page was ${pageUrl})` });
        if ('error' in p.done) return json(200, { stored: false, reason: p.done.error });
        return finish(p.done.scope);
      }
      case '/api/status':
        return json(200, {
          ok: true, stats, vaultSize: redactor.vault.size, detectors: redactor.detectors.map((d) => d.id),
          policy: redactor.policy, upstreams: config.upstreams,
          // Where the host integrations live, so launchers (agent-bridge) can wire them in.
          paths: {
            opencodePlugin: path.resolve(import.meta.dirname, '../../hooks/opencode/agent-understudy.ts'),
            claudeMod: path.resolve(import.meta.dirname, '../../hooks/claude'),
            cli: path.resolve(import.meta.dirname, '../../bin/understudy'),
            node: process.execPath,
          },
          sidecar: sidecar ? await sidecar.health().then((h) => h.models).catch((e) => ({ error: String(e.message) })) : null,
        });
      case '/api/scan': {
        // Votes only; values are returned to the local caller (hooks/MCP decide what to show a model).
        const r = await redactor.scan(String(body.text ?? ''));
        return json(200, r);
      }
      case '/api/redact': {
        const r = await redactor.redact(String(body.text ?? ''));
        return json(200, { text: r.text, changed: r.changed, errors: r.errors, findings: r.findings.map(({ value: _v, ...f }) => f) });
      }
      case '/api/redact-json': {
        // Strings at the top level can't be mutated in place; wrap them.
        const box = { value: body.value };
        const { outcome, refuse } = await redactRequest(box, body.protocol ?? 'raw', String(body.where ?? 'api'));
        return json(refuse ? 409 : 200, { value: box.value, changed: outcome.changed > 0, refuse });
      }
      case '/api/restore':
        return json(200, { text: restore(String(body.text ?? ''), body.json ? (s) => JSON.stringify(s).slice(1, -1) : undefined) });
      case '/api/stream-restore': {
        // { key, delta } -> text safe to show now; { key, flush: true } -> the held tail.
        const key = String(body.key ?? '');
        let h = hookStreams.get(key);
        if (!h) { h = { r: new StreamRestorer(restore, hold), at: Date.now() }; hookStreams.set(key, h); }
        h.at = Date.now();
        const text = body.flush ? h.r.flush('s') : h.r.push('s', String(body.delta ?? ''));
        if (body.flush) hookStreams.delete(key);
        for (const [k, v] of hookStreams) if (Date.now() - v.at > 600_000) hookStreams.delete(k);
        return json(200, { text });
      }
      case '/api/scrub': {
        // Credential values only (tool records the person reads in the UI keep their real PII).
        syncCredentials();
        let changed = false;
        const walk = (v: any): any => {
          if (typeof v === 'string') { const s = redactor.vault.scrubCredentials(v); if (s !== v) changed = true; return s; }
          if (Array.isArray(v)) return v.map(walk);
          if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
          return v;
        };
        const value = walk(body.value);
        return json(200, { value, changed });
      }
      case '/api/residue': {
        // Stand-ins left in an already-restored value (tool arguments about to run, files about to be committed).
        const text = typeof body.value === 'string' ? body.value : JSON.stringify(body.value ?? '');
        return json(200, { residue: redactor.vault.residue(text) });
      }
      case '/api/restore-json':
        return json(200, { value: restoreDeep(body.value, restore) });
      default:
        return json(404, { error: 'not found' });
    }
  }

  async function proxy(req: http.IncomingMessage, res: http.ServerResponse, url: URL) {
    const r = route(url.pathname + url.search, config.upstreams);
    if (!r) { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('agent-understudy: unknown route'); return; }
    const protocol = protocolFor(url.pathname);
    const sid = req.headers['session-id'] ?? req.headers['session_id'];
    if (typeof sid === 'string' && sid) proxiedSessions.set(sid, Date.now());
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (v !== undefined && !HOP.has(k)) headers[k] = Array.isArray(v) ? v.join(', ') : v;
    headers['accept-encoding'] = 'identity';

    let body: Buffer | undefined;
    let wantsStream = /event-stream/.test(String(req.headers.accept ?? ''));
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      body = decode(await readBody(req), req.headers['content-encoding'] as string | undefined);
      if (protocol && body.length && /json/.test(String(req.headers['content-type'] ?? 'application/json'))) {
        const parsed = JSON.parse(body.toString('utf8'));
        if (parsed?.stream === true) wantsStream = true;
        const { outcome, refuse } = await redactRequest(parsed, protocol, `${r.name}${url.pathname}`, true);
        if (refuse) { res.writeHead(503, { 'content-type': 'application/json' }); res.end(JSON.stringify({ type: 'error', error: { type: 'api_error', message: refuse } })); return; }
        if (outcome.changed) body = Buffer.from(JSON.stringify(parsed));
      }
      if (body?.length) dump(`${r.name}${url.pathname}`, body.toString('utf8'));
    }

    let up: Response;
    try {
      up = await fetch(r.target, { method: req.method, headers, body: body as BodyInit | undefined, redirect: 'manual', signal: abortOn(res) });
    } catch (e) {
      if (res.headersSent || res.destroyed) return;
      res.writeHead(502, { 'content-type': 'text/plain' }); res.end(`agent-understudy: upstream error: ${(e as Error).message}`); return;
    }
    const outHeaders: Record<string, string> = {};
    up.headers.forEach((v, k) => { if (!HOP.has(k)) outHeaders[k] = v; });
    const ctype = up.headers.get('content-type') ?? '';

    // chatgpt.com's codex /responses streams SSE without a content-type: go by what was asked for too.
    if (protocol && up.body && (ctype.includes('text/event-stream') || (!ctype && wantsStream))) {
      res.writeHead(up.status, outHeaders);
      const t = transformFor(protocol, restore, hold);
      const sse = new SseParser();
      const emit = (raw: string) => {
        const ev = parseEvent(raw);
        if (ev.data === undefined || ev.data === '[DONE]' || !ev.data.includes('{')) { res.write(raw + '\n\n'); return; }
        let data: any;
        try { data = JSON.parse(ev.data); } catch { res.write(raw + '\n\n'); return; }
        for (const o of t.event(ev.event, data)) res.write(formatEvent({ event: o.event, data: JSON.stringify(o.data), other: ev.other }));
      };
      try {
        for await (const chunk of up.body) for (const raw of sse.feed(chunk)) emit(raw);
        for (const raw of sse.end()) emit(raw);
      } catch (e) { log(`stream error: ${(e as Error).message}`); }
      res.end();
      return;
    }
    const buf = Buffer.from(await up.arrayBuffer());
    if (protocol && ctype.includes('json')) {
      const out = Buffer.from(JSON.stringify(restoreDeep(JSON.parse(buf.toString('utf8')), restore)));
      res.writeHead(up.status, outHeaders); res.end(out); return;
    }
    res.writeHead(up.status, outHeaders); res.end(buf);
  }

  /** The fallback masked-input page. The one-time id in the URL is the capability; it dies on submit. */
  async function secretPage(req: http.IncomingMessage, res: http.ServerResponse, url: URL) {
    const id = url.pathname.slice('/secret/'.length);
    const p = prompts.get(id);
    const page = (body: string) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' }); res.end(body); };
    if (!p || p.done) return page(shell('<p>This request has expired or was already answered.</p>'));
    if (req.method === 'POST') {
      const form = new URLSearchParams((await readBody(req)).toString());
      if (form.get('action') === 'cancel') { p.done = { error: 'cancelled by the user' }; return page(shell('<p>Cancelled. You can close this tab.</p>')); }
      try {
        const scope = form.get('action') === 'project' ? 'project' : 'session';
        const info = needStoreOrThrow().set(p.cwd, p.name, form.get('value') ?? '', scope);
        redactor.vault.addCredential(info.name, form.get('value') ?? '');
        p.done = { scope };
        return page(shell(`<p>Saved <b>${esc(p.name)}</b> (${scope === 'project' ? 'remembered for this project' : 'this session only'}). You can close this tab.</p>`));
      } catch (e) { return page(shell(`<p class=err>${esc((e as Error).message)}</p>${form_(p)}`)); }
    }
    return page(shell(form_(p)));
  }
  const needStoreOrThrow = () => { if (!credentials) throw new Error('credentials are not enabled'); return credentials; };
  const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const form_ = (p: { name: string; description: string; cwd: string }) => `
    <h1>${esc(p.name)}</h1><p class=d>${esc(p.description)}</p><p class=m>Project: ${esc(p.cwd)}</p>
    <form method=post autocomplete=off><input type=password name=value autofocus required minlength=8 placeholder="paste the value">
    <div class=b><button name=action value=project>Remember for this project</button><button name=action value=session>This session only</button><button name=action value=cancel formnovalidate class=c>Cancel</button></div></form>
    <p class=m>The value goes to the local agent-understudy vault. The agent's commands get it as <code>$AGENT_SECRET_${esc(p.name)}</code>; the model only ever sees <code>Hide(${esc(p.name)})</code>.</p>`;
  const shell = (inner: string) => `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width"><title>agent-understudy credential</title>
    <style>:root{color-scheme:light dark}body{font:15px system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem}input{width:100%;font:inherit;padding:.6rem;box-sizing:border-box}
    .b{display:flex;gap:.5rem;margin:.8rem 0;flex-wrap:wrap}button{font:inherit;padding:.5rem .8rem}.c{opacity:.7}.m{opacity:.65;font-size:13px}.err{color:#c33}</style>${inner}`;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (url.pathname.startsWith('/secret/')) await secretPage(req, res, url);
      else if (url.pathname.startsWith('/api/') && !url.pathname.startsWith('/api/hello')) await control(req, res, url);
      else if (url.pathname === '/api/hello' || url.pathname === '/anthropic/api/hello') { res.writeHead(200); res.end(); }
      else await proxy(req, res, url);
    } catch (e) {
      log(`error ${req.method} ${url.pathname}: ${(e as Error).stack}`);
      if (!res.headersSent) { res.writeHead(500, { 'content-type': 'text/plain' }); }
      res.end(`agent-understudy: ${(e as Error).message}`);
    }
  });

  // codex opens a WebSocket to <base>/responses by default; proxy it with the same redact/restore.
  const wss = new WebSocketServer({ noServer: true });
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const r = route(url.pathname + url.search, config.upstreams);
    if (!r || protocolFor(url.pathname) !== 'responses') { socket.end('HTTP/1.1 404 Not Found\r\n\r\n'); return; }
    wss.handleUpgrade(req, socket, head, (client) => bridgeWebSocket(client, req, r.target));
  });

  function bridgeWebSocket(client: WebSocket, req: http.IncomingMessage, target: string) {
    const sid = req.headers['session-id'] ?? req.headers['session_id'];
    if (typeof sid === 'string' && sid) proxiedSessions.set(sid, Date.now());
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined || HOP.has(k) || k.startsWith('sec-websocket-')) continue;
      headers[k] = Array.isArray(v) ? v.join(', ') : v;
    }
    const upstream = new WebSocket(target.replace(/^http/, 'ws'), { headers, perMessageDeflate: false });
    const queue: Array<Promise<string | undefined>> = [];
    let flushing = Promise.resolve();
    // Redaction is async; keep client->upstream message order.
    client.on('message', (data, isBinary) => {
      const p = (async () => {
        if (isBinary) return undefined;
        const msg = JSON.parse(data.toString());
        const { refuse } = await redactRequest(msg, 'responses', 'codex-ws', true);
        if (refuse) { client.close(1011, refuse.slice(0, 120)); return undefined; }
        return JSON.stringify(msg);
      })().catch((e) => { log(`ws redact error: ${e.message}`); client.close(1011, 'agent-understudy error'); return undefined; });
      queue.push(p);
      flushing = flushing.then(async () => {
        const out = await queue.shift()!;
        if (out === undefined) return;
        if (upstream.readyState === WebSocket.CONNECTING) await new Promise((r) => upstream.once('open', r));
        if (upstream.readyState === WebSocket.OPEN) { dump('codex-ws', out); upstream.send(out); }
      });
    });
    let t = responsesStream(restore, hold);
    upstream.on('message', (data, isBinary) => {
      if (isBinary) { client.send(data, { binary: true }); return; }
      let ev: any;
      try { ev = JSON.parse(data.toString()); } catch { client.send(data.toString()); return; }
      for (const o of t.event(undefined, ev)) client.send(JSON.stringify(o.data));
      if (ev?.type === 'response.completed' || ev?.type === 'response.failed') t = responsesStream(restore, hold);
    });
    upstream.on('unexpected-response', (_req, res) => {
      log(`ws upstream refused: ${res.statusCode}`);
      client.close(1011, `upstream ${res.statusCode}`);
    });
    upstream.on('close', (code, reason) => { if (client.readyState === WebSocket.OPEN) client.close(code === 1005 ? 1000 : code, reason); });
    upstream.on('error', (e) => { log(`ws upstream error: ${e.message}`); if (client.readyState === WebSocket.OPEN) client.close(1011, 'upstream error'); });
    client.on('close', () => upstream.close());
    client.on('error', () => upstream.close());
  }

  return { server, stats };
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const parts: Buffer[] = [];
    req.on('data', (c) => parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts)));
    req.on('error', reject);
  });
}

function abortOn(res: http.ServerResponse): AbortSignal {
  const ac = new AbortController();
  res.on('close', () => { if (!res.writableFinished) ac.abort(); });
  return ac.signal;
}
