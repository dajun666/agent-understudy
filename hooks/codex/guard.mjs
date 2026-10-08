#!/usr/bin/env node
// PreToolUse guard for hosts that reach the model through the gateway without an in-process plugin
// (codex; Claude Code without the mod). The gateway already restored the tool arguments; this refuses
// a call that still carries stand-ins it could not map back, so they never reach a file or a command.
//
// codex: installed by the agent-understudy codex plugin (hooks/codex), which runs it with --inject.
// claude settings.json hooks (only if you don't use the Claude Code mod): "node /abs/hooks/codex/guard.mjs", WITHOUT --inject (Claude Code's "allow" would skip its permission
// prompt; the Claude Code mod does the injection instead).
//
// --inject: a shell command that reads $AGENT_SECRET_<NAME> is rewritten to load the values from the gateway when it
// runs (codex: updatedInput requires permissionDecision "allow", which keeps codex's own sandbox and approvals).
import { readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
const gateway = (process.env.AGENT_UNDERSTUDY_GATEWAY ?? 'http://127.0.0.1:8790').replace(/\/+$/, '');
const home = process.env.AGENT_UNDERSTUDY_HOME ?? path.join(os.homedir(), '.agent-understudy');
let token = '';
// No token (gateway never ran): keep going — calls fail, and a credential answer is still withheld from the model.
try { token = readFileSync(path.join(home, 'api.token'), 'utf8').trim(); } catch { /* fall through */ }
let raw = '';
for await (const c of process.stdin) raw += c;
let input;
try { input = JSON.parse(raw); } catch { process.exit(0); }
const post = (route, body) => fetch(`${gateway}${route}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
  body: JSON.stringify(body), signal: AbortSignal.timeout(8000) }).then(async (r) => ({ ok: r.ok, body: await r.json().catch(() => ({})) }));
const SECRET_Q = /^agent_secret__([A-Z][A-Z0-9_]{1,63})$/;

// --session-start: a codex not routed through an engine talks to OpenAI directly. The hook cannot reroute it (the
// API address is fixed at launch), so it stops the session's first turn before the prompt is sent and says how to
// launch it. Routed: `understudy run codex` (sets AGENT_UNDERSTUDY_GATEWAY), or a config.toml openai_base_url on
// localhost (a long-lived `understudy up`). AGENT_UNDERSTUDY_ALLOW_UNPROTECTED=1 lets a plain codex run anyway.
// Then: tell the engine this project's codex hooks are live, so secret_request may use the masked TUI prompt.
export function isRouted(env = process.env) {
  if (env.AGENT_UNDERSTUDY_GATEWAY) return true;
  const codexHome = env.CODEX_HOME ?? path.join(os.homedir(), '.codex');
  try {
    return /^\s*openai_base_url\s*=\s*["']http:\/\/(?:127\.0\.0\.1|localhost)[:/]/m.test(readFileSync(path.join(codexHome, 'config.toml'), 'utf8'));
  } catch { return false; }
}
if (process.argv.includes('--session-start')) {
  if (!isRouted() && process.env.AGENT_UNDERSTUDY_ALLOW_UNPROTECTED !== '1') {
    process.stdout.write(JSON.stringify({
      continue: false,
      stopReason: 'agent-understudy: this codex is not protected — it talks to OpenAI directly, so your prompts and files ' +
        'would leave unredacted. Quit and start it with `understudy run codex` (same arguments). ' +
        'To run unprotected on purpose: AGENT_UNDERSTUDY_ALLOW_UNPROTECTED=1 codex',
    }) + '\n');
    process.exit(0);
  }
  await post('/api/hook/hello', { host: 'codex', cwd: input.cwd ?? process.cwd(), session: input.session_id }).catch(() => {});
  process.exit(0);
}

// Masked credential prompts ride on codex's own request_user_input (isSecret masks the notes field).
if ((input.tool_name ?? '') === 'request_user_input') {
  const questions = (input.tool_input ?? {}).questions ?? [];
  const secretQs = questions.filter((q) => SECRET_Q.test(q?.id ?? ''));
  if (!process.argv.includes('--post')) {
    // PreToolUse: an agent_secret__ question without isSecret would show the value in clear text.
    if (secretQs.some((q) => q.isSecret !== true)) {
      process.stderr.write('agent-understudy: credential questions (id agent_secret__<NAME>) must set "isSecret": true so the input is masked. Retry with it\n');
      process.exit(2);
    }
    process.exit(0);
  }
  if (!secretQs.length) process.exit(0);
  // PostToolUse: the answer holds the value. Store it, then replace the result the model would read — always,
  // even on failure, so the value never reaches the model.
  let resp = input.tool_response;
  try { if (typeof resp === 'string') resp = JSON.parse(resp); } catch { /* keep as is */ }
  const answers = resp?.answers ?? {};
  const results = [];
  for (const q of secretQs) {
    const name = SECRET_Q.exec(q.id)[1];
    const list = answers[q.id]?.answers ?? [];
    const note = list.find((a) => typeof a === 'string' && a.startsWith('user_note: '));
    const value = note ? note.slice('user_note: '.length).trim() : '';
    const scope = list.some((a) => typeof a === 'string' && a.startsWith('Remember')) ? 'project' : 'session';
    if (!value) { results.push({ name, stored: false, reason: 'no value was typed (type it after choosing an option)' }); continue; }
    try {
      const r = await post('/api/secret/put', { cwd: input.cwd ?? process.cwd(), name, value, scope });
      results.push(r.ok ? { name, stored: true, ref: `Hide(${name})`, env: `AGENT_SECRET_${name}`, scope: r.body.scope }
        : { name, stored: false, reason: r.body.error ?? 'gateway refused it' });
    } catch { results.push({ name, stored: false, reason: 'agent-understudy gateway not reachable' }); }
  }
  const usage = results.filter((r) => r.stored).map((r) => `"$${r.env}"`).join(', ');
  process.stdout.write(JSON.stringify({ decision: 'block', reason: `agent-understudy handled the credential answer (the value is not shown to you): ${JSON.stringify(results)}` +
    (usage ? `. Use ${usage} in shell commands.` : '. Ask again with secret_request if it should be retried.') }));
  process.exit(0);
}

// --post (PostToolUse): a credential echoed by the command is replaced in the result codex stores and sends.
// "block" is codex's way to substitute a result; it only fires when a credential was actually there.
if (process.argv.includes('--post')) {
  // The one-shot env file: the command deletes it itself, but not if it failed before reaching the rm.
  const envFile = /^\. '([^']*agent-understudy-[0-9a-f]+\.env)' && rm -f/.exec(String((input.tool_input ?? {}).command ?? ''))?.[1];
  if (envFile) await post('/api/secret/release', { file: envFile }).catch(() => {});
  const response = input.tool_response ?? input.toolResponse;
  if (response === undefined) process.exit(0);
  try {
    const r = await fetch(`${gateway}/api/scrub`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ value: response }), signal: AbortSignal.timeout(5000) });
    const j = await r.json();
    if (j.changed) {
      const text = typeof j.value === 'string' ? j.value : JSON.stringify(j.value);
      process.stdout.write(JSON.stringify({ decision: 'block', reason: `(agent-understudy: credentials in this output are shown as Hide(NAME))\n${text}` }));
    }
  } catch { /* no gateway: the outgoing request is still redacted by it if it is the base URL */ }
  process.exit(0);
}
const value = input.tool_input ?? input.toolInput ?? input.arguments ?? input;
let residue = [];
try {
  const r = await fetch(`${gateway}/api/residue`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify({ value }), signal: AbortSignal.timeout(5000) });
  if (r.ok) ({ residue } = await r.json());
} catch { process.exit(0); } // gateway down: this guard checks correctness, the gateway itself fails closed
const refs = residue.filter((r) => r.startsWith('Hide('));
if (refs.length) {
  process.stderr.write(`agent-understudy: ${refs.join(', ')} is a reference, not the value. Read it from the environment in shell commands: ` +
    `${refs.map((r) => `"$AGENT_SECRET_${r.slice(5, -1)}"`).join(', ')}\n`);
  process.exit(2);
}
if (residue.length) {
  process.stderr.write(`agent-understudy: this call still contains stand-ins that could not be mapped back (${residue.map((r) => `"${r}"`).join(', ')}). ` +
    'Write names, emails and numbers exactly as they appear in the conversation, or use a neutral identifier (e.g. ownerId) where you were deriving one from a name. Do not report the task as done until the call succeeds\n');
  process.exit(2); // exit 2 = block, stderr goes back to the model (Claude Code and codex hook protocol)
}

if (process.argv.includes('--inject') && typeof value?.command === 'string') {
  const names = [...new Set([...value.command.matchAll(/AGENT_SECRET_([A-Z][A-Z0-9_]{1,63})/g)].map((m) => m[1]))];
  if (names.length) {
    // The sandbox blocks the network, so the hook (outside it) gets a one-shot 0600 env file from the gateway;
    // the command sources and deletes it. Values never appear in the command, the rollout or argv.
    const r = await fetch(`${gateway}/api/secret/envfile`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ cwd: input.cwd ?? process.cwd(), names }), signal: AbortSignal.timeout(5000) }).catch(() => undefined);
    const j = r ? await r.json().catch(() => ({})) : { error: 'gateway not reachable' };
    if (!r?.ok) {
      process.stderr.write(`agent-understudy: ${j.error ?? 'could not load credentials'}. Ask for it with the secret_request tool (the user enters it privately), then retry\n`);
      process.exit(2);
    }
    const shq = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
    const command = `. ${shq(j.file)} && rm -f ${shq(j.file)} &&\n${value.command}`;
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow', updatedInput: { ...value, command } } }));
  }
}
