// MCP server: lets an agent pick detector models and ask "is this file safe to send?" without the
// file's sensitive values ever entering its context. Tools take paths, never raw text.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { spawnSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { gatewayClient } from '../client.ts';
import { projectOf } from '../core/credentials.ts';
import { loadConfig, saveConfig } from '../config.ts';
import { buildRedactor } from '../runtime.ts';
import { SIDECAR_MODELS, SidecarClient } from '../core/sidecar.ts';
import type { Finding } from '../core/types.ts';

const ok = (data: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] });
const fail = (e: unknown) => ({ isError: true, content: [{ type: 'text' as const, text: String((e as Error)?.message ?? e) }] });

const MAX_BYTES = 2_000_000;

export type Verdict = 'clean' | 'redact' | 'review';

/** clean: nothing found. redact: the gateway would replace values (the file is safe to send through it).
 *  review: detectors disagree below threshold — a human should look before sending. */
export function verdictOf(findings: Finding[]): Verdict {
  if (findings.some((f) => !f.redact && f.voters.some((v) => v.score >= 0.8))) return 'review';
  return findings.some((f) => f.redact) ? 'redact' : 'clean';
}

export async function main() {
  const server = new McpServer({ name: 'agent-understudy', version: '0.1.0' }, {
    instructions:
      'Local secret/PII detectors that vote. redact_scan takes file paths and reports what each detector flagged ' +
      '(placeholders and positions only — never the values) plus a verdict per file. Use it before reading or ' +
      'uploading files that may hold credentials or personal data. redact_models lists, downloads and selects the models that vote. ' +
      'When a command needs an API key or token, use secret_list / secret_request: the user enters it privately and commands read $AGENT_SECRET_<NAME>.',
  });

  server.registerTool('redact_models', {
    description: 'List detector models (license, size, pulled, voting), download one, or choose which models vote.',
    inputSchema: {
      action: z.enum(['list', 'pull', 'use']).default('list'),
      models: z.array(z.enum(Object.keys(SIDECAR_MODELS) as [string, ...string[]])).optional().describe('pull: models to download; use: the full set that should vote'),
    },
  }, async (a) => {
    try {
      const config = loadConfig();
      const dir = path.resolve(import.meta.dirname, '../../sidecar');
      const py = path.join(dir, '.venv/bin/python');
      if (a.action === 'pull') {
        const done: string[] = [];
        for (const m of a.models ?? []) {
          const r = spawnSync(py, ['-c', `import server; server.pull(server.MODELS[${JSON.stringify(m)}])`], { cwd: dir, encoding: 'utf8', timeout: 3_600_000 });
          if (r.status !== 0) throw new Error(`pull ${m} failed: ${r.stderr.slice(-400)}`);
          done.push(m);
        }
        return ok({ pulled: done });
      }
      if (a.action === 'use') {
        saveConfig({ models: a.models ?? [] });
        return ok({ voting: ['gitleaks', 'patterns', ...(a.models ?? [])], note: 'restart the gateway (understudy up) to apply there; redact_scan uses it immediately' });
      }
      const st = spawnSync(py, ['-c', 'import server, json; print(json.dumps(server.status()))'], { cwd: dir, encoding: 'utf8' });
      const status = st.status === 0 ? JSON.parse(st.stdout) : {};
      const live = await new SidecarClient(`http://127.0.0.1:${config.sidecarPort}`).health().catch(() => undefined);
      return ok({
        sidecarRunning: !!live,
        always: ['gitleaks (222 secret rules)', 'patterns (email, card+Luhn, IBAN, SSN, phone, IP, URL credentials)'],
        models: Object.keys(SIDECAR_MODELS).map((id) => ({ id, voting: config.models.includes(id), ...(status[id] ?? {}), loaded: live?.models[id]?.loaded ?? false })),
        policy: config.resolvedPolicy.mode,
      });
    } catch (e) { return fail(e); }
  });

  server.registerTool('redact_scan', {
    description: 'Scan files with the voting detectors. Returns per-file verdict (clean | redact | review) and each finding with its label, line, length, placeholder and which detectors voted — never the value.',
    inputSchema: {
      paths: z.array(z.string()).min(1).describe('Absolute or cwd-relative file paths'),
      models: z.array(z.enum(Object.keys(SIDECAR_MODELS) as [string, ...string[]])).optional().describe('Override which models vote for this scan (to compare models)'),
      mode: z.enum(['weighted', 'any', 'majority']).optional().describe('Override the voting rule for this scan'),
    },
  }, async (a) => {
    try {
      const config = loadConfig();
      const live = await new SidecarClient(`http://127.0.0.1:${config.sidecarPort}`).health().catch(() => undefined);
      const models = live ? (a.models ?? config.models) : [];
      const { redactor } = buildRedactor(config, { models });
      if (a.mode) redactor.policy = { ...redactor.policy, mode: a.mode };
      const files = [];
      for (const p of a.paths) {
        const abs = path.resolve(p);
        const size = statSync(abs).size;
        if (size > MAX_BYTES) { files.push({ path: abs, error: `too large (${size} bytes)` }); continue; }
        const text = readFileSync(abs, 'utf8');
        const r = await redactor.scan(text);
        const perDetector: Record<string, number> = {};
        for (const f of r.findings) for (const v of f.voters) perDetector[v.detector] = (perDetector[v.detector] ?? 0) + 1;
        files.push({
          path: abs, verdict: verdictOf(r.findings), perDetector, errors: r.errors,
          findings: r.findings.map((f) => {
            const before = text.slice(0, f.start);
            return {
              label: f.label, redact: f.redact, votes: f.votes, threshold: f.threshold,
              line: before.split('\n').length, column: f.start - before.lastIndexOf('\n'), length: f.value.length,
              placeholder: f.redact ? redactor.vault.placeholder(f.value, f.label, f.parts, text) : undefined,
              voters: f.voters.map((v) => `${v.detector}${v.source ? `(${v.source})` : ''}:${v.score}`),
              silent: f.abstained,
            };
          }),
        });
      }
      return ok({
        detectors: redactor.detectors.map((d) => d.id),
        note: live ? undefined : 'model sidecar not running: regex detectors only (start with `understudy up`)',
        files,
      });
    } catch (e) { return fail(e); }
  });

  // ---- project credentials ------------------------------------------------------------------------

  server.registerTool('secret_request', {
    description:
      'Ask the user for a credential this project needs (an API key, a token). The user types it into a private masked ' +
      'dialog you never see and chooses whether to remember it for this project. You get back only a reference: ' +
      'Hide(NAME). In shell commands use the environment variable $AGENT_SECRET_<NAME>; never ask the user to paste a ' +
      'secret into the chat. Call secret_list first: it may already be stored.',
    inputSchema: {
      name: z.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/).describe('UPPER_SNAKE_CASE, e.g. OPENROUTER_API_KEY'),
      description: z.string().max(300).describe('One line for the user: what it is for and where to get it'),
      fallback: z.boolean().default(false).describe('true = use the system dialog even where an in-terminal prompt is available'),
    },
  }, async (a) => {
    try {
      // codex: ask in its own TUI (masked request_user_input) when the agent-understudy codex hooks are provably live
      // for this project — they intercept the answer before the model can read it.
      const client = server.server.getClientVersion()?.name ?? '';
      if (!a.fallback && /codex/i.test(client)) {
        const cwd = await workspace();
        const { active } = await gatewayClient(loadConfig()).post<{ active: boolean }>('/api/hook/active', { host: 'codex', cwd });
        if (active) {
          return ok({
            stored: false, askInTerminal: true,
            next: 'Call request_user_input now with exactly this argument (isSecret must stay true). The agent-understudy hook ' +
              'stores the answer and returns only Hide(NAME). If request_user_input is unavailable in this mode, call ' +
              'secret_request again with fallback: true.',
            request_user_input: { questions: [{
              id: `agent_secret__${a.name}`, header: 'Credential', isSecret: true,
              question: `${a.name}: ${a.description} — choose where to keep it, press Tab, type or paste the value (masked), then Enter. The model never sees it.`,
              options: [
                { label: 'Remember for this project', description: 'Encrypted on this machine; available in later sessions.' },
                { label: 'This session only', description: 'Forgotten when the agent-understudy gateway stops.' },
              ],
            }] },
          });
        }
      }
      // The gateway runs the dialog (or the browser page) and stores the answer; the value never passes through here.
      const r = await gatewayClient(loadConfig()).post('/api/secret/ask', { cwd: await workspace(), name: a.name, description: a.description }, 660_000);
      if (!r.stored) return ok(r);
      return ok({ ...r, scope: r.scope === 'project' ? 'remembered for this project' : 'this session only',
        usage: `Use "$AGENT_SECRET_${a.name}" in shell commands. Output containing the value comes back as Hide(${a.name}).` });
    } catch (e) { return fail(e); }
  });

  server.registerTool('secret_list', {
    description: 'Names (never values) of the credentials available to commands in this project, and whether each is remembered or session-only.',
    inputSchema: {},
  }, async () => {
    try {
      const cwd = await workspace();
      const { credentials } = await gatewayClient(loadConfig()).post<{ credentials: Array<{ name: string; scope: string }> }>('/api/secret/list', { cwd });
      return ok({ project: projectOf(cwd).root, credentials: credentials.map((c) => ({ name: c.name, env: `AGENT_SECRET_${c.name}`, ref: `Hide(${c.name})`, scope: c.scope })) });
    } catch (e) { return fail(e); }
  });

  // The host's workspace: first MCP root if the client exposes roots, else our own cwd.
  async function workspace(): Promise<string> {
    if (server.server.getClientCapabilities()?.roots) {
      try {
        const { roots } = await server.server.listRoots(undefined, { timeout: 3000 });
        const first = roots.find((r) => r.uri.startsWith('file://'));
        if (first) return fileURLToPath(first.uri);
      } catch { /* fall through */ }
    }
    return process.cwd();
  }

  await server.connect(new StdioServerTransport());
}
