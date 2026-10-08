// opencode plugin for agent-understudy.
//
// opencode with a ChatGPT login ignores provider baseURL, so nothing can sit in its network path. This
// plugin redacts in-process instead: every message is redacted right before it goes to the model, tool
// calls get the real values back right before they run, and the final text is restored for display.
//
// No daemon: the plugin starts an agent-understudy engine inside opencode, on a random localhost port,
// for as long as opencode runs (vault and remembered credentials are shared with other sessions on disk;
// models come from the shared sidecar, started on demand). With "gateway" (or AGENT_UNDERSTUDY_GATEWAY)
// it uses that engine instead, e.g. a long-lived `understudy up`.
//
// Load it from opencode.json: { "plugin": ["file:///abs/path/to/agent-understudy.ts"] }
// Options (second element of the tuple form): { "gateway": "http://127.0.0.1:8790", "failClosed": true }
//
// secret_request asks inside the opencode TUI when the companion TUI plugin is loaded from tui.json:
// { "plugin": ["file:///abs/path/to/agent-understudy-tui.tsx"] }. Without it (opencode run / serve, web
// clients) the gateway's native dialog asks instead. Options: "tuiAsk": false, "tuiClaimMs": 3000.
import { tool, type Plugin, type ToolContext } from '@opencode-ai/plugin'
import { appendFileSync, readFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { askViaTui } from './secret-handoff.ts'

type Slot = { get: () => unknown; set: (v: any) => void }
type SecretOutcome = { stored: true; ref: string; env: string; scope: string } | { stored: false; reason: string }

export const AgentUnderstudy: Plugin = async (_ctx, options) => {
  const home = process.env.AGENT_UNDERSTUDY_HOME ?? path.join(os.homedir(), '.agent-understudy')
  const explicit = options?.gateway ?? process.env.AGENT_UNDERSTUDY_GATEWAY
  const log = (s: string) => { try { appendFileSync(path.join(home, 'engine.log'), `${new Date().toISOString()} [opencode ${process.pid}] ${s}\n`, { mode: 0o600 }) } catch { /* best effort */ } }
  // Started once, on first use; a failure is reported on every call (and refuses to send when failClosed).
  let engineUrl: Promise<string> | undefined
  const gatewayUrl = () => (engineUrl ??= explicit
    ? Promise.resolve(String(explicit).replace(/\/+$/, ''))
    : import('../../src/engine.ts').then((m) => m.startEngine({ log })).then((e) => { log(`engine on ${e.url}`); return e.url }))
  const failClosed = options?.failClosed !== false
  const tuiAsk = options?.tuiAsk !== false
  const tuiClaimMs = Number(options?.tuiClaimMs ?? 3000)

  // The control API needs the token from ~/.agent-understudy/api.token (0600).
  const token = () => readFileSync(path.join(home, 'api.token'), 'utf8').trim()

  async function call<T>(route: string, body: unknown): Promise<T> {
    const r = await fetch((await gatewayUrl()) + route, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token()}` }, body: JSON.stringify(body),
    })
    if (!r.ok) throw new Error(`agent-understudy gateway ${route}: ${r.status}`)
    return (await r.json()) as T
  }

  /** Redacts a batch of slots in one gateway call; refuses the request when the gateway can't be reached. */
  async function redactSlots(slots: Slot[], where: string) {
    if (!slots.length) return
    try {
      const r = await call<{ value: unknown[]; changed: boolean; refuse?: string }>('/api/redact-json', {
        value: slots.map((s) => s.get()), protocol: 'raw', where,
      })
      if (r.refuse) throw new Error(r.refuse)
      if (r.changed) slots.forEach((s, i) => s.set(r.value[i]))
    } catch (e) {
      if (failClosed) throw new Error(`agent-understudy: not sending (${(e as Error).message}). See ${path.join(home, 'engine.log')}.`)
    }
  }

  // Stand-ins can be realistic names, so there is no cheap pre-check: always ask (localhost).
  const restore = async <T>(value: T): Promise<T> => (await call<{ value: T }>('/api/restore-json', { value })).value

  /**
   * The opencode TUI (agent-understudy-tui.tsx) asks inside the terminal when it is running; otherwise the
   * gateway pops its native dialog. Either way only the outcome comes back here, never the value.
   */
  async function askForSecret(name: string, description: string, ctx: ToolContext): Promise<SecretOutcome> {
    // Not in the public ToolContext type, but opencode passes the tool call id through.
    const callID = (ctx as ToolContext & { callID?: string }).callID
    if (tuiAsk && callID) {
      type Listed = { credentials: Array<{ name: string; scope: string; createdAt?: string }> }
      const before = await call<Listed>('/api/secret/list', { cwd: ctx.directory })
      const a = await askViaTui({ name, description, cwd: ctx.directory, gateway: await gatewayUrl(), sessionID: ctx.sessionID, callID }, { signal: ctx.abort, claimMs: tuiClaimMs })
      if (a) {
        if (!a.stored) return { stored: false, reason: a.reason }
        // The TUI sent the value to the gateway itself; check it really arrived.
        const hit = (await call<Listed>('/api/secret/list', { cwd: ctx.directory })).credentials.find((c) => c.name === name)
        const prev = before.credentials.find((c) => c.name === name)
        if (!hit || (prev && hit.scope === 'project' && a.scope === 'project' && hit.createdAt === prev.createdAt)) {
          return { stored: false, reason: 'the TUI reported a stored value the gateway does not have' }
        }
        return { stored: true, ref: `Hide(${name})`, env: `AGENT_SECRET_${name}`, scope: a.scope }
      }
    }
    return call<SecretOutcome>('/api/secret/ask', { cwd: ctx.directory, name, description })
  }

  return {
    // Project credentials: the person types the value into a private dialog; the model gets Hide(NAME).
    tool: {
      secret_request: tool({
        description: 'Ask the user for a credential this project needs (API key, token). The user types it into a private masked ' +
          'dialog you never see and chooses whether to remember it for this project. You get back only Hide(NAME); shell ' +
          'commands read it as $AGENT_SECRET_<NAME>. Never ask the user to paste a secret into the chat. Check secret_list first.',
        args: {
          name: tool.schema.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/).describe('UPPER_SNAKE_CASE, e.g. OPENROUTER_API_KEY'),
          description: tool.schema.string().max(300).describe('One line for the user: what it is for and where to get it'),
        },
        async execute(args, ctx) {
          const r = await askForSecret(args.name, args.description, ctx)
          return {
            title: r.stored ? `${args.name} stored (${r.scope})` : `${args.name} not stored`,
            output: JSON.stringify(r.stored ? { ...r, usage: `Use "$AGENT_SECRET_${args.name}" in shell commands; output containing it comes back as Hide(${args.name}).` } : r),
          }
        },
      }),
      secret_list: tool({
        description: 'Names (never values) of the credentials available to shell commands in this project.',
        args: {},
        async execute(_args, ctx) {
          const r = await call<{ credentials: Array<{ name: string; scope: string }> }>('/api/secret/list', { cwd: ctx.directory })
          return {
            title: `${r.credentials.length} credential(s)`,
            output: JSON.stringify(r.credentials.map((c) => ({ name: c.name, env: `AGENT_SECRET_${c.name}`, ref: `Hide(${c.name})`, scope: c.scope }))),
          }
        },
      }),
    },

    // Everything the model is about to read. Parts are replaced with copies, so the stored session
    // (and the UI) keep the real values; only the outgoing request carries placeholders.
    'experimental.chat.messages.transform': async (_input, output) => {
      const slots: Slot[] = []
      for (const m of output.messages) {
        m.parts.forEach((p: any, i: number) => {
          const swap = (patch: (q: any) => any) => { m.parts[i] = patch(m.parts[i]) }
          if (p.type === 'text' || p.type === 'reasoning') {
            if (p.type === 'reasoning') return // provider-signed; leave as is
            slots.push({ get: () => p.text, set: (v) => swap((q) => ({ ...q, text: v })) })
          } else if (p.type === 'subtask') {
            slots.push({ get: () => p.prompt, set: (v) => swap((q) => ({ ...q, prompt: v })) })
          } else if (p.type === 'tool') {
            slots.push({ get: () => p.state.input, set: (v) => swap((q) => ({ ...q, state: { ...q.state, input: v } })) })
            if (typeof p.state.output === 'string') slots.push({ get: () => p.state.output, set: (v) => swap((q) => ({ ...q, state: { ...q.state, output: v } })) })
            if (typeof p.state.error === 'string') slots.push({ get: () => p.state.error, set: (v) => swap((q) => ({ ...q, state: { ...q.state, error: v } })) })
          }
        })
      }
      await redactSlots(slots, 'opencode:messages')
    },

    // System prompt (AGENTS.md, environment details).
    'experimental.chat.system.transform': async (_input, output) => {
      await redactSlots(output.system.map((_s, i) => ({ get: () => output.system[i], set: (v) => { output.system[i] = v } })), 'opencode:system')
    },

    // Tools run with real values.
    'tool.execute.before': async (input, output) => {
      // A command reading a credential this project doesn't have would just get an empty string.
      if (input.tool === 'bash' && typeof output.args?.command === 'string') {
        const names = [...new Set([...output.args.command.matchAll(/AGENT_SECRET_([A-Z][A-Z0-9_]{1,63})/g)].map((m: RegExpMatchArray) => m[1]!))]
        if (names.length) {
          const { credentials } = await call<{ credentials: Array<{ name: string }> }>('/api/secret/list', { cwd: process.cwd() })
          const missing = names.filter((n) => !credentials.some((c) => c.name === n))
          if (missing.length) throw new Error(`agent-understudy: no credential ${missing.join(', ')} for this project. Ask for it with the secret_request tool (the user enters it privately), then retry.`)
        }
      }
      const restored = await restore(output.args)
      // Realistic stand-ins that could not be mapped back would land in files as fake-but-plausible data.
      const { residue } = await call<{ residue: string[] }>('/api/residue', { value: restored })
      if (residue.some((r) => r.startsWith('Hide('))) {
        const refs = residue.filter((r) => r.startsWith('Hide('))
        throw new Error(`agent-understudy: ${refs.join(', ')} is a reference, not the value. Read it from the environment in shell commands: ` +
          `${refs.map((r) => `"$AGENT_SECRET_${r.slice(5, -1)}"`).join(', ')}.`)
      }
      if (residue.length) {
        throw new Error(`agent-understudy: this call still contains stand-ins that could not be mapped back (${residue.map((r) => `"${r}"`).join(', ')}). ` +
          'Write names, emails and numbers exactly as they appear in the conversation, or use a neutral identifier (e.g. ownerId) where you were deriving one from a name. Do not report the task as done until the call succeeds.')
      }
      if (JSON.stringify(restored) === JSON.stringify(output.args)) return
      for (const k of Object.keys(output.args)) delete output.args[k]
      Object.assign(output.args, restored)
    },

    // Project credentials for shell commands: $AGENT_SECRET_<NAME>. The model only ever sees Hide(NAME).
    'shell.env': async (input, output) => {
      try {
        const { env } = await call<{ env: Record<string, string> }>('/api/secret/env', { cwd: input.cwd })
        Object.assign(output.env, env)
      } catch { /* no gateway or no credentials: commands just don't get them */ }
    },

    // The answer as shown and stored.
    'experimental.text.complete': async (_input, output) => {
      output.text = (await call<{ text: string }>('/api/restore', { text: output.text })).text
    },
  }
}

export default { id: 'agent-understudy', server: AgentUnderstudy }
