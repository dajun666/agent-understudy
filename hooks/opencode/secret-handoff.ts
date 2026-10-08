// Hand-off between the opencode server plugin (secret_request tool) and the opencode TUI plugin.
//
// They can't talk directly: the server plugin runs in opencode's server worker (or another process
// for `opencode attach`), the TUI plugin in the TUI thread, and opencode gives plugins no channel
// between the two. So they meet in a private directory (<agent-understudy home>/opencode-asks, 0700):
//
//   server  writes  <id>.ask.json     {name, description, cwd, gateway, sessionID, callID}  (no value)
//   TUI     creates <id>.claim        O_EXCL: exactly one TUI shows the dialog
//   server  creates <id>.claim        itself after a short wait when no TUI did -> native dialog fallback
//   TUI     sends the value straight to the gateway (/api/secret/put), never through opencode
//   TUI     writes  <id>.answer.json  {stored, scope, createdAt} or {stored:false, reason}  (no value)
//   server  removes all of them when the tool call ends; the TUI closes its dialog when .ask.json goes
//
// The id is derived from the session and tool call, which the TUI sees in the tool part events.
import { createHash, randomBytes } from 'node:crypto'
import { mkdirSync, chmodSync, readdirSync, statSync, readFileSync, rmSync } from 'node:fs'
import { access, open, readFile, rename, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

export type Ask = { name: string; description: string; cwd: string; gateway: string; sessionID: string; callID: string; at: number }
export type Answer = { stored: true; scope: 'project' | 'session'; createdAt?: string } | { stored: false; reason: string }

export const agentUnderstudyHome = () => process.env.AGENT_UNDERSTUDY_HOME ?? path.join(os.homedir(), '.agent-understudy')
export const asksDir = (home = agentUnderstudyHome()) => path.join(home, 'opencode-asks')
export const askId = (sessionID: string, callID: string) => createHash('sha256').update(`${sessionID}\0${callID}`).digest('hex').slice(0, 32)
export const readToken = (home = agentUnderstudyHome()) => readFileSync(path.join(home, 'api.token'), 'utf8').trim()

const file = (dir: string, id: string, kind: 'ask.json' | 'claim' | 'answer.json') => path.join(dir, `${id}.${kind}`)

function ensureDir(dir: string) {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
}

async function writeAtomic(target: string, data: string) {
  const tmp = `${target}.${randomBytes(6).toString('hex')}.tmp`
  await writeFile(tmp, data, { mode: 0o600 })
  await rename(tmp, target)
}

/** O_EXCL create: true for exactly one caller. */
export async function claim(dir: string, id: string, who: string): Promise<boolean> {
  try {
    const fh = await open(file(dir, id, 'claim'), 'wx', 0o600)
    await fh.writeFile(who)
    await fh.close()
    return true
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST' || (e as NodeJS.ErrnoException).code === 'ENOENT') return false
    throw e
  }
}

const sleep = (ms: number, signal?: AbortSignal) => new Promise<void>((resolve) => {
  const t = setTimeout(resolve, ms)
  signal?.addEventListener('abort', () => { clearTimeout(t); resolve() }, { once: true })
})

// ---------------------------------------------------------------------------------------------
// Server side

export type ServerAskOptions = {
  dir?: string
  /** How long a TUI has to claim the request before we fall back. */
  claimMs?: number
  /** How long the person has to answer. */
  answerMs?: number
  pollMs?: number
  signal?: AbortSignal
}

/**
 * Publishes the request and waits for a TUI to answer it.
 * Returns undefined when no TUI claimed it (the caller falls back to the gateway's own dialog).
 */
export async function askViaTui(ask: Omit<Ask, 'at'>, opts: ServerAskOptions = {}): Promise<Answer | undefined> {
  const dir = opts.dir ?? asksDir()
  const claimMs = opts.claimMs ?? 3000
  const answerMs = opts.answerMs ?? 600_000
  const pollMs = opts.pollMs ?? 150
  ensureDir(dir)
  sweep(dir)
  const id = askId(ask.sessionID, ask.callID)
  await writeAtomic(file(dir, id, 'ask.json'), JSON.stringify({ ...ask, at: Date.now() }))
  try {
    const claimDeadline = Date.now() + claimMs
    let claimed = false
    while (!opts.signal?.aborted) {
      if (await exists(file(dir, id, 'claim'))) { claimed = true; break }
      if (Date.now() >= claimDeadline) {
        // Take it ourselves; if a TUI got there in the same instant, its claim wins.
        claimed = !(await claim(dir, id, 'server-fallback'))
        break
      }
      await sleep(Math.min(pollMs, 50), opts.signal)
    }
    if (opts.signal?.aborted) return { stored: false, reason: 'the tool call was aborted' }
    if (!claimed) return undefined
    const deadline = Date.now() + answerMs
    while (!opts.signal?.aborted && Date.now() < deadline) {
      const raw = await readFile(file(dir, id, 'answer.json'), 'utf8').catch(() => undefined)
      if (raw !== undefined) return parseAnswer(raw)
      await sleep(pollMs, opts.signal)
    }
    if (opts.signal?.aborted) return { stored: false, reason: 'the tool call was aborted' }
    return { stored: false, reason: `no answer within ${Math.round(answerMs / 60_000)} minutes` }
  } finally {
    await Promise.all((['ask.json', 'claim', 'answer.json'] as const).map((k) => rm(file(dir, id, k), { force: true })))
  }
}

function parseAnswer(raw: string): Answer {
  try {
    const a = JSON.parse(raw)
    if (a?.stored === true && (a.scope === 'project' || a.scope === 'session')) return { stored: true, scope: a.scope, createdAt: typeof a.createdAt === 'string' ? a.createdAt : undefined }
    return { stored: false, reason: typeof a?.reason === 'string' ? a.reason.slice(0, 300) : 'the user cancelled' }
  } catch {
    return { stored: false, reason: 'unreadable answer from the TUI' }
  }
}

/** Leftovers from crashed sessions. */
function sweep(dir: string) {
  try {
    for (const f of readdirSync(dir)) {
      const p = path.join(dir, f)
      try { if (Date.now() - statSync(p).mtimeMs > 3_600_000) rmSync(p, { force: true }) } catch { /* raced */ }
    }
  } catch { /* no dir */ }
}

async function exists(p: string) {
  try { await access(p); return true } catch { return false }
}

// ---------------------------------------------------------------------------------------------
// TUI side

/** Reads the request for a tool call the TUI just saw running; waits briefly for the server to write it. */
export async function readAsk(sessionID: string, callID: string, opts: { dir?: string; waitMs?: number } = {}): Promise<{ id: string; ask: Ask } | undefined> {
  const dir = opts.dir ?? asksDir()
  const id = askId(sessionID, callID)
  const deadline = Date.now() + (opts.waitMs ?? 2000)
  for (;;) {
    const raw = await readFile(file(dir, id, 'ask.json'), 'utf8').catch(() => undefined)
    if (raw !== undefined) {
      try { return { id, ask: JSON.parse(raw) as Ask } } catch { return undefined }
    }
    if (Date.now() >= deadline) return undefined
    await sleep(50)
  }
}

/** True while the server still waits for this request. */
export const askOpen = (id: string, dir = asksDir()) => exists(file(dir, id, 'ask.json'))

export async function answer(id: string, a: Answer, dir = asksDir()) {
  if (!(await askOpen(id, dir))) return false
  await writeAtomic(file(dir, id, 'answer.json'), JSON.stringify(a))
  return true
}

export type PutResult = { ok: true; scope: 'project' | 'session'; createdAt?: string } | { ok: false; error: string }

/**
 * Stores the value at the gateway. The only place the value travels: TUI memory -> localhost gateway.
 * Error text never echoes the value back.
 */
export async function putSecret(ask: Pick<Ask, 'gateway' | 'cwd' | 'name'>, value: string, scope: 'project' | 'session', opts: { token?: string; fetch?: typeof fetch } = {}): Promise<PutResult> {
  const scrub = (s: string) => (value ? s.split(value).join('[value]') : s).slice(0, 300)
  try {
    const r = await (opts.fetch ?? fetch)(ask.gateway.replace(/\/+$/, '') + '/api/secret/put', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${opts.token ?? readToken()}` },
      body: JSON.stringify({ cwd: ask.cwd, name: ask.name, value, scope }),
    })
    const text = await r.text()
    if (!r.ok) return { ok: false, error: scrub(text.replace(/^agent-understudy:\s*/, '') || `gateway answered ${r.status}`) }
    const body = JSON.parse(text)
    if (body.error) return { ok: false, error: scrub(String(body.error)) }
    return { ok: true, scope: body.scope === 'project' ? 'project' : 'session', createdAt: body.createdAt }
  } catch (e) {
    return { ok: false, error: scrub(`gateway unreachable (${(e as Error).message}). Start it with \`understudy up\`.`) }
  }
}
