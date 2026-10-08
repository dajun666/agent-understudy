// Claude Code mod for agent-understudy.
//
// Every row the conversation keeps (prompts, tool results, injected context, the model's own text)
// is redacted before it is stored or sent, so the transcript file holds placeholders too. The model answers with placeholders; tool calls get the real values back just
// before they run, and streamed text is restored for display (and redacted again when stored).
//
// No daemon: on session start the mod runs `agent-understudy engine` as a child of the session. It lives
// exactly as long as the session (or this module) and listens on a random localhost port. Launched with
// `understudy run claude`, or given the `gateway` option, the mod uses that engine instead.
import type { EngineInterface, Register } from 'claude-code'

const WITHHELD = '[agent-understudy: no engine was reachable, so this content was withheld. Is `agent-understudy` on PATH? See /debug.]'

/** The session's engine URL, once its child has said where it listens. */
let engineUrl: Promise<string> | undefined
let engineFound: ((url: string) => void) | undefined
let engineFailed: ((err: Error) => void) | undefined
const ENGINE_WAIT_MS = 8_000

function expectEngine(): Promise<string> {
  engineUrl = new Promise<string>((resolve, reject) => { engineFound = resolve; engineFailed = reject })
  engineUrl.catch(() => undefined) // reported where it is awaited
  return engineUrl
}

/** Runs the engine for the session's life: the loop below is the child's life (see $.process.spawn). */
async function runEngine($: EngineInterface, cli: string): Promise<void> {
  let said = false
  let buf = ''
  try {
    const child = $.process.spawn({ argv: [cli, 'engine'] })
    for await (const chunk of child) {
      if (chunk.stream === 'stderr') { $.ui.log(chunk.text.trimEnd(), { to: 'debug' }); continue }
      if (said) continue
      buf += chunk.text
      const nl = buf.indexOf('\n')
      if (nl < 0) continue
      said = true
      engineFound?.((JSON.parse(buf.slice(0, nl)) as { url: string }).url.replace(/\/+$/, ''))
    }
  } catch (err) {
    if (!said) engineFailed?.(err as Error)
    return
  }
  if (!said) engineFailed?.(new Error('the engine exited before it started'))
}

/** The engine to talk to: explicit, inherited from `understudy run`, or the session's own child. */
async function gatewayOf($: EngineInterface, explicit: string | undefined): Promise<string> {
  if (explicit) return explicit
  const inherited = await $.env.get('AGENT_UNDERSTUDY_GATEWAY')
  if (inherited) return inherited.replace(/\/+$/, '')
  if (!engineUrl) throw new Error('the agent-understudy engine has not been started for this session')
  // Waiting here is the hook's own time (about ten seconds); an engine is up in well under that.
  const late = $.clock.sleep(ENGINE_WAIT_MS).then(() => { throw new Error('the agent-understudy engine did not start in time') })
  late.catch(() => undefined)
  return Promise.race([engineUrl, late])
}

/** The tool's own arguments: everything on a tool.call input but the envelope. */
function argsOf(e: Record<string, unknown>): Record<string, unknown> {
  const { tool: _t, tool_use_id: _id, agentId: _a, ...args } = e
  return args
}

/** The gateway's control API needs the token from ~/.agent-understudy/api.token (0600). */
async function apiToken($: EngineInterface): Promise<string> {
  const home = (await $.env.get('AGENT_UNDERSTUDY_HOME')) ?? `${await $.env.get('HOME')}/.agent-understudy`
  return (await $.fs.read(`${home}/api.token`)).trim()
}

async function gatewayCall<T>($: EngineInterface, gateway: string, path: string, body: unknown): Promise<T> {
  const r = await $.http.fetch(gateway + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${await apiToken($)}` },
    body: JSON.stringify(body),
  })
  if (!r.ok) {
    let msg = r.text.slice(0, 200)
    try { msg = (JSON.parse(r.text) as { error?: string }).error ?? msg } catch { /* plain text */ }
    throw new Error(msg)
  }
  return JSON.parse(r.text) as T
}

async function redactValue<T>($: EngineInterface, gateway: string, value: T, where: string) {
  return gatewayCall<{ value: T; changed: boolean; refuse?: string }>($, gateway, '/api/redact-json', { value, protocol: 'raw', where })
}

/** Feeds one streamed piece to the gateway's restorer for this block; returns what is safe to show. */
async function streamRestore($: EngineInterface, gateway: string, key: string, delta: string, flush = false): Promise<string> {
  return (await gatewayCall<{ text: string }>($, gateway, '/api/stream-restore', { key, delta, flush })).text
}

async function residueOf($: EngineInterface, gateway: string, value: unknown): Promise<string[]> {
  return (await gatewayCall<{ residue: string[] }>($, gateway, '/api/residue', { value })).residue
}

/** What the model is told when a call still carries stand-ins: enough to fix it, never a real value. */
function residueMessage(residue: string[]): string {
  const refs = residue.filter((r) => r.startsWith('Hide('))
  if (refs.length) {
    return `agent-understudy: ${refs.join(', ')} is a reference, not the value. In shell commands read the credential from the environment ` +
      `instead: ${refs.map((r) => `"$AGENT_SECRET_${r.slice(5, -1)}"`).join(', ')}. Never write the value into files or commands.`
  }
  return `agent-understudy: this call still contains stand-ins that could not be mapped back to real values (${residue.map((r) => `"${r}"`).join(', ')}). ` +
    'Some names, emails and numbers in this conversation are stand-ins. Write them exactly as they appear in the conversation ' +
    '(same spelling and spacing), or use a neutral identifier (e.g. ownerId) where you were deriving one from a name. ' +
    'Do not report the task as done until the call succeeds.'
}

/** The prefix withSecrets adds; group 1 is the env file. */
const ENV_PREFIX = /^\. '([^']*agent-understudy-[0-9a-f]+\.env)' && rm -f '[^']*' &&\n/

const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`

/**
 * Wraps a command that reads $AGENT_SECRET_<NAME>: the gateway writes the values to a one-shot 0600 file
 * that the command sources and deletes, so they never appear in the command text, the transcript or the
 * process arguments, and sandboxed commands (no network) still get them. Throws when one is missing.
 */
async function withSecrets($: EngineInterface, gateway: string, command: string, cwd: string): Promise<string> {
  const names = [...new Set([...command.matchAll(/AGENT_SECRET_([A-Z][A-Z0-9_]{1,63})/g)].map((m) => m[1]!))]
  if (!names.length) return command
  const { file } = await gatewayCall<{ file: string }>($, gateway, '/api/secret/envfile', { cwd, names })
  // No braces or nested quotes: Claude Code's shell checks read those as obfuscation and refuse the call.
  return `. ${shq(file)} && rm -f ${shq(file)} &&\n${command}`
}

/**
 * What the screen shows: stored rows keep stand-ins (they are what the next request sends), so messages are
 * restored at draw time. Draws repeat on every redraw; a bounded cache keeps it to one engine call per text.
 */
const drawn = new Map<string, string>()
async function restoreForDisplay($: EngineInterface, gateway: string, text: string): Promise<string> {
  const hit = drawn.get(text)
  if (hit !== undefined) return hit
  const out = (await gatewayCall<{ text: string }>($, gateway, '/api/restore', { text })).text
  if (drawn.size > 500) drawn.delete(drawn.keys().next().value!)
  drawn.set(text, out)
  return out
}

async function restoreArgs($: EngineInterface, gateway: string, args: Record<string, unknown>) {
  return (await gatewayCall<{ value: Record<string, unknown> }>($, gateway, '/api/restore-json', { value: args })).value
}

// ---- secret_request, asked inside Claude Code ---------------------------------------------------
//
// The MCP server's secret_request pops a native dialog through the gateway. Where a person is at a
// Claude Code surface that draws input fields, the mod answers the call itself instead: a pane with
// a masked field, the value posted straight to the gateway (/api/secret/put). The MCP server is not
// called then (no `next(e)`), so no second dialog opens. Headless runs, panes the surface will not
// seat, and any failure fall through to the MCP tool and its dialog.

/** The tool as the plugin's own server (`mcp__plugin_<plugin>_<server>__…`) or a hand-added `agent-understudy` server names it. */
const SECRET_TOOL = /^mcp__(?:plugin_agent-understudy_)?agent-understudy__secret_request$/
const SECRET_PANE = 'agent-understudy-secret'
const NAME_RE = /^[A-Z][A-Z0-9_]{1,63}$/
const BULLET = '•'
/** How long the pane waits for the person before answering "no answer". */
const ASK_SECONDS = 900
const SLEEP_SLICE_SECONDS = 60

type SecretScope = 'project' | 'session'
type SecretAnswer = { stored: true; scope: SecretScope } | { stored: false; reason: string }

/**
 * The one ask in flight. Module memory only: never $.state or $.store (both are the host's, and
 * $.store is written to disk), so the value dies with this environment.
 */
type SecretAsk = {
  gateway: string
  name: string
  description: string
  cwd: string
  /** The value typed so far. */
  real: string
  /** What the field holds, as far as the mod knows: bullets as last drawn, plus anything typed since. */
  field: string
  error?: string
  busy?: boolean
  answer?: SecretAnswer
  /** The sleeping child the waiting hook reads from; killing it wakes the hook. */
  pid?: string
}

let secretAsk: SecretAsk | undefined

/**
 * Applies one edit of the masked field to the real value. `before` is the field's text before the
 * edit and lines up with `real` character for character (each a bullet or the typed character);
 * `after` is the text now. What both share at the start and the end is kept; the middle of `after`
 * is new text (typed or pasted) that replaces the middle of `real`. Typed text is never a bullet,
 * so where it lands is exact; a pure deletion inside a run of bullets is ambiguous and is taken
 * from the end of the run.
 */
function applyMaskedEdit(real: string, before: string, after: string): string {
  const max = Math.min(before.length, after.length)
  let p = 0
  while (p < max && before[p] === after[p]) p++
  let s = 0
  while (s < max - p && before[before.length - 1 - s] === after[after.length - 1 - s]) s++
  return real.slice(0, p) + after.slice(p, after.length - s) + real.slice(real.length - s)
}

/** The gateway's refusal, for the pane: its JSON `{ error }` or its plain-text message. */
function gatewayReason(status: number, text: string): string {
  let msg = text
  try { msg = String((JSON.parse(text) as { error?: unknown }).error ?? text) } catch { /* plain text */ }
  return msg.replace(/^agent-understudy: /, '').slice(0, 300) || `the gateway answered ${status}`
}

/** Ends the hook's wait: the sleeping child exits and the hook's read loop with it. */
async function wakeSecretWaiter($: EngineInterface, a: SecretAsk): Promise<void> {
  const pid = a.pid
  if (!pid) return
  a.pid = '' // killed once; the loop sees the answer and spawns no other
  await $.process.run(['kill', pid]).catch(() => undefined)
}

/**
 * Waits for the person's answer inside a `$` call. A hook's own time is capped (ten seconds) but
 * time inside a `$` call is not, and a person may take minutes to find a key: so the hook reads
 * from a child that sleeps until the answer kills it. Children sleep a minute at a time, so a
 * child that is lost (or a host that ends it early) costs a respawn, not the ask. Ends with an
 * answer, after ASK_SECONDS, or when the turn is interrupted (which kills the child too).
 */
async function waitForSecretAnswer($: EngineInterface, a: SecretAsk, signal: AbortSignal): Promise<void> {
  const deadline = Date.now() + ASK_SECONDS * 1000
  while (!a.answer && !signal.aborted && Date.now() < deadline) {
    a.pid = undefined
    const child = $.process.spawn({ argv: ['/bin/sh', '-c', `echo $$; exec sleep ${SLEEP_SLICE_SECONDS}`] })
    for await (const chunk of child) {
      if (a.pid === undefined && chunk.stream === 'stdout') {
        a.pid = chunk.text.trim().split('\n')[0] ?? ''
        if (a.answer) await wakeSecretWaiter($, a)
      }
    }
  }
  a.pid = undefined
}

function finishSecretAsk($: EngineInterface, a: SecretAsk, answer: SecretAnswer): void {
  if (a.answer) return
  a.real = ''
  a.field = ''
  a.answer = answer
  void wakeSecretWaiter($, a)
}

/** Posts the value to the gateway; a refusal is shown in the pane and the person tries again. */
async function submitSecret($: EngineInterface, a: SecretAsk, scope: SecretScope): Promise<void> {
  if (a.busy || a.answer) return
  const value = a.real
  // The buffer is cleared at every attempt: a refused value is typed again, never kept around.
  a.real = ''
  a.field = ''
  if (!value) {
    a.error = 'Enter the value first.'
    $.ui.invalidate('ui.render')
    return
  }
  a.busy = true
  a.error = undefined
  $.ui.invalidate('ui.render')
  let reason: string | undefined
  try {
    const r = await $.http.fetch(`${a.gateway}/api/secret/put`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${await apiToken($)}` },
      body: JSON.stringify({ cwd: a.cwd, name: a.name, value, scope }),
    })
    if (!r.ok) reason = gatewayReason(r.status, r.text)
  } catch (err) {
    reason = `could not reach the agent-understudy engine (${(err as Error).message.slice(0, 200)})`
  }
  a.busy = false
  if (reason !== undefined) {
    a.error = `${reason.replace(/\.$/, '')}. Enter it again.`
    $.ui.invalidate('ui.render')
    return
  }
  finishSecretAsk($, a, { stored: true, scope })
}

/** What the model receives: names and references only, never the value. */
function secretResult(name: string, answer: SecretAnswer | undefined): string {
  if (!answer) return JSON.stringify({ stored: false, reason: `no answer within ${ASK_SECONDS / 60} minutes` })
  if (!answer.stored) return JSON.stringify(answer)
  return JSON.stringify({
    stored: true,
    ref: `Hide(${name})`,
    env: `AGENT_SECRET_${name}`,
    scope: answer.scope === 'project' ? 'remembered for this project' : 'this session only',
    usage: `Use "$AGENT_SECRET_${name}" in shell commands. Output containing the value comes back as Hide(${name}).`,
  })
}

/** Takes the field's text after an edit (or at Enter) into the real value; the redraw shows bullets. */
function takeFieldText($: EngineInterface, a: SecretAsk, text: string): void {
  if (a.answer || a.busy) return
  a.real = applyMaskedEdit(a.real, a.field, text)
  a.field = text
  if (a.error && a.real) a.error = undefined
  $.ui.invalidate('ui.render')
}

export const register: Register = (on, options) => {
  const explicit = options.gateway ? String(options.gateway).replace(/\/+$/, '') : undefined
  const cli = String(options.cli ?? 'agent-understudy')
  const failClosed = options.failClosed !== false

  // Starts this session's engine (unless one was given or inherited). A module reload fires this again
  // and the old child went with the old module, so each load starts its own.
  on('session.start', async ($, e, next) => {
    const started = await next(e)
    if (!explicit && !(await $.env.get('AGENT_UNDERSTUDY_GATEWAY'))) {
      expectEngine()
      void runEngine($, cli)
    }
    return started
  })

  // The system prompt's per-session sections (environment, git status with names, memory) carry personal data
  // too. Shared sections are the engine's own text, the same for everyone: left alone, so the cache holds.
  on('prompt.compose', async ($, e, next) => {
    const composed = await next(e)
    const at = composed.sections.flatMap((sec, i) => (sec.scope === 'session' ? [i] : []))
    if (!at.length) return composed
    let texts: string[]
    try {
      const r = await redactValue($, await gatewayOf($, explicit), at.map((i) => composed.sections[i]!.text), 'claude:system')
      if (!r.changed) return composed
      texts = r.value
    } catch (err) {
      if (!failClosed) return composed
      texts = at.map(() => WITHHELD)
    }
    const sections = composed.sections.map((sec, i) => (at.includes(i) ? { ...sec, text: texts[at.indexOf(i)]! } : sec))
    return { ...composed, sections }
  })

  // The prompt as submitted: rewritten here so even the queue's record of it is clean.
  on('prompt.submit', async ($, e, next) => {
    const gateway = await gatewayOf($, explicit)
    const r = await redactValue($, gateway, e.text, 'claude:prompt')
    return next(r.changed ? { ...e, text: r.value } : e)
  }).catch(($, e, next) => (next.called || !failClosed ? next(e) : next({ ...e, text: WITHHELD })))

  // Every row before it is stored and sent: text blocks and tool_result content are rewritable;
  // thinking and tool_use blocks are pinned by the engine and come back untouched.
  on('session.append', async ($, e, next) => {
    const gateway = await gatewayOf($, explicit)
    const r = await redactValue($, gateway, e.message.content, `claude:${e.door}`)
    if (!r.changed) { $.ui.status(undefined); return next(e) }
    $.ui.status('redacted')
    return next({ ...e, message: { ...e.message, content: r.value } })
  }).catch(($, e, next) => {
    if (next.called || !failClosed) return next(e)
    $.ui.status('gateway unreachable, content withheld')
    const content = e.message.content.map((b) =>
      b.type === 'text' ? { ...b, text: WITHHELD }
        : b.type === 'tool_result' ? { ...b, content: WITHHELD }
          : b)
    return next({ ...e, message: { ...e.message, content } })
  })

  // secret_request: ask in a pane with a masked field instead of the MCP server's native dialog.
  on('tool.call', { tool: SECRET_TOOL }, async ($, e, next) => {
    const name = String((e as Record<string, unknown>).name ?? '')
    const description = String((e as Record<string, unknown>).description ?? '').slice(0, 300)
    // A bad name is the MCP server's to refuse; a second ask while one is up gets the dialog.
    if (!NAME_RE.test(name) || secretAsk) return next(e)
    // No surface that draws an Input (`claude -p`, the SDK, the mobile app alone): the dialog.
    if (!(await $.session.surfaces()).some((s) => s !== 'mobile')) return next(e)
    const a: SecretAsk = { gateway: await gatewayOf($, explicit), name, description, cwd: await $.session.cwd(), real: '', field: '' }
    secretAsk = a
    try {
      const opened = await $.ui.open({ id: SECRET_PANE, title: `Credential ${name}`, focus: true, closeOnEscape: true, holdToasts: true, rows: 12 })
      if (!opened.isPlaced) {
        // Opened by the model, not the person: a narrow terminal keeps it unseated. Use the dialog.
        secretAsk = undefined
        await $.ui.close({ id: SECRET_PANE })
        return next(e)
      }
      $.ui.status(`enter ${name} in the pane`)
      await waitForSecretAnswer($, a, next.signal)
    } finally {
      // Whatever ended the wait, nothing of the value stays behind.
      a.real = ''
      a.field = ''
    }
    secretAsk = undefined
    $.ui.status(undefined)
    await $.ui.close({ id: SECRET_PANE })
    return { result: secretResult(name, a.answer ?? (next.signal.aborted ? { stored: false, reason: 'the turn was interrupted' } : undefined)) }
  }).catch(async ($, e, next) => {
    // The pane could not be shown or the wait broke: fall back to the MCP tool's own dialog, unless
    // the person already answered here (then that answer stands).
    const a = secretAsk
    secretAsk = undefined
    if (a) { a.real = ''; a.field = '' }
    try { $.ui.status(undefined); await $.ui.close({ id: SECRET_PANE }) } catch { /* not open */ }
    if (next.called) return next(e)
    if (a?.answer) return { result: secretResult(a.name, a.answer) }
    return next(e)
  })

  // The person closing the pane (its close mark, Escape) is a cancel.
  on('ui.close', { id: SECRET_PANE }, async ($, e, next) => {
    const a = secretAsk
    if (a && e.origin.kind !== 'plugin') finishSecretAsk($, a, { stored: false, reason: 'the user cancelled' })
    return next(e)
  })

  on('ui.render', { component: 'Pane', requestId: SECRET_PANE }, async ($, e) => {
    const a = secretAsk
    if (e.surface === 'mobile') {
      const { Box, Text } = $.ui.resolve(e)
      return (
        <Box flexDirection="column">
          <Text bold>{a ? `Credential requested: ${a.name}` : 'No credential requested.'}</Text>
          <Text dimColor>Enter it in Claude Code on your computer.</Text>
        </Box>
      )
    }
    const { Box, Text, Button, Input } = $.ui.resolve(e)
    if (!a || a.answer) return <Text dimColor>No credential requested.</Text>
    // The field is drawn as bullets only; every draw resets what the mod assumes it holds.
    const masked = BULLET.repeat(a.real.length)
    a.field = masked
    return (
      <Box flexDirection="column" gap={1}>
        <Box flexDirection="column">
          <Text bold>The agent asks for a credential: {a.name}</Text>
          {a.description ? <Text>{a.description}</Text> : null}
          <Text dimColor>Project: {a.cwd}</Text>
        </Box>
        <Box flexDirection="column">
          <Input
            key="value"
            label="Value "
            placeholder="type or paste; shown as dots"
            value={masked}
            autoFocus
            submitLabel="this session only"
            onInput={(text) => takeFieldText($, a, text)}
            onSubmit={(text) => { takeFieldText($, a, text); void submitSecret($, a, 'session') }}
          />
          <Text dimColor>{a.busy ? 'Saving…' : `${a.real.length} characters`}</Text>
          {a.error ? <Text color="error">{a.error}</Text> : null}
        </Box>
        <Box flexDirection="row" gap={1} flexWrap="wrap">
          <Button key="project" onPress={() => void submitSecret($, a, 'project')}>Remember for this project</Button>
          <Button key="session" variant="primary" onPress={() => void submitSecret($, a, 'session')}>This session only</Button>
          <Button key="clear" dimColor onPress={() => takeFieldText($, a, '')}>Clear</Button>
          <Button key="cancel" role="dismiss" onPress={() => finishSecretAsk($, a, { stored: false, reason: 'the user cancelled' })}>Cancel</Button>
        </Box>
        <Text dimColor>The value goes to the local agent-understudy gateway only. The agent gets Hide({a.name}); commands read $AGENT_SECRET_{a.name}.</Text>
      </Box>
    )
  })

  // The person reads real values: the prompt they typed, the model's answer and its tool rows are restored for
  // drawing only. A rewrite here never touches the stored row (which the next request sends).
  on('ui.render', { component: 'AssistantMessage' }, async ($, e, next) => {
    const text = await restoreForDisplay($, await gatewayOf($, explicit), e.props.text)
    return next(text === e.props.text ? e : { ...e, props: { ...e.props, text } })
  }).catch(($, e, next) => next(e))
  on('ui.render', { component: 'UserMessage' }, async ($, e, next) => {
    const text = await restoreForDisplay($, await gatewayOf($, explicit), e.props.text)
    return next(text === e.props.text ? e : { ...e, props: { ...e.props, text } })
  }).catch(($, e, next) => next(e))
  on('ui.render', { component: 'ToolUse' }, async ($, e, next) => {
    const gateway = await gatewayOf($, explicit)
    const input = await restoreArgs($, gateway, e.props.input as Record<string, unknown>)
    return next(JSON.stringify(input) === JSON.stringify(e.props.input) ? e : { ...e, props: { ...e.props, input } })
  }).catch(($, e, next) => next(e))

  // Tool calls run with real values. The tool_use block in the transcript keeps the placeholders.
  on('tool.call', async ($, e, next) => {
    // Stand-ins can be realistic names, so every call asks; it is a localhost round trip.
    const gateway = await gatewayOf($, explicit)
    const args = argsOf(e as unknown as Record<string, unknown>)
    const restored = await restoreArgs($, gateway, args)
    // Explicit check after restoring: realistic stand-ins that slipped through would look like real data
    // in a file or a commit, so the call is refused and the model is asked to write them verbatim.
    const residue = await residueOf($, gateway, restored)
    if (residue.length) return { deny: residueMessage(residue) }
    // Project credentials: a shell command that reads $AGENT_SECRET_<NAME> gets the values at run time.
    if (e.tool === 'Bash' && typeof restored.command === 'string') {
      try { restored.command = await withSecrets($, gateway, restored.command, await $.session.cwd()) } catch (err) {
        return { deny: `agent-understudy: ${(err as Error).message}. Ask for it with the secret_request tool (the user enters it privately), then retry.` }
      }
    }
    const envFile = typeof restored.command === 'string' ? ENV_PREFIX.exec(restored.command)?.[1] : undefined
    let ran: Awaited<ReturnType<typeof next>>
    try {
      ran = await (JSON.stringify(restored) === JSON.stringify(args) ? next(e) : next({ ...e, ...restored } as typeof e))
    } finally {
      // Run, refused at the permission prompt, or failed: the one-shot env file goes either way.
      if (envFile) await gatewayCall($, gateway, '/api/secret/release', { file: envFile }).catch(() => {})
    }
    // A credential echoed by the tool must not reach the transcript's own record of the result either
    // (session.append covers what the model reads; this covers what Claude Code stores beside it).
    if (ran.deny !== undefined || ran.result === undefined) return ran
    const scrubbed = await gatewayCall<{ value: unknown; changed: boolean }>($, gateway, '/api/scrub', { value: ran.result })
    return scrubbed.changed ? { result: scrubbed.value as typeof ran.result, context: ran.context } : ran
  }).catch(($, e, next) =>
    next.called ? next(e) : { deny: 'agent-understudy: could not restore placeholders in this tool call (no engine reachable)' })

  // Permissions judge the command the model wrote. Our prefix only sources and deletes a one-shot env file, but
  // it would stop allow rules (Bash(npm test:*)) from matching and read as credential access to auto mode.
  on('tool.check', { tool: 'Bash' }, async ($, e, next) => {
    const cmd = (e.input as { command?: unknown } | undefined)?.command
    const m = typeof cmd === 'string' ? ENV_PREFIX.exec(cmd) : null
    if (!m || typeof cmd !== 'string') return next(e)
    const v = await $.tool.check({ tool: 'Bash', input: { ...(e.input as object), command: cmd.slice(m[0].length) } })
    return { decision: v.decision, reason: v.reason, rule: v.rule }
  }).catch(($, e, next) => (next.called ? next(e) : next(e)))

  // Streamed text: show the real values. The engine holds back a tail that could still become a
  // stand-in. The stored row is redacted again by session.append.
  on('turn.step', async function* ($, e, next) {
    const gateway = await gatewayOf($, explicit)
    const open = new Set<number>()
    const key = (index: number) => `${e.turnId}:${e.agentId ?? 'main'}:${e.index}:${index}`
    for await (const c of next(e)) {
      if (c.kind === 'text') {
        open.add(c.index)
        const text = await streamRestore($, gateway, key(c.index), c.text)
        if (text) yield { ...c, text }
        continue
      }
      for (const index of open) {
        const rest = await streamRestore($, gateway, key(index), '', true)
        if (rest) yield { kind: 'text' as const, index, text: rest }
      }
      open.clear()
      yield c
    }
    for (const index of open) {
      const rest = await streamRestore($, gateway, key(index), '', true)
      if (rest) yield { kind: 'text' as const, index, text: rest }
    }
    // Returning nothing keeps the result of next(e).
  })
}
