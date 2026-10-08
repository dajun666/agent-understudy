// secret_request answered inside Claude Code: a pane with a masked field, the value posted to the
// gateway's /api/secret/put, the model told only the reference. The gateway, the session and the
// sleeping child the hook waits on are answered by the test's own hooks beneath the plugin.
import { describe, expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

const PLUGIN = 'agent-understudy'
const TOOL = 'mcp__plugin_agent-understudy_agent-understudy__secret_request'
const PANE = 'agent-understudy-secret'
const NAME = 'OPENROUTER_API_KEY'
const SECRET = 'sk-or-v1-0123456789abcdefXYZ'
const BULLET = '•'
const SURFACES = ['terminal', 'desktop'] as const

const PANE_PROPS = {
  title: `Credential ${NAME}`,
  isFocused: true,
  bodyColumns: 100,
  placement: 'inline' as const,
  scroll: { offset: 0, bodyRows: 20 },
  view: {},
}

type World = {
  puts: Array<Record<string, unknown>>
  mcpCalls: number
  kills: string[]
  opened: number
  closed: number
  /** Resolves once the hook sleeps on its child, i.e. the pane is up and waiting. */
  waiting: () => Promise<void>
  /** Ends the current child as its sleep running out would; resolves once the hook sleeps on the next. */
  rollover: () => Promise<void>
}

type WorldOptions = {
  surfaces?: readonly ('terminal' | 'desktop' | 'mobile' | 'vscode')[]
  placed?: boolean
  /** Answers for /api/secret/put, in order; past the list, 200. */
  putAnswers?: Array<{ status: number; text: string }>
}

function world(on: On, opts: WorldOptions = {}): World {
  let sleeping: () => void = () => {}
  let isWaiting = new Promise<void>((resolve) => { sleeping = resolve })
  let end: (killed: boolean) => void = () => {}
  const w: World = {
    puts: [], mcpCalls: 0, kills: [], opened: 0, closed: 0,
    waiting: () => isWaiting,
    rollover: () => {
      isWaiting = new Promise<void>((resolve) => { sleeping = resolve })
      end(false)
      return isWaiting
    },
  }
  const putAnswers = [...(opts.putAnswers ?? [])]

  mock.env(on, { HOME: '/home/test', AGENT_UNDERSTUDY_GATEWAY: 'http://127.0.0.1:8790' })
  on('fs.read', () => ({ value: 'test-token\n' }))
  on('session.cwd', () => ({ value: '/work/project' }))
  on('session.surfaces', () => ({ value: opts.surfaces ?? ['terminal'] }))
  on('ui.open', () => { w.opened++; return { value: opts.placed === false ? { isPlaced: false as const, reason: 'narrow' } : { isPlaced: true as const } } })
  on('ui.close', () => { w.closed++; return { value: undefined } })
  on('ui.status', () => ({ value: undefined }))
  on('http.fetch', ($, e) => {
    const path = new URL(e.url).pathname
    const body = JSON.parse(e.init?.body ?? '{}') as Record<string, unknown>
    expect(e.init?.headers?.authorization).toBe('Bearer test-token')
    const answer = (status: number, text: string) => ({ value: { status, ok: status < 300, headers: {}, text } })
    if (path === '/api/restore-json') return answer(200, JSON.stringify({ value: body.value }))
    if (path === '/api/residue') return answer(200, JSON.stringify({ residue: [] }))
    if (path === '/api/scrub') return answer(200, JSON.stringify({ value: body.value, changed: false }))
    if (path === '/api/secret/put') {
      w.puts.push(body)
      const next = putAnswers.shift()
      if (next) return answer(next.status, next.text)
      return answer(200, JSON.stringify({ name: body.name, scope: body.scope, project: '/work/project', ref: `Hide(${String(body.name)})`, env: `AGENT_SECRET_${String(body.name)}` }))
    }
    throw new Error(`unexpected gateway call ${path}`)
  })
  // The sleeping child: prints its pid, then ends when killed or when the test rolls it over (its
  // minute ran out; the hook spawns the next). A test hook's wait counts against its own ten-second
  // budget, so the tests roll children over between acts.
  let pid = 4241
  on('process.spawn', async function* () {
    pid++
    yield { stream: 'stdout' as const, text: `${pid}\n` }
    const killed = new Promise<boolean>((resolve) => { end = resolve })
    sleeping()
    const wasKilled = await killed
    return { value: wasKilled ? { code: null, signal: 'SIGTERM' } : { code: 0, signal: null } }
  })
  on('process.run', ($, e) => {
    expect(e.argv[0]).toBe('kill')
    w.kills.push(String(e.argv[1]))
    end(true)
    return { value: { exitCode: 0, stdout: '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
  })
  // The MCP server's own handling (the native dialog): reached only on a fallback.
  on('tool.call', { tool: TOOL }, () => {
    w.mcpCalls++
    return { result: JSON.stringify({ stored: true, ref: `Hide(${NAME})`, env: `AGENT_SECRET_${NAME}`, scope: 'this session only', via: 'native dialog' }) }
  })
  return w
}

function resultText(r: { result?: unknown; deny?: string }): string {
  expect(r.deny).toBeUndefined()
  return typeof r.result === 'string' ? r.result : JSON.stringify(r.result)
}

describe('secret_request in the TUI', () => {
  for (const surface of SURFACES) {
    test(`${surface}: typed, pasted and corrected value is masked and reaches only the gateway`, { timeoutMs: 30_000 }, async ($, on) => {
      const w = world(on, { surfaces: [surface] })
      const call = $.tool.call({ tool: TOOL, name: NAME, description: 'For OpenRouter calls in scripts/run.sh' })
      await w.waiting()
      expect(w.opened).toBe(1)

      const ui = await $.ui.mount({ plugin: PLUGIN, surface, component: 'Pane', requestId: PANE, props: PANE_PROPS })
      // What the pane shows: the name, the model's description, the project, an empty masked field, three choices.
      expect(await ui.find({ type: 'Text', text: NAME })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: 'For OpenRouter calls in scripts/run.sh' })).toBeDefined()
      expect(await ui.find({ type: 'Text', text: '/work/project' })).toBeDefined()
      expect((await ui.find({ key: 'project' }))?.text).toBe('Remember for this project')
      expect((await ui.find({ key: 'session' }))?.text).toBe('This session only')
      expect((await ui.find({ key: 'cancel' }))?.text).toBe('Cancel')

      const field = async () => String((await ui.find({ type: 'Input', key: 'value' }))?.props.value ?? '')
      const expectMasked = async (length: number) => {
        expect(await field()).toBe(BULLET.repeat(length))
        const drawn = JSON.stringify(await ui.drawn())
        for (const piece of ['sk-', 'or-v1', '0123', 'abcdef', 'XYZ', 'Q']) expect(drawn.includes(piece)).toBe(false)
      }
      expect(await field()).toBe('')

      // Typing one character at a time: the field holds bullets plus the new character, then is redrawn.
      await ui.input({ key: 'value', text: 's', kind: 'change' })
      await expectMasked(1)
      await w.rollover()
      await ui.input({ key: 'value', text: `${BULLET}k`, kind: 'change' })
      await expectMasked(2)
      await w.rollover()
      // A paste of the rest in one edit.
      await ui.input({ key: 'value', text: `${BULLET}${BULLET}${SECRET.slice(2)}Q`, kind: 'change' })
      await expectMasked(SECRET.length + 1)
      await w.rollover()
      // Backspace takes the stray Q off the end.
      await ui.input({ key: 'value', text: BULLET.repeat(SECRET.length), kind: 'change' })
      await expectMasked(SECRET.length)
      expect(await ui.find({ type: 'Text', text: `${SECRET.length} characters` })).toBeDefined()

      await ui.press({ key: 'session' })
      const r = await call
      expect(w.puts).toEqual([{ cwd: '/work/project', name: NAME, value: SECRET, scope: 'session' }])
      expect(w.mcpCalls).toBe(0)
      expect(w.kills).toEqual(['4245'])

      const text = resultText(r)
      expect(text.includes(SECRET)).toBe(false)
      expect(text.includes('sk-or')).toBe(false)
      expect(JSON.parse(text)).toEqual({
        stored: true,
        ref: `Hide(${NAME})`,
        env: `AGENT_SECRET_${NAME}`,
        scope: 'this session only',
        usage: `Use "$AGENT_SECRET_${NAME}" in shell commands. Output containing the value comes back as Hide(${NAME}).`,
      })
      // The pane is closed and, if drawn again, holds nothing.
      expect(w.closed).toBeGreaterThan(0)
      await ui.redraw()
      expect(await ui.find({ type: 'Input' })).toBeUndefined()
      expect(JSON.stringify(await ui.drawn()).includes(SECRET)).toBe(false)
      await ui.unmount()
    })
  }

  test('an insertion in the middle lands where it was typed; Enter remembers nothing beyond the session', async ($, on) => {
    const w = world(on)
    const call = $.tool.call({ tool: TOOL, name: NAME, description: 'x' })
    await w.waiting()
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', component: 'Pane', requestId: PANE, props: PANE_PROPS })
    await ui.input({ key: 'value', text: 'abcdefgh', kind: 'change' })
    await ui.input({ key: 'value', text: `${BULLET.repeat(4)}XY${BULLET.repeat(4)}`, kind: 'change' })
    await ui.input({ key: 'value', text: BULLET.repeat(10) })
    await call
    expect(w.puts).toEqual([{ cwd: '/work/project', name: NAME, value: 'abcdXYefgh', scope: 'session' }])
  })

  test('Remember for this project sends scope project', async ($, on) => {
    const w = world(on)
    const call = $.tool.call({ tool: TOOL, name: NAME, description: 'x' })
    await w.waiting()
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'desktop', component: 'Pane', requestId: PANE, props: PANE_PROPS })
    await ui.input({ key: 'value', text: SECRET, kind: 'change' })
    await ui.press({ key: 'project' })
    const text = resultText(await call)
    expect(w.puts).toEqual([{ cwd: '/work/project', name: NAME, value: SECRET, scope: 'project' }])
    expect(JSON.parse(text).scope).toBe('remembered for this project')
  })

  test('a gateway refusal is shown in the pane, the buffer is cleared, and a retry succeeds', { timeoutMs: 30_000 }, async ($, on) => {
    const w = world(on, { putAnswers: [{ status: 500, text: 'agent-understudy: value must be 8-8192 characters' }] })
    const call = $.tool.call({ tool: TOOL, name: NAME, description: 'x' })
    await w.waiting()
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', component: 'Pane', requestId: PANE, props: PANE_PROPS })
    await ui.input({ key: 'value', text: 'short', kind: 'change' })
    await ui.press({ key: 'session' })
    expect(await ui.find({ type: 'Text', text: /value must be 8-8192 characters\. Enter it again\./ })).toBeDefined()
    expect((await ui.find({ type: 'Input', key: 'value' }))?.props.value).toBe('')
    expect(JSON.stringify(await ui.drawn()).includes('short')).toBe(false)
    await w.rollover()
    await ui.input({ key: 'value', text: SECRET, kind: 'change' })
    await ui.press({ key: 'session' })
    const text = resultText(await call)
    expect(w.puts.map((p) => p.value)).toEqual(['short', SECRET])
    expect(JSON.parse(text).stored).toBe(true)
    expect(w.mcpCalls).toBe(0)
  })

  test('Cancel answers stored:false and sends nothing', async ($, on) => {
    const w = world(on)
    const call = $.tool.call({ tool: TOOL, name: NAME, description: 'x' })
    await w.waiting()
    const ui = await $.ui.mount({ plugin: PLUGIN, surface: 'terminal', component: 'Pane', requestId: PANE, props: PANE_PROPS })
    await ui.input({ key: 'value', text: SECRET, kind: 'change' })
    await ui.press({ key: 'cancel' })
    expect(JSON.parse(resultText(await call))).toEqual({ stored: false, reason: 'the user cancelled' })
    expect(w.puts).toEqual([])
    expect(w.mcpCalls).toBe(0)
  })

  test('headless (no surface): falls through to the MCP tool and its native dialog', async ($, on) => {
    const w = world(on, { surfaces: [] })
    const r = await $.tool.call({ tool: TOOL, name: NAME, description: 'x' })
    expect(JSON.parse(resultText(r)).via).toBe('native dialog')
    expect(w.mcpCalls).toBe(1)
    expect(w.opened).toBe(0)
  })

  test('mobile alone (no Input): falls through to the MCP tool', async ($, on) => {
    const w = world(on, { surfaces: ['mobile'] })
    await $.tool.call({ tool: TOOL, name: NAME, description: 'x' })
    expect(w.mcpCalls).toBe(1)
  })

  test('a pane the surface does not seat: falls through to the MCP tool', async ($, on) => {
    const w = world(on, { placed: false })
    const r = await $.tool.call({ tool: TOOL, name: NAME, description: 'x' })
    expect(JSON.parse(resultText(r)).via).toBe('native dialog')
    expect(w.mcpCalls).toBe(1)
    expect(w.opened).toBe(1)
  })
})
