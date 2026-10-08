// No daemon: the mod starts `agent-understudy engine` as a child of the session and talks to the URL it
// prints. The child, its URL and the engine's answers are played by the test's own hooks.
import { describe, expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

const ENGINE = 'http://127.0.0.1:61234'

function world(on: On, env: Record<string, string> = {}) {
  const w = { spawned: [] as string[][], calls: [] as string[] }
  mock.env(on, { HOME: '/home/test', ...env })
  on('fs.read', () => ({ value: 'test-token\n' }))
  on('session.cwd', () => ({ value: '/work/project' }))
  on('ui.status', () => ({ value: undefined }))
  // What the engine itself does beneath the plugin: start echoes the cwd, submit keeps the text as rewritten.
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('prompt.submit', ($, e) => ({ text: e.text }))
  on('process.spawn', async function* ($, e) {
    w.spawned.push([...e.argv])
    yield { stream: 'stdout' as const, text: `{"url":"${ENGINE}"}\n` }
    return { value: { code: 0, signal: null } }
  })
  on('http.fetch', ($, e) => {
    const u = new URL(e.url)
    w.calls.push(`${u.origin}${u.pathname}`)
    const body = JSON.parse(e.init?.body ?? '{}') as { value: unknown; text?: string }
    if (u.pathname === '/api/restore') return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify({ text: String(body.text).replaceAll('Rubie', 'Maria') }) } }
    const swap = (v: unknown): unknown => (typeof v === 'string' ? v.replace('Maria Santos', 'Rubie Cremin') : Array.isArray(v) ? v.map(swap) : v)
    const value = swap(body.value)
    return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify({ value, changed: JSON.stringify(value) !== JSON.stringify(body.value) }) } }
  })
  return w
}


describe('session engine', () => {
  test('session start runs `agent-understudy engine`; prompts are redacted through the URL it printed', async ($, on) => {
    const w = world(on)
    await $.session.start({ cwd: '/work/project', surface: 'terminal', isInteractive: true })
    const r = await $.prompt.submit({ text: 'email Maria Santos about the invoice', wait: false, origin: { kind: 'composer' } })
    expect(w.spawned).toEqual([['agent-understudy', 'engine']])
    expect(JSON.stringify(r)).not.toContain('Maria Santos')
    expect(w.calls).toEqual([`${ENGINE}/api/redact-json`])
  })

  test('launched by `understudy run claude`: the inherited engine is used and none is started', async ($, on) => {
    const w = world(on, { AGENT_UNDERSTUDY_GATEWAY: 'http://127.0.0.1:50000/' })
    await $.session.start({ cwd: '/work/project', surface: 'terminal', isInteractive: true })
    expect(w.spawned).toEqual([])
    await $.prompt.submit({ text: 'email Maria Santos', wait: false, origin: { kind: 'composer' } })
    expect(w.calls).toEqual(['http://127.0.0.1:50000/api/redact-json'])
  })

  test("the answer is drawn with real values while the stored row keeps the stand-in", async ($, on) => {
    world(on)
    // The engine's own drawing beneath the plugin: the text as it is handed down.
    on('ui.render', { component: 'AssistantMessage' }, ($, e) => {
      const { Text } = $.ui.resolve(e)
      return <Text>{e.props.text}</Text>
    })
    await $.session.start({ cwd: '/work/project', surface: 'terminal', isInteractive: true })
    const ui = await $.ui.mount({
      plugin: 'agent-understudy', surface: 'terminal', component: 'AssistantMessage', requestId: 'msg-1',
      props: { text: "The customer's first name is **Rubie**.", isFirstOfReply: true },
    })
    const drawnText = JSON.stringify(await ui.drawn())
    expect(drawnText).toContain('Maria')
    expect(drawnText).not.toContain('Rubie')
  })

  test('per-session system prompt sections are redacted; the shared ones are left as they are', async ($, on) => {
    world(on)
    on('prompt.compose', () => ({ sections: [
      { id: 'intro', text: 'You are Claude Code. Maria Santos is a common example name.', scope: 'shared' as const },
      { id: 'env', text: 'Git user: Maria Santos', scope: 'session' as const },
    ] }))
    await $.session.start({ cwd: '/work/project', surface: 'terminal', isInteractive: true })
    const { sections } = await $.prompt.compose({ model: 'claude-opus-5-5', promptModel: 'claude-opus-5-5', surfaces: ['terminal'], tools: [], outputStyle: null, traits: [] })
    expect(sections.map((x) => x.text)).toEqual(['You are Claude Code. Maria Santos is a common example name.', 'Git user: Rubie Cremin'])
  })
})
