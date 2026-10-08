/** @jsxImportSource @opentui/solid */
// opencode TUI plugin for agent-understudy: secret_request asks inside the terminal.
//
// Load it from tui.json (next to opencode.json, or ~/.config/opencode/tui.json):
//   { "plugin": ["file:///abs/path/to/agent-understudy-tui.tsx"] }
// The server plugin (agent-understudy.ts in opencode.json) is still what registers the tools; opencode
// loads server and TUI plugins from separate files.
//
// Flow: the TUI sees the secret_request tool part go to "running", claims the request the server
// plugin published (secret-handoff.ts), and shows a masked field with Remember for this project /
// This session only / Cancel. The value goes from this process straight to the local gateway;
// opencode's server, session storage, logs and the model only ever get the outcome.
import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from '@opencode-ai/plugin/tui'
import { TextAttributes, type BoxRenderable, type KeyEvent, type PasteEvent } from '@opentui/core'
import { createSignal, For, onMount, Show } from 'solid-js'
import { CHOICES, choose, cleared, initialState, lengthHint, masked, onKey, onPaste, type Action } from './masked-input.ts'
import { answer, askOpen, asksDir, claim, putSecret, readAsk, type Answer, type Ask } from './secret-handoff.ts'

type Job = { key: string; id: string; ask: Ask; finish?: (a: Answer) => void }

const tui: TuiPlugin = async (api) => {
  const dir = asksDir()
  const seen = new Set<string>()
  const queue: Job[] = []
  const jobs = new Map<string, Job>()
  let active: Job | undefined

  async function take(sessionID: string, callID: string) {
    const key = `${sessionID}\0${callID}`
    const found = await readAsk(sessionID, callID, { dir })
    // No request file: an older server plugin, tuiAsk off, or the request already finished.
    if (!found) return
    // Another TUI attached to the same server, or the server's own fallback, may have it already.
    if (!(await claim(dir, found.id, `tui ${process.pid}`))) return
    const job: Job = { key, ...found }
    jobs.set(key, job)
    queue.push(job)
    pump()
  }

  function pump() {
    if (active || !queue.length) return
    const job = queue.shift()!
    active = job
    show(api, job, async (a) => {
      jobs.delete(job.key)
      await answer(job.id, a, dir).catch(() => {})
      if (active === job) active = undefined
      pump()
    })
  }

  const off = api.event.on('message.part.updated', (e) => {
    const part = e.properties.part
    if (part.type !== 'tool' || part.tool !== 'secret_request') return
    const key = `${part.sessionID}\0${part.callID}`
    if (part.state.status === 'running') {
      if (seen.has(key)) return
      seen.add(key)
      void take(part.sessionID, part.callID).catch(() => {})
    } else if (part.state.status !== 'pending') {
      // Finished, failed or aborted on the server side: drop the dialog if it is still up.
      jobs.get(key)?.finish?.({ stored: false, reason: 'the tool call ended' })
      seen.delete(key)
    }
  })
  api.lifecycle.onDispose(() => {
    off()
    for (const j of [...jobs.values()]) j.finish?.({ stored: false, reason: 'the TUI closed' })
  })
}

function show(api: TuiPluginApi, job: Job, done: (a: Answer) => Promise<void>) {
  let finished = false
  let open = true
  let watch: ReturnType<typeof setInterval> | undefined
  const [state, setState] = createSignal(initialState())

  const finish = (a: Answer) => {
    if (finished) return
    finished = true
    setState(cleared(state()))
    if (watch) clearInterval(watch)
    if (open) { open = false; api.ui.dialog.clear() }
    void done(a)
  }
  job.finish = finish

  // The server gave up (abort, timeout, opencode exiting): close without answering.
  watch = setInterval(() => { void askOpen(job.id).then((still) => { if (!still) finish({ stored: false, reason: 'the request is gone' }) }) }, 500)

  async function act(action: Action) {
    if (action.type === 'cancel') return finish({ stored: false, reason: 'the user cancelled' })
    setState({ ...state(), busy: true, error: undefined })
    const r = await putSecret(job.ask, state().value, action.scope)
    if (finished) return
    if (r.ok) return finish({ stored: true, scope: r.scope, createdAt: r.createdAt })
    // Bad value or no keychain: say why, keep the field so the person can fix it or pick session-only.
    setState({ ...state(), busy: false, error: r.error })
  }

  api.ui.dialog.replace(
    () => <SecretDialog api={api} ask={job.ask} state={state} setState={setState} act={act} />,
    () => { open = false; finish({ stored: false, reason: 'the user cancelled' }) },
  )
}

function SecretDialog(props: {
  api: TuiPluginApi
  ask: Ask
  state: () => ReturnType<typeof initialState>
  setState: (s: ReturnType<typeof initialState>) => void
  act: (a: Action) => void
}) {
  const theme = () => props.api.theme.current
  let field: BoxRenderable | undefined

  onMount(() => {
    props.api.ui.dialog.setSize('large')
    setTimeout(() => { if (field && !field.isDestroyed) field.focus() }, 1)
  })

  const key = (k: KeyEvent) => {
    if (k.defaultPrevented) return // the dialog's own Escape / Ctrl+C binding already closed us
    const r = onKey(props.state(), k)
    if (!r.handled) return
    k.preventDefault()
    k.stopPropagation()
    props.setState(r.state)
    if (r.action) props.act(r.action)
  }

  const paste = (e: PasteEvent) => {
    e.preventDefault()
    e.stopPropagation()
    props.setState(onPaste(props.state(), new TextDecoder().decode(e.bytes)))
  }

  const pick = (i: number) => {
    if (props.state().busy) return
    const r = choose({ ...props.state(), choice: i })
    props.setState(r.state)
    if (r.action) props.act(r.action)
  }

  return (
    <box paddingLeft={2} paddingRight={2} gap={1}>
      <box flexDirection="row" justifyContent="space-between">
        <text attributes={TextAttributes.BOLD} fg={theme().text}>
          Credential needed: {props.ask.name}
        </text>
        <text fg={theme().textMuted} onMouseUp={() => props.act({ type: 'cancel' })}>
          esc
        </text>
      </box>
      <Show when={props.ask.description}>
        <text fg={theme().text}>{props.ask.description}</text>
      </Show>
      <text fg={theme().textMuted}>
        Project: {props.ask.cwd}. The model only sees Hide({props.ask.name}); commands read $AGENT_SECRET_{props.ask.name}.
      </text>
      <box
        ref={(r: BoxRenderable) => { field = r }}
        focusable
        border
        borderColor={theme().borderActive}
        paddingLeft={1}
        height={3}
        onKeyDown={key}
        onPaste={paste}
      >
        <Show when={props.state().value} fallback={<text fg={theme().textMuted}>Type or paste the value (hidden)</text>}>
          <text fg={theme().text}>{masked(props.state(), 48)}</text>
        </Show>
      </box>
      <Show when={props.state().error}>
        <text fg={theme().error}>{props.state().error}</text>
      </Show>
      <box flexDirection="row" gap={2}>
        <For each={[...CHOICES]}>
          {(c, i) => (
            <text
              fg={i() === props.state().choice ? theme().selectedListItemText : theme().text}
              bg={i() === props.state().choice ? theme().primary : undefined}
              onMouseUp={() => pick(i())}
            >
              {` ${c.label} `}
            </text>
          )}
        </For>
      </box>
      <box flexDirection="row" justifyContent="space-between" paddingBottom={1}>
        <text fg={theme().textMuted}>
          {props.state().busy ? 'saving…' : 'enter choose · tab/←→ switch · esc cancel'}
        </text>
        <text fg={theme().textMuted}>{lengthHint(props.state())}</text>
      </box>
    </box>
  )
}

const plugin: TuiPluginModule & { id: string } = { id: 'agent-understudy-tui', tui }
export default plugin
