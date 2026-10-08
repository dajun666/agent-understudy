// State machine behind the TUI's masked credential field. OpenTUI's <input>/<textarea> have no
// password mode and keep their text (and an undo history) in a native edit buffer, so the dialog
// keeps the value here instead and only ever draws bullets.
//
// Append-only on purpose: no cursor, no selection, no undo — nothing that could keep or show a copy.

export const CHOICES = [
  { id: 'project', label: 'Remember for this project' },
  { id: 'session', label: 'This session only' },
  { id: 'cancel', label: 'Cancel' },
] as const
export type Choice = (typeof CHOICES)[number]['id']

export type MaskState = { value: string; choice: number; error?: string; busy: boolean }
/** The subset of OpenTUI's KeyEvent the field needs. */
export type Key = { name: string; sequence: string; ctrl?: boolean; meta?: boolean; option?: boolean; shift?: boolean }
export type Action = { type: 'submit'; scope: 'project' | 'session' } | { type: 'cancel' }

export const MAX_LENGTH = 8192

export const initialState = (): MaskState => ({ value: '', choice: 0, busy: false })

/** Bullets for display; long values are shortened so the dialog keeps its width. */
export function masked(s: MaskState, width = 40): string {
  const n = [...s.value].length
  if (n === 0) return ''
  return n <= width ? '•'.repeat(n) : `${'•'.repeat(width - 1)}…`
}

export const lengthHint = (s: MaskState) => { const n = [...s.value].length; return n ? `${n} character${n === 1 ? '' : 's'}` : '' }

/** Control characters never belong in a credential; terminals send them for unbound keys. */
const printable = (t: string) => t.length > 0 && !/[\u0000-\u001f\u007f]/.test(t)

function insert(s: MaskState, text: string): MaskState {
  if (!text) return s
  const room = MAX_LENGTH - s.value.length
  if (room <= 0) return { ...s, error: `at most ${MAX_LENGTH} characters` }
  return { ...s, value: s.value + text.slice(0, room), error: undefined }
}

/** Enter, or a click on a choice: act on the highlighted choice. */
export function choose(s: MaskState): { state: MaskState; action?: Action } {
  const c = CHOICES[s.choice]!.id
  if (c === 'cancel') return { state: s, action: { type: 'cancel' } }
  if (s.value.length === 0) return { state: { ...s, error: 'type or paste the value first' } }
  return { state: { ...s, error: undefined }, action: { type: 'submit', scope: c } }
}

/** One key press. While busy (the gateway call is in flight) only Escape does anything. */
export function onKey(s: MaskState, k: Key): { state: MaskState; action?: Action; handled: boolean } {
  if (k.name === 'escape') return { state: s, action: { type: 'cancel' }, handled: true }
  if (s.busy) return { state: s, handled: true }
  if (k.ctrl && k.name === 'c') return { state: s, action: { type: 'cancel' }, handled: true }
  switch (k.name) {
    case 'return': case 'enter': case 'kpenter': case 'linefeed': {
      const r = choose(s)
      return { ...r, handled: true }
    }
    case 'tab': case 'right': case 'down':
      if (k.name === 'tab' && k.shift) return { state: { ...s, choice: (s.choice + CHOICES.length - 1) % CHOICES.length }, handled: true }
      return { state: { ...s, choice: (s.choice + 1) % CHOICES.length }, handled: true }
    case 'left': case 'up':
      return { state: { ...s, choice: (s.choice + CHOICES.length - 1) % CHOICES.length }, handled: true }
    case 'backspace':
      // Option/Alt/Ctrl+Backspace and Ctrl+W/U clear the whole field: with nothing visible, word
      // boundaries mean nothing to the person typing.
      if (k.ctrl || k.meta || k.option) return { state: { ...s, value: '', error: undefined }, handled: true }
      return { state: { ...s, value: [...s.value].slice(0, -1).join(''), error: undefined }, handled: true }
  }
  if (k.ctrl && (k.name === 'u' || k.name === 'w')) return { state: { ...s, value: '', error: undefined }, handled: true }
  if (k.ctrl || k.meta) return { state: s, handled: false }
  const text = k.name === 'space' ? ' ' : k.sequence
  if (printable(text)) return { state: insert(s, text), handled: true }
  return { state: s, handled: false }
}

/** Bracketed paste. Surrounding whitespace (a copied line end) is dropped; a value spanning lines is refused. */
export function onPaste(s: MaskState, text: string): MaskState {
  if (s.busy) return s
  const t = text.trim()
  if (/[\r\n]/.test(t)) return { ...s, error: 'that paste spans several lines; a credential is a single line' }
  // Tabs and other control characters from a sloppy copy.
  const clean = t.replace(/[\u0000-\u001f\u007f]/g, '')
  return insert(s, clean)
}

/** After submit or cancel: drop our reference to the value. */
export const cleared = (s: MaskState): MaskState => ({ ...s, value: '', busy: false })
