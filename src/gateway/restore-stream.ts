// Restores placeholders in streamed deltas. A placeholder can be split across deltas, so each stream
// (one text block, one tool-call argument string, ...) holds back a tail that could still grow into a
// placeholder and releases it with the next delta or at the end of the stream.

/** Length of the trailing slice of `s` that could be the start of a placeholder. 0 = nothing to hold. */
export function partialTail(s: string): number {
  const m = /R(?:D(?:X(?:_(?:[A-Z]+(?:_[0-9a-f]{0,9})?)?)?)?)?$/.exec(s);
  if (!m) return 0;
  // A complete placeholder at the very end is final (exactly 10 hex digits), so only partial forms are held.
  if (/RDX_[A-Z]+_[0-9a-f]{10}$/.test(m[0])) return 0;
  // Labels are short; a long uppercase run is not a placeholder.
  if (m[0].length > 'RDX_ADDRESS_'.length + 9) return 0;
  return m[0].length;
}

export type Restore = (text: string, escape?: (v: string) => string) => string;

export const jsonEscape = (v: string) => JSON.stringify(v).slice(1, -1);

export type Hold = (s: string) => number;

export class StreamRestorer {
  private readonly pending = new Map<string, string>();
  private readonly restore: Restore;
  private readonly hold: Hold;
  /** hold: how much of a stream's tail to keep back; defaults to partial RDX_ tokens only. */
  constructor(restore: Restore, hold: Hold = partialTail) { this.restore = restore; this.hold = hold; }

  /** Feeds a delta; returns the text that is safe to emit now (restored). */
  push(key: string, delta: string, json = false): string {
    const s = (this.pending.get(key) ?? '') + delta;
    const hold = this.hold(s);
    this.pending.set(key, s.slice(s.length - hold));
    return this.apply(s.slice(0, s.length - hold), json);
  }

  /** Ends a stream; returns whatever was held back (restored if it turned out complete). */
  flush(key: string, json = false): string {
    const s = this.pending.get(key) ?? '';
    this.pending.delete(key);
    return this.apply(s, json);
  }

  keys(): string[] { return [...this.pending.keys()].filter((k) => this.pending.get(k)); }

  private apply(s: string, json: boolean): string {
    return s ? this.restore(s, json ? jsonEscape : undefined) : s;
  }
}

/** Minimal SSE framing: splits a byte stream into events (raw text of each event, without the blank line). */
export class SseParser {
  private buf = '';
  private readonly decoder = new TextDecoder();
  feed(chunk: Uint8Array): string[] {
    this.buf += this.decoder.decode(chunk, { stream: true }).replace(/\r\n/g, '\n');
    const out: string[] = [];
    for (let i = this.buf.indexOf('\n\n'); i >= 0; i = this.buf.indexOf('\n\n')) {
      out.push(this.buf.slice(0, i));
      this.buf = this.buf.slice(i + 2);
    }
    return out;
  }
  end(): string[] { const rest = this.buf + this.decoder.decode(); this.buf = ''; return rest.trim() ? [rest] : []; }
}

export interface SseEvent { event?: string; data?: string; other: string[] }

export function parseEvent(raw: string): SseEvent {
  const e: SseEvent = { other: [] };
  const data: string[] = [];
  for (const line of raw.split('\n')) {
    if (line.startsWith('event:')) e.event = line.slice(6).trim();
    else if (line.startsWith('data:')) data.push(line.slice(line[5] === ' ' ? 6 : 5));
    else e.other.push(line);
  }
  if (data.length) e.data = data.join('\n');
  return e;
}

export function formatEvent(e: { event?: string; data?: string; other?: string[] }): string {
  const lines = [...(e.other ?? []).filter(Boolean)];
  if (e.event) lines.push(`event: ${e.event}`);
  if (e.data !== undefined) for (const l of e.data.split('\n')) lines.push(`data: ${l}`);
  return lines.join('\n') + '\n\n';
}
