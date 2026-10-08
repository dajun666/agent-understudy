// Per-API knowledge: which strings in a request carry user/tool content (redact them), and where
// placeholders can show up in a response (restore them).
import type { Finding } from '../core/types.ts';
import type { Redactor } from '../core/redactor.ts';
import { StreamRestorer, jsonEscape, type Hold, type Restore } from './restore-stream.ts';

/** raw: any JSON value (hooks send conversation rows and tool results this way). */
export type Protocol = 'anthropic' | 'responses' | 'chat' | 'raw';

/** Keys whose string values are identifiers or opaque blobs, never content. */
const SKIP_KEYS = new Set([
  'type', 'role', 'id', 'call_id', 'tool_use_id', 'name', 'model', 'status', 'signature', 'encrypted_content',
  'data', 'media_type', 'cache_control', 'tool_choice', 'previous_response_id', 'prompt_cache_key', 'service_tier',
  'image_url', 'file_id', 'detail', 'format', 'effort', 'summary_mode', 'stop_reason', 'object',
]);
/** Blocks/items whose content must reach the API byte-for-byte. */
const OPAQUE_TYPES = new Set(['thinking', 'redacted_thinking', 'reasoning', 'image', 'input_image', 'compaction']);

export interface RedactOutcome { findings: Finding[]; errors: Array<{ detector: string; error: string }>; changed: number; strings: number; chars: number }

/**
 * Walks a request body and redacts every content string in place.
 * Anthropic: the first system block (billing/attribution header) is left untouched.
 */
export async function redactBody(body: any, protocol: Protocol, redactor: Redactor, opts: { observe?: boolean } = {}): Promise<RedactOutcome> {
  const outcome: RedactOutcome = { findings: [], errors: [], changed: 0, strings: 0, chars: 0 };
  // A body that already carries our stand-ins was redacted before it got here (mod/plugin in front of the
  // gateway): its stand-in words are ours, not real collisions, so it must not mark anything ambiguous.
  if (opts.observe && redactor.vault.hasIssuedStandIns(JSON.stringify(body))) opts = { ...opts, observe: false };
  const jobs: Array<Promise<void>> = [];
  // raw: inside tool-call inputs, keys are the tool's own and carry content ({"name": "Alice"}).
  const visit = (node: any, key: string | undefined, set: (v: string) => void, raw = false) => {
    if (typeof node === 'string') {
      if (!raw && key && SKIP_KEYS.has(key)) return;
      if (node.length < 4) return;
      outcome.strings++;
      outcome.chars += node.length;
      jobs.push(redactor.redact(node, opts).then((r) => {
        outcome.findings.push(...r.findings.filter((f) => f.redact));
        outcome.errors.push(...r.errors);
        if (r.changed) { outcome.changed++; set(r.text); }
      }));
      return;
    }
    if (Array.isArray(node)) { node.forEach((v, i) => visit(v, key, (s) => { node[i] = s; }, raw)); return; }
    if (node && typeof node === 'object') {
      if (!raw && typeof node.type === 'string' && OPAQUE_TYPES.has(node.type)) return;
      const toolInput = !raw && (node.type === 'tool_use' || node.type === 'server_tool_use');
      for (const [k, v] of Object.entries(node)) visit(v, k, (s) => { node[k] = s; }, raw || (toolInput && k === 'input'));
    }
  };

  if (protocol === 'anthropic') {
    if (typeof body.system === 'string') visit(body.system, 'system', (s) => { body.system = s; });
    else if (Array.isArray(body.system)) {
      body.system.forEach((b: any, i: number) => {
        if (i === 0 && typeof b?.text === 'string' && b.text.startsWith('x-anthropic-billing-header')) return;
        visit(b, undefined, () => {});
      });
    }
    visit(body.messages, 'messages', () => {});
  } else if (protocol === 'responses') {
    if (typeof body.instructions === 'string') visit(body.instructions, 'instructions', (s) => { body.instructions = s; });
    if (typeof body.input === 'string') visit(body.input, 'input', (s) => { body.input = s; });
    else visit(body.input, 'input', () => {});
  } else if (protocol === 'chat') {
    visit(body.messages, 'messages', () => {});
  } else {
    visit(body, undefined, () => {});
  }
  await Promise.all(jobs);
  return outcome;
}

/** Restores placeholders in every content string of a parsed JSON value (non-streaming responses, aggregate events). */
export function restoreDeep(node: any, restore: Restore, key?: string): any {
  if (typeof node === 'string') {
    // No key filter: restore() only rewrites stand-ins the vault issued.
    // Tool-call arguments are JSON inside a string: the value must be escaped for that inner JSON.
    return restore(node, key === 'arguments' || key === 'partial_json' ? jsonEscape : undefined);
  }
  if (Array.isArray(node)) return node.map((v) => restoreDeep(v, restore, key));
  if (node && typeof node === 'object') {
    if (typeof node.type === 'string' && OPAQUE_TYPES.has(node.type)) return node;
    for (const k of Object.keys(node)) node[k] = restoreDeep(node[k], restore, k);
  }
  return node;
}

export interface StreamTransform {
  /** Returns zero or more events (data objects) to emit in place of this one. */
  event(name: string | undefined, data: any): Array<{ event?: string; data: any }>;
}

/** Anthropic Messages SSE. */
export function anthropicStream(restore: Restore, hold?: Hold): StreamTransform {
  const r = new StreamRestorer(restore, hold);
  const kinds = new Map<number, 'text' | 'json' | 'skip'>();
  return {
    event(name, d) {
      if (d?.type === 'content_block_start') {
        const t = d.content_block?.type;
        kinds.set(d.index, t === 'text' ? 'text' : t === 'tool_use' || t === 'server_tool_use' ? 'json' : 'skip');
        return [{ event: name, data: restoreDeep(d, restore) }];
      }
      if (d?.type === 'content_block_delta') {
        const k = kinds.get(d.index) ?? 'skip';
        const key = String(d.index);
        if (k === 'text' && d.delta?.type === 'text_delta') d.delta.text = r.push(key, d.delta.text ?? '');
        else if (k === 'json' && d.delta?.type === 'input_json_delta') d.delta.partial_json = r.push(key, d.delta.partial_json ?? '', true);
        else return [{ event: name, data: d }];
        const text = d.delta.text ?? d.delta.partial_json;
        return text ? [{ event: name, data: d }] : [];
      }
      if (d?.type === 'content_block_stop') {
        const k = kinds.get(d.index);
        const rest = k === 'text' || k === 'json' ? r.flush(String(d.index), k === 'json') : '';
        const out: Array<{ event?: string; data: any }> = [];
        if (rest) {
          out.push({ event: 'content_block_delta', data: { type: 'content_block_delta', index: d.index,
            delta: k === 'text' ? { type: 'text_delta', text: rest } : { type: 'input_json_delta', partial_json: rest } } });
        }
        out.push({ event: name, data: d });
        return out;
      }
      return [{ event: name, data: d }];
    },
  };
}

/** OpenAI Responses SSE / WebSocket events (same JSON either way). */
export function responsesStream(restore: Restore, hold?: Hold): StreamTransform {
  const r = new StreamRestorer(restore, hold);
  const DELTA: Record<string, { json: boolean; done: string }> = {
    'response.output_text.delta': { json: false, done: 'response.output_text.done' },
    'response.function_call_arguments.delta': { json: true, done: 'response.function_call_arguments.done' },
    'response.custom_tool_call_input.delta': { json: false, done: 'response.custom_tool_call_input.done' },
    'response.reasoning_summary_text.delta': { json: false, done: 'response.reasoning_summary_text.done' },
    'response.reasoning_text.delta': { json: false, done: 'response.reasoning_text.done' },
  };
  const DONE = new Map(Object.entries(DELTA).map(([delta, v]) => [v.done, { delta, json: v.json }]));
  const keyOf = (d: any) => `${d.item_id ?? d.output_index}:${d.content_index ?? d.summary_index ?? 0}`;
  const last = new Map<string, any>();
  return {
    event(name, d) {
      const t = d?.type as string | undefined;
      const delta = t ? DELTA[t] : undefined;
      if (delta && typeof d.delta === 'string') {
        const key = `${t}:${keyOf(d)}`;
        last.set(key, d);
        d.delta = r.push(key, d.delta, delta.json);
        return d.delta ? [{ event: name, data: d }] : [];
      }
      const done = t ? DONE.get(t) : undefined;
      const out: Array<{ event?: string; data: any }> = [];
      if (done) {
        const key = `${done.delta}:${keyOf(d)}`;
        const rest = r.flush(key, done.json);
        if (rest) out.push({ event: done.delta, data: { ...last.get(key), delta: rest } });
        last.delete(key);
      }
      out.push({ event: name, data: restoreDeep(d, restore) });
      return out;
    },
  };
}

/** OpenAI Chat Completions SSE. */
export function chatStream(restore: Restore, hold?: Hold): StreamTransform {
  const r = new StreamRestorer(restore, hold);
  return {
    event(name, d) {
      for (const c of d?.choices ?? []) {
        const delta = c.delta ?? {};
        if (typeof delta.content === 'string') delta.content = r.push(`c${c.index}`, delta.content);
        for (const tc of delta.tool_calls ?? []) {
          if (typeof tc.function?.arguments === 'string') tc.function.arguments = r.push(`t${c.index}:${tc.index}`, tc.function.arguments, true);
        }
        if (c.finish_reason) {
          const rest = r.flush(`c${c.index}`);
          if (rest) delta.content = (delta.content ?? '') + rest;
          for (const k of r.keys().filter((k) => k.startsWith(`t${c.index}:`))) {
            const rest = r.flush(k, true);
            const idx = Number(k.split(':')[1]);
            delta.tool_calls ??= [];
            const tc = delta.tool_calls.find((x: any) => x.index === idx) ?? (delta.tool_calls.push({ index: idx, function: { arguments: '' } }), delta.tool_calls.at(-1));
            tc.function = { ...tc.function, arguments: (tc.function?.arguments ?? '') + rest };
          }
        }
      }
      return [{ event: name, data: d }];
    },
  };
}
