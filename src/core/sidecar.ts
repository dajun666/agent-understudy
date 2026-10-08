// Client and process manager for the Python model sidecar (sidecar/server.py).
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import type { Detector, Label, Span } from './types.ts';

export const SIDECAR_MODELS: Record<string, readonly Label[]> = {
  'privacy-filter': ['SECRET', 'EMAIL', 'PHONE', 'PERSON', 'ADDRESS', 'ACCOUNT', 'URL', 'DATE'],
  masker: ['PERSON', 'ADDRESS', 'EMAIL', 'PHONE', 'ACCOUNT', 'ID', 'DATE'],
  'gliner-pii': ['PERSON', 'EMAIL', 'PHONE', 'ADDRESS', 'ACCOUNT', 'ID', 'SECRET', 'DATE'],
  piiranha: ['ACCOUNT', 'ADDRESS', 'DATE', 'ID', 'EMAIL', 'PERSON', 'SECRET', 'PHONE'],
};

export interface ModelStatus {
  repo: string; license: string; size: string; note: string;
  pulled: boolean; loaded: boolean; device: string | null; error: string | null;
}

type Result = { spans: Array<Omit<Span, 'detector'>>; ms: number } | { error: string };

export class SidecarClient {
  readonly url: string;
  private readonly timeoutMs: number;
  // Every (text, model) asked for during one tick goes out as a single batched /detect call.
  private pending?: { texts: Map<string, number>; models: Set<string>; promise: Promise<Array<Record<string, Result>>> };

  /** Settles when the sidecar is up (it may be starting): detection waits for it instead of going without. */
  private readonly ready?: Promise<void>;

  constructor(url = `http://127.0.0.1:${process.env.AGENT_UNDERSTUDY_SIDECAR_PORT ?? 8791}`, timeoutMs = 300_000, ready?: Promise<void>) {
    this.url = url;
    this.timeoutMs = timeoutMs;
    this.ready = ready;
  }

  async health(): Promise<{ ok: boolean; models: Record<string, ModelStatus> }> {
    return this.call('GET', '/health', undefined, 3000);
  }
  pull(model: string) { return this.call('POST', '/pull', { model }, 3_600_000); }
  load(model: string) { return this.call('POST', '/load', { model }, 600_000); }

  detect(text: string, model: string): Promise<Result> {
    if (!this.pending) {
      const texts = new Map<string, number>();
      const models = new Set<string>();
      const promise = new Promise<Array<Record<string, Result>>>((resolve, reject) => {
        setImmediate(() => {
          this.pending = undefined;
          this.call('POST', '/detect', { texts: [...texts.keys()], models: [...models] }, this.timeoutMs)
            .then((r: { batch: Array<Record<string, Result>> }) => resolve(r.batch), reject);
        });
      });
      this.pending = { texts, models, promise };
    }
    const p = this.pending;
    if (!p.texts.has(text)) p.texts.set(text, p.texts.size);
    p.models.add(model);
    const k = p.texts.get(text)!;
    return p.promise.then((batch) => batch[k]?.[model] ?? { error: 'no result' });
  }

  private async call(method: string, p: string, body: unknown, timeoutMs: number): Promise<any> {
    if (p !== '/health') await this.ready;
    const res = await fetch(this.url + p, {
      method, headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(timeoutMs),
    });
    const j = await res.json();
    if (!res.ok) throw new Error(j.error ?? `sidecar ${res.status}`);
    return j;
  }
}

export class SidecarDetector implements Detector {
  readonly id: string;
  readonly labels: readonly Label[];
  private readonly client: SidecarClient;
  constructor(id: string, client: SidecarClient) {
    this.id = id;
    this.labels = SIDECAR_MODELS[id] ?? [];
    this.client = client;
  }
  async detect(text: string): Promise<Span[]> {
    const r = await this.client.detect(text, this.id);
    if ('error' in r) throw new Error(r.error);
    return r.spans.map((s) => ({ ...s, detector: this.id }));
  }
}

/** Starts sidecar/server.py from its uv venv and waits for /health. */
export async function startSidecar(opts: { port?: number; preload?: string[]; log?: (s: string) => void } = {}): Promise<{ client: SidecarClient; proc: ChildProcess }> {
  const dir = path.resolve(import.meta.dirname, '../../sidecar');
  const py = path.join(dir, '.venv/bin/python');
  if (!existsSync(py)) throw new Error(`sidecar venv missing: run \`uv sync\` in ${dir}`);
  const port = opts.port ?? Number(process.env.AGENT_UNDERSTUDY_SIDECAR_PORT ?? 8791);
  const proc = spawn(py, ['server.py', '--port', String(port), '--preload', ...(opts.preload ?? [])], {
    cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, TOKENIZERS_PARALLELISM: 'false' },
  });
  proc.stderr!.on('data', (d) => opts.log?.(String(d).trimEnd()));
  const client = new SidecarClient(`http://127.0.0.1:${port}`);
  const deadline = Date.now() + 600_000; // preloading big models can take minutes
  for (;;) {
    if (proc.exitCode !== null) throw new Error(`sidecar exited with ${proc.exitCode}`);
    try { await client.health(); return { client, proc }; } catch { /* not up yet */ }
    if (Date.now() > deadline) { proc.kill(); throw new Error('sidecar did not come up'); }
    await new Promise((r) => setTimeout(r, 500));
  }
}
