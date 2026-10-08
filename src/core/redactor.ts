// Detectors + policy + vault: text in, redacted text and the per-span vote record out.
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { DEFAULT_POLICY, vote, type Policy } from './ensemble.ts';
import { Vault } from './vault.ts';
import type { Detector, Finding, Span } from './types.ts';

export interface ScanResult {
  findings: Finding[];
  /** Detectors that failed on this text (e.g. sidecar down). Their votes are missing, not "no". */
  errors: Array<{ detector: string; error: string }>;
}

export interface RedactResult extends ScanResult { text: string; changed: boolean }

/** The vault's vote: values (and name words) it has redacted before are redacted again, everywhere. */
class VaultDetector implements Detector {
  readonly id = 'vault';
  readonly labels = [] as const;
  private readonly vault: Vault;
  constructor(vault: Vault) { this.vault = vault; }
  async detect(text: string): Promise<Span[]> {
    return this.vault.stickySpans(text).map((s) => ({ ...s, score: 1, detector: this.id }));
  }
}

/** Bump when detector output changes shape (v2: sub-entity parts), so stale cached spans are ignored. */
const CACHE_VERSION = 2;

export class Redactor {
  readonly detectors: Detector[];
  policy: Policy;
  readonly vault: Vault;
  private readonly cache = new Map<string, Span[]>();
  private readonly cacheMax: number;
  private readonly vaultDetector: VaultDetector;

  private readonly disk?: SpanCache;

  constructor(opts: { detectors: Detector[]; vault: Vault; policy?: Policy; cacheMax?: number; cacheFile?: string }) {
    if (opts.cacheFile) this.disk = new SpanCache(opts.cacheFile);
    this.detectors = opts.detectors;
    this.vault = opts.vault;
    this.policy = opts.policy ?? DEFAULT_POLICY;
    this.cacheMax = opts.cacheMax ?? 20000;
    this.vaultDetector = new VaultDetector(this.vault);
  }

  /** Runs every detector and votes. Does not touch the vault. */
  async scan(text: string): Promise<ScanResult> {
    const errors: ScanResult['errors'] = [];
    const spans = [...await this.detectCached(text, errors), ...await this.vaultDetector.detect(text)];
    // Never re-redact our own stand-ins.
    const own = this.vault.standInSpans(text);
    const kept = spans.filter((s) => !own.some(([a, b]) => s.start < b && s.end > a));
    const policy = { ...this.policy, authoritative: { ...this.policy.authoritative, vault: [...this.policy.labels] } };
    return { findings: vote(text, kept, this.detectors, policy), errors };
  }

  /** observe: the text is real outgoing content (gateway path), so stand-ins found in it are real words. */
  async redact(text: string, opts: { observe?: boolean } = {}): Promise<RedactResult> {
    if (!text.trim()) return { text, changed: false, findings: [], errors: [] };
    if (opts.observe) this.vault.observe(text);
    const r = await this.scan(text);
    const out = this.vault.apply(text, r.findings);
    return { ...r, text: out, changed: out !== text };
  }

  restore(text: string, escape?: (v: string) => string): string { return this.vault.restore(text, escape); }

  // Conversations resend their whole history every turn; only new text should hit the models.
  // Cached per detector, keyed by a hash of the text; the disk copy holds offsets and labels, never text.
  private async detectCached(text: string, errors: ScanResult['errors']): Promise<Span[]> {
    const h = createHash('sha256').update(text).digest('hex');
    const all = await Promise.all(this.detectors.map(async (d) => {
      const key = `${d.id}@${CACHE_VERSION}:${h}`;
      const hit = this.cache.get(key) ?? this.disk?.get(key);
      if (hit) { this.touch(key, hit); return hit; }
      try {
        const spans = await d.detect(text);
        this.touch(key, spans);
        if (this.disk && d.id !== 'gitleaks' && d.id !== 'patterns') this.disk.set(key, spans);
        return spans;
      } catch (e) {
        errors.push({ detector: d.id, error: String((e as Error)?.message ?? e) });
        return [];
      }
    }));
    return all.flat();
  }

  private touch(key: string, spans: Span[]) {
    this.cache.delete(key);
    this.cache.set(key, spans);
    if (this.cache.size > this.cacheMax) this.cache.delete(this.cache.keys().next().value!);
  }
}

/** Append-only JSONL of model detections: {k: "<detector>:<sha256>", s: spans}. No text is stored. */
class SpanCache {
  private readonly map = new Map<string, Span[]>();
  private readonly file: string;
  constructor(file: string) {
    this.file = file;
    if (!existsSync(file)) return;
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      if (!line) continue;
      try { const { k, s } = JSON.parse(line); this.map.set(k, s); } catch { /* torn line */ }
    }
  }
  get(k: string) { return this.map.get(k); }
  set(k: string, s: Span[]) {
    if (this.map.has(k)) return;
    this.map.set(k, s);
    try { appendFileSync(this.file, JSON.stringify({ k, s }) + '\n', { mode: 0o600 }); } catch { /* cache is best-effort */ }
  }
}
