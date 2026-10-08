// ~/.agent-understudy/config.json — everything optional; defaults below.
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { DEFAULT_POLICY, type Policy } from './core/ensemble.ts';
import { defaultHome } from './core/vault.ts';
import { LABELS } from './core/types.ts';

const label = z.enum(LABELS);
const ConfigSchema = z.object({
  port: z.number().int().default(8790),
  sidecarPort: z.number().int().default(8791),
  /** Named upstreams. /anthropic, /backend-api/codex and /openai map to the first three; any other name is served at /u/<name>/... */
  upstreams: z.record(z.string(), z.string().url()).default({
    anthropic: 'https://api.anthropic.com',
    codex: 'https://chatgpt.com/backend-api/codex',
    openai: 'https://api.openai.com',
  }),
  /** Sidecar models that vote. Regex detectors (gitleaks, patterns) always run. */
  // Benchmark (bench/): masker + privacy-filter is the best pair; privacy-filter alone is next. ~3.5 GB RAM.
  models: z.array(z.string()).default(['masker', 'privacy-filter']),
  /**
   * Whether to redact people's names and postal addresses. Models find these and miss handles and bare
   * surnames, so some people would rather not pay for them (RAM, false positives). Off: emails, phones,
   * keys, card numbers and the rest are still redacted, and `knownNames` still are.
   */
  names: z.boolean().default(true),
  addresses: z.boolean().default(true),
  /** Your own names and handles: always redacted, wherever they appear (models miss lowercase handles). */
  knownNames: z.array(z.string()).default([]),
  /** Stand-in style per label: surrogate (realistic fake), numbered ("Person A"), or token (RDX_...). */
  placeholders: z.partialRecord(label, z.enum(['surrogate', 'numbered', 'token'])).default({}),
  /** What to do when a model detector fails: keep going on regex votes, or refuse the request. */
  onDetectorError: z.enum(['continue', 'block']).default('continue'),
  policy: z.object({
    mode: z.enum(['weighted', 'any', 'majority']).optional(),
    thresholds: z.record(z.string(), z.number()).optional(),
    weights: z.record(z.string(), z.record(z.string(), z.number())).optional(),
    authoritative: z.record(z.string(), z.array(label)).optional(),
    minScore: z.number().optional(),
    labels: z.array(label).optional(),
  }).default({}),
});

export type Config = z.infer<typeof ConfigSchema> & { home: string; resolvedPolicy: Policy };

export function configPath(home = defaultHome()) { return path.join(home, 'config.json'); }

export function loadConfig(home = defaultHome()): Config {
  const file = configPath(home);
  const raw = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
  const c = ConfigSchema.parse(raw);
  const p = c.policy;
  const resolvedPolicy: Policy = {
    mode: p.mode ?? DEFAULT_POLICY.mode,
    thresholds: { ...DEFAULT_POLICY.thresholds, ...(p.thresholds ?? {}) },
    weights: { ...DEFAULT_POLICY.weights, ...(p.weights ?? {}) },
    authoritative: { ...DEFAULT_POLICY.authoritative, ...(p.authoritative ?? {}) },
    minScore: p.minScore ?? DEFAULT_POLICY.minScore,
    labels: (p.labels ?? DEFAULT_POLICY.labels).filter((l) => (l !== 'PERSON' || c.names) && (l !== 'ADDRESS' || c.addresses)),
  };
  return { ...c, upstreams: { ...ConfigSchema.shape.upstreams.parse(undefined), ...c.upstreams }, home, resolvedPolicy };
}

/** Shallow-merges a patch into config.json (creating it). */
export function saveConfig(patch: Record<string, unknown>, home = defaultHome()) {
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const file = configPath(home);
  const raw = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
  writeFileSync(file, JSON.stringify({ ...raw, ...patch }, null, 2) + '\n');
}
