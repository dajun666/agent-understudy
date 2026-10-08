// Wires config -> detectors -> redactor. Shared by the gateway, the CLI and the MCP server.
import type { Config } from './config.ts';
import { GitleaksDetector } from './core/gitleaks.ts';
import { PatternDetector } from './core/patterns.ts';
import { Redactor } from './core/redactor.ts';
import { SidecarClient, SidecarDetector } from './core/sidecar.ts';
import { Vault } from './core/vault.ts';
import path from 'node:path';
import type { Detector } from './core/types.ts';

export function buildRedactor(config: Config, opts: { models?: string[]; sidecar?: SidecarClient; vault?: Vault } = {}) {
  const sidecar = opts.sidecar ?? new SidecarClient(`http://127.0.0.1:${config.sidecarPort}`);
  const models = opts.models ?? config.models;
  const detectors: Detector[] = [new GitleaksDetector(), new PatternDetector(), ...models.map((m) => new SidecarDetector(m, sidecar))];
  const vault = opts.vault ?? new Vault(config.home, { styles: config.placeholders });
  if (config.knownNames?.length) vault.seedKnownNames(config.knownNames);
  return { redactor: new Redactor({ detectors, vault, policy: config.resolvedPolicy, cacheFile: path.join(config.home, 'detections.jsonl') }), sidecar };
}
