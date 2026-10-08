// Shared contract between detectors, the ensemble, the vault and the front-ends (gateway, MCP, hooks).
// Node runs this via native type stripping: no enums, no parameter properties, no namespaces.

/** Unified label set every detector maps its own taxonomy onto. */
export const LABELS = [
  'SECRET', 'EMAIL', 'PHONE', 'PERSON', 'ADDRESS', 'ACCOUNT', 'URL', 'DATE', 'IP', 'ID',
] as const;
export type Label = (typeof LABELS)[number];

/** Sub-entity kinds the taggers report inside a name or an address. */
export type PartKind = 'given' | 'family' | 'street' | 'number' | 'city' | 'zip' | 'domain';
export interface SpanPart { start: number; end: number; kind: PartKind }

/** A character span in the scanned text. Offsets are UTF-16 code units (JS string indices). */
export interface Span {
  start: number;
  end: number;
  label: Label;
  /** 0..1. Rule-based detectors report 1. */
  score: number;
  /** Detector id that produced the span. */
  detector: string;
  /** Detector-native label or rule id, for auditing. */
  source?: string;
  /** Structure inside the span (absolute offsets), when the detector reports it. */
  parts?: SpanPart[];
}

export interface Detector {
  readonly id: string;
  /** Labels this detector can emit. The ensemble only counts a detector's vote for labels it covers. */
  readonly labels: readonly Label[];
  detect(text: string): Promise<Span[]>;
}

/** A merged entity after voting. */
export interface Finding {
  start: number;
  end: number;
  label: Label;
  /** The matched text. Never returned to a model, only kept locally. */
  value: string;
  /** Weighted vote total and the threshold it was compared against. */
  votes: number;
  threshold: number;
  redact: boolean;
  voters: Array<{ detector: string; label: Label; score: number; source?: string }>;
  /** Detectors that cover this label but did not flag it. */
  abstained: string[];
  /** Why a cluster that cleared the vote was still kept, e.g. "path". */
  suppressed?: string;
  /** Structure inside the value (offsets relative to start), from the most detailed voter. */
  parts?: SpanPart[];
}
