// Voting: overlapping spans from different detectors form one cluster; the cluster is redacted when
// the weighted vote clears the label's threshold, or an authoritative detector flagged it.
import type { Detector, Finding, Label, Span } from './types.ts';
import { SYSTEM_USERS, isCommonWord, isLanguageOrPeople, isTechWord } from './common-words.ts';
import { FICTIONAL_PHONE, RESERVED_EMAIL } from './patterns.ts';

export type VoteMode = 'weighted' | 'any' | 'majority';

export interface Policy {
  mode: VoteMode;
  /** weighted mode: a cluster is redacted when sum(weight * score) >= threshold. */
  thresholds: Partial<Record<Label, number>> & { default: number };
  /** weights[detector][label], default 1. Lets you trust NER models for PERSON and regex for SECRET. */
  weights: Record<string, Partial<Record<Label, number>>>;
  /** A single vote from one of these detectors for one of these labels redacts, in every mode. */
  authoritative: Record<string, Label[]>;
  /** Spans below this score are ignored entirely. */
  minScore: number;
  /** Labels to act on. Findings with other labels are reported but never redacted. */
  labels: Label[];
}

export const DEFAULT_POLICY: Policy = {
  mode: 'weighted',
  // From the detector benchmark (bench/): one confident model is enough for names, addresses and phones.
  // Requiring two models to agree on a name cut recall on real sessions from 45% to 14%.
  thresholds: { default: 1.5, SECRET: 0.8, PERSON: 0.8, ADDRESS: 0.9, PHONE: 0.9 },
  weights: {
    gitleaks: { SECRET: 2 },
    patterns: { EMAIL: 2, ACCOUNT: 2, ID: 2, IP: 1, PHONE: 1, SECRET: 2 },
    'privacy-filter': { SECRET: 1, PERSON: 1, ADDRESS: 1 },
    masker: { PERSON: 1.2, ADDRESS: 1.2 },
    'gliner-pii': { PERSON: 0.8, ADDRESS: 0.8 },
  },
  authoritative: { gitleaks: ['SECRET'], patterns: ['EMAIL', 'ACCOUNT', 'ID', 'SECRET', 'ADDRESS'] },
  minScore: 0.3,
  labels: ['SECRET', 'EMAIL', 'PHONE', 'PERSON', 'ADDRESS', 'ACCOUNT', 'ID'],
};

/** Rule-based voters; everything else is a model. */
const RULE_DETECTORS = new Set(['gitleaks', 'patterns', 'vault']);

/** Capitalized words that open sentences or label fields, never part of a name. */
const NOT_NAMES = new Set(['Ask', 'Dear', 'Hi', 'Hello', 'Hey', 'Thanks', 'Contact', 'Owner', 'Name', 'Signed', 'From', 'To', 'Cc',
  'The', 'A', 'An', 'And', 'Or', 'By', 'With', 'For', 'Per', 'Mr', 'Mrs', 'Ms', 'Dr', 'Prof', 'Sir', 'Madam', 'Team', 'Billing',
  'Author', 'Maintainer', 'Reviewer', 'Assignee', 'Manager', 'Lead', 'Email', 'Phone', 'Address', 'Note', 'Notes', 'TODO', 'FIXME']);

/** Extends a name span by one adjacent capitalized word on each side ("Daniel" + "Okafor", "Okonkwo-Hale"). */
export function expandName(text: string, start: number, stop: number): [number, number] {
  const nameLike = (w: string) => !NOT_NAMES.has(w) && w.split('-').every((p) => !isCommonWord(p));
  // A hyphenated surname split by the tagger ("Okonkwo-" + "Hale", "Okonkwo" + "-Hale").
  const hl = /(\p{Lu}[\p{Ll}'’]+)-$/u.exec(text.slice(Math.max(0, start - 30), start));
  if (hl) start -= hl[0].length;
  const hy = /^-\p{Lu}[\p{Ll}'’]+/u.exec(text.slice(stop, stop + 30));
  if (hy) stop += hy[0].length;
  const left = /(\p{Lu}[\p{Ll}'’]+(?:-\p{Lu}[\p{Ll}'’]+)*) $/u.exec(text.slice(Math.max(0, start - 40), start));
  if (left && nameLike(left[1]!)) start -= left[0].length;
  const right = /^ (\p{Lu}[\p{Ll}'’]+(?:-\p{Lu}[\p{Ll}'’]+)*)(?![\p{L}])/u.exec(text.slice(stop, stop + 40));
  if (right && nameLike(right[1]!)) stop += right[0].length;
  return [start, stop];
}

/** Model spans stop at a line break: Read-tool output puts the next line's number right after it ("…4472\n  4\t"). */
function clipAtLine(text: string, s: Span): Span {
  if (RULE_DETECTORS.has(s.detector) || s.label === 'SECRET') return s;
  const nl = text.indexOf('\n', s.start);
  if (nl < 0 || nl >= s.end) return s;
  // Multi-line addresses are fine unless the next line starts with a line number.
  if (s.label === 'ADDRESS' && !/^\n\s*\d+\t/.test(text.slice(nl, nl + 12))) return s;
  return { ...s, end: nl, parts: s.parts?.filter((p) => p.end <= nl) };
}

// When detectors disagree on the label, the more dangerous one names the cluster.
const PRIORITY: Label[] = ['SECRET', 'ACCOUNT', 'ID', 'EMAIL', 'PHONE', 'PERSON', 'ADDRESS', 'IP', 'URL', 'DATE'];

export function vote(text: string, spans: Span[], ran: Detector[], policy: Policy = DEFAULT_POLICY): Finding[] {
  const live = spans.map((s) => clipAtLine(text, s)).filter((s) => s.score >= policy.minScore && s.end > s.start).sort((a, b) => a.start - b.start || b.end - a.end);
  const clusters: Span[][] = [];
  let end = -1;
  for (const s of live) {
    const last = clusters[clusters.length - 1];
    // Taggers split one address into "number + street" and "city, ST zip": rejoin pieces separated by ", ".
    const addressRun = s.label === 'ADDRESS' && last?.some((x) => x.label === 'ADDRESS') && s.start >= end && /^,? ?$/.test(text.slice(end, s.start));
    if (s.start < end || addressRun) { last!.push(s); end = Math.max(end, s.end); }
    else { clusters.push([s]); end = s.end; }
  }
  return clusters.map((c) => decide(text, c, ran, policy));
}

function decide(text: string, c: Span[], ran: Detector[], policy: Policy): Finding {
  // One vote per detector: its best span in the cluster.
  const best = new Map<string, Span>();
  for (const s of c) { const b = best.get(s.detector); if (!b || s.score > b.score) best.set(s.detector, s); }
  const voters = [...best.values()];
  // Rule-based voters know what they matched (a phone pattern is a phone); models' labels only break ties.
  const ruled = voters.filter((v) => RULE_DETECTORS.has(v.detector) && v.detector !== 'vault');
  const label = PRIORITY.find((l) => ruled.some((v) => v.label === l)) ?? PRIORITY.find((l) => voters.some((v) => v.label === l)) ?? voters[0].label;
  const weight = (s: Span) => policy.weights[s.detector]?.[s.label] ?? 1;
  const covering = ran.filter((d) => d.labels.includes(label));
  const abstained = covering.filter((d) => !best.has(d.id)).map((d) => d.id);

  let votes: number;
  let threshold: number;
  if (policy.mode === 'any') { votes = voters.length; threshold = 1; }
  else if (policy.mode === 'majority') {
    votes = voters.length;
    threshold = Math.floor(Math.max(covering.length, voters.length) / 2) + 1;
  } else {
    votes = voters.reduce((a, s) => a + weight(s) * s.score, 0);
    threshold = policy.thresholds[label] ?? policy.thresholds.default;
    // Thresholds assume two models can agree. With a single model covering this label (the light default),
    // agreement is impossible, so its own confident vote has to be enough or names never get redacted.
    const models = covering.filter((d) => !RULE_DETECTORS.has(d.id));
    if (models.length === 1) threshold = Math.min(threshold, (policy.weights[models[0]!.id]?.[label] ?? 1) * 0.8);
  }
  const auth = voters.filter((s) => policy.authoritative[s.detector]?.includes(s.label));
  const authoritative = auth.length > 0;
  // Extent: rule-based spans are exact (a URL's password, not the whole URL), so they win when present.
  // Otherwise the union of the model spans: over-redacting a few characters beats leaking a suffix.
  // Rule spans are exact for keys, emails, accounts and IDs. A city/state/zip rule only knows the tail of an
  // address and names come from models, so those take the union of every voter.
  const basis = authoritative && label !== 'ADDRESS' && label !== 'PERSON' ? auth : voters;
  let start = Math.min(...basis.map((s) => s.start));
  let stop = Math.max(...basis.map((s) => s.end));
  if (!authoritative && label === 'SECRET') [start, stop] = trimAssignment(text, start, stop);
  // Taggers often catch only the surname (or only the given name); the neighbour is part of the name too.
  if (label === 'PERSON') {
    // "@author Dangelo Simonis", "@Marcelle", "_nathan_hauke": the name is what follows the tag or sigil.
    const lead = /^(?:@author\s+|@|_+)/.exec(text.slice(start, stop));
    if (lead && lead[0].length < stop - start) start += lead[0].length;
    [start, stop] = expandName(text, start, stop);
  }
  if (label === 'ADDRESS') {
    const suffix = /^ (?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Court|Ct|Way|Place|Pl|Terrace|Circle|Highway|Hwy|Parkway|Pkwy)\b\.?/.exec(text.slice(stop, stop + 14));
    if (suffix) stop += suffix[0].length;
  }
  const value = text.slice(start, stop);
  // Names listed in knownNames are redacted even when name detection is off: the person asked for them.
  const passed = (policy.labels.includes(label) || voters.some((s) => s.source === 'known')) && (authoritative || votes >= threshold);
  // The vault's sticky vote only repeats an earlier decision, so it can't vouch for a code-shaped value.
  // Spelling variants of a known name are exact matches, not guesses: they are rule-backed too.
  const ruleBacked = voters.some((s) => (RULE_DETECTORS.has(s.detector) && s.detector !== 'vault') || s.source === 'variant' || s.source === 'fingerprint' || s.source === 'known');
  let suppressed = passed && !ruleBacked ? codeShape(value, label) ?? modelOnlyShape(text, start, value, label) : undefined;
  // Model-only "secrets" that are bare hex or UUIDs are commit SHAs and ids unless something says key/token.
  if (passed && !ruleBacked && !suppressed && label === 'SECRET' && /^(?:[0-9a-f]{7,64}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$/i.test(value)
    && !/(?:key|token|secret|passw(?:or)?d|bearer|auth|credential)\W{0,6}$/i.test(text.slice(Math.max(0, start - 40), start))) suppressed = 'hex';
  // Structure for surrogates: the voter whose parts cover the most of the final extent.
  const parts = voters
    .map((s) => (s.parts ?? []).filter((p) => p.start >= start && p.end <= stop))
    .sort((a, b) => b.reduce((n, p) => n + p.end - p.start, 0) - a.reduce((n, p) => n + p.end - p.start, 0))[0]
    ?.map((p) => ({ ...p, start: p.start - start, end: p.end - start }));
  return {
    start, end: stop, label, value, ...(parts?.length ? { parts } : {}),
    votes: Math.round(votes * 100) / 100, threshold,
    redact: passed && !suppressed, suppressed,
    voters: voters.map((s) => ({ detector: s.detector, label: s.label, score: Math.round(s.score * 1000) / 1000, source: s.source })),
    abstained,
  };
}

/** Models often tag `API_KEY="value"` as one secret; keep the name and quotes, redact the value. */
export function trimAssignment(text: string, start: number, stop: number): [number, number] {
  const span = text.slice(start, stop);
  const m = /^[A-Za-z_][\w.-]*\s*(?:=|:(?!\/\/))\s*(["'`]?)/.exec(span);
  if (m && m[0].length < span.length - 4) {
    start += m[0].length;
    if (m[1] && text[stop - 1] === m[1]) stop--;
  }
  return [start, stop];
}

/**
 * What models trained on prose tag in tool output (benchmark set A, public agent traces):
 * ls -l owners ("root root"), file names, numbers taken for house numbers, languages taken for people.
 * Applies to model-only findings; a rule or a name the vault already trusts is never second-guessed here.
 */
export function modelOnlyShape(text: string, start: number, value: string, label: Label): string | undefined {
  const v = value.trim();
  if (label === 'ADDRESS') {
    // An address needs words: "1847 Juniper Hollow Lane", "Sunnyvale". File sizes, counts, line numbers do not.
    if (!/\p{L}{2,}/u.test(v)) return 'number';
  }
  if (label === 'PERSON') {
    if (!/^\p{L}/u.test(v) || /[=/\\\n]/.test(v) || v.startsWith('.')) return 'not-a-name';
    const words = v.split(/\s+/);
    if (words.every((w) => SYSTEM_USERS.has(w.toLowerCase()))) return 'system-user';
    if (words.every((w) => isLanguageOrPeople(w))) return 'language';
    // "-rw-r--r--  1 owner group  size date name": the owner may be a real person's login (keep that redacted),
    // but the file name after the time/year is not a person. Tool output is often JSON-escaped, so a literal "\n"
    // separates lines too.
    const head = text.slice(Math.max(0, start - 200), start);
    const esc = head.lastIndexOf('\\n');
    const line = head.slice(Math.max(head.lastIndexOf('\n') + 1, esc < 0 ? 0 : esc + 2));
    if (/(?:^|\s)[-dlcbps][rwxsStT-]{9}[@+.]?\s+\d+\s.*(?:\d{1,2}:\d{2}|\s\d{4})\s+\.?$/.test(line)) return 'ls-file-name';
  }
  return undefined;
}

/**
 * Model taggers trained on prose mistake code identifiers for IDs and account numbers. Replacing a
 * file path or a commit hash breaks the agent (it can no longer open the file), so a model-only
 * cluster whose whole value has one of these shapes is kept. Rule-based findings are never suppressed.
 */
export function codeShape(value: string, label: Label): string | undefined {
  const v = value.trim();
  if (/^(?:~|\.{1,2})?\/?(?:[\w.@+-]+\/)+[\w.@+ -]*$/.test(v) && v.includes('/')) return 'path';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) return 'uuid';
  if (label !== 'SECRET' && /^[0-9a-f]{7,64}$/i.test(v)) return 'hex';
  // Documentation addresses (RFC 2606): example.com, *.test, *.invalid, localhost.
  if (label === 'EMAIL' && RESERVED_EMAIL.test(v)) return 'example-email';
  if (label === 'PHONE' && FICTIONAL_PHONE.test(v)) return 'fictional-phone';
  if (label !== 'SECRET' && /^v?\d+(?:\.\d+){1,3}(?:[-+][\w.]+)?$/.test(v) && !/^\d{3}\.\d{3}\.\d{4}$/.test(v)) return 'version';
  // Tool, function and env-var names ("mcp__agent-understudy__secret_request", "OPENROUTER_API_KEY"):
  // whole words joined by _ or -, no digits — a generated secret never looks like this.
  // ...but "Okonkwo-Hale" (Title-Case joined by hyphens) is a name, not an identifier.
  if (/^[A-Za-z]{2,}(?:[_-]+[A-Za-z]{2,})+$/.test(v) && !/^\p{Lu}\p{Ll}+(?:-\p{Lu}\p{Ll}+)+$/u.test(v)) return 'identifier';
  // "Asking Claude", "Claude Agent SDK": ordinary words and product names, not a person.
  if (label === 'PERSON') {
    const words = v.split(/[\s-]+/).filter(Boolean);
    if (words.length && words.every((w) => isCommonWord(w) || isTechWord(w) || /^[A-Z]{2,}$/.test(w)) && words.some((w) => isTechWord(w) || isCommonWord(w))) return 'common-words';
  }
  return undefined;
}
