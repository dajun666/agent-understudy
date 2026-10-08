// Structured PII that regex plus a checksum catches better than any model.
import type { Detector, Label, PartKind, Span } from './types.ts';

export function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}

function ipv4Ok(s: string): boolean {
  const parts = s.split('.').map(Number);
  if (parts.some((p) => p > 255)) return false;
  // Loopback, unspecified, and version-number-looking addresses are noise in code.
  if (parts[0] === 127 || parts[0] === 0) return false;
  return true;
}

const US_STATES = 'AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC';

interface Pattern {
  id: string; label: Label; re: RegExp; check?: (m: string) => boolean; group?: number;
  /** Capture groups that are structure inside the match (for surrogates). */
  parts?: (m: RegExpMatchArray) => Array<{ group: number; kind: PartKind }>;
}

/** Email domains reserved for documentation and tests. */
export const RESERVED_EMAIL = /@(?:(?:[\w-]+\.)*example(?:\.(?:com|org|net))?|(?:[\w-]+\.)*(?:test|invalid|localhost)|localhost)$/i;

/** NANP 555-0100..0199, reserved for fiction (and what our own phone surrogates use). */
export const FICTIONAL_PHONE = /555\D?01\d\d$/;

const PATTERNS: Pattern[] = [
  // Not right after a backslash: JSON-escaped text has "\n@click.command(", which is no address.
  { id: 'email', label: 'EMAIL', re: /(?<![\\\w.%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b(?!:)/g, // "git@github.com:owner/repo" is SSH, not mail
    check: (m) => !RESERVED_EMAIL.test(m) && !/\.(?:png|jpe?g|gif|svg|webp)$/i.test(m) },
  { id: 'credit-card', label: 'ACCOUNT', re: /(?<![\d.])\b(?:\d[ -]?){12,18}\d\b/g, // not the digits of a decimal (3.684716553287982)
    check: (m) => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d) && !/^(\d)\1+$/.test(d); } },
  { id: 'iban', label: 'ACCOUNT', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, check: ibanOk },
  { id: 'us-ssn', label: 'ID', re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  // A sentence may end right after the number ("…461-8853."); a following digit means it's something else.
  { id: 'phone', label: 'PHONE', re: /(?<![\w.])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)[ .-]?|\d{3}[ .-])\d{3}[ .-]\d{4}(?!\w|\.\d)/g,
    check: (m) => !FICTIONAL_PHONE.test(m) },
  // "Sunnyvale, CA 94087": city, state and ZIP. The city and ZIP are replaced, the state code kept.
  { id: 'us-city-state-zip', label: 'ADDRESS', re: new RegExp(`\\b((?:[A-Z][a-z]+(?:[ -](?=[A-Z]))?){1,3}),? (?:${US_STATES}) (\\d{5}(?:-\\d{4})?)\\b`, 'g'),
    parts: (m) => [{ group: 1, kind: 'city' }, { group: 2, kind: 'zip' }] },
  { id: 'ipv4', label: 'IP', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, check: ipv4Ok },
  // Formats newer than the bundled gitleaks rules.
  { id: 'openrouter-api-key', label: 'SECRET', re: /\bsk-or-v1-[0-9a-f]{64}\b/g },
  // Credentials embedded in a URL: only the password part is the secret.
  { id: 'url-credentials', label: 'SECRET', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:([^\s@/]{3,})@/gi, group: 1 },
];

function ibanOk(raw: string): boolean {
  const s = raw.replace(/ /g, '');
  if (s.length < 15 || s.length > 34) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const d of v) rem = (rem * 10 + Number(d)) % 97;
  }
  return rem === 1;
}

export class PatternDetector implements Detector {
  readonly id = 'patterns';
  readonly labels = ['EMAIL', 'ACCOUNT', 'ID', 'PHONE', 'IP', 'SECRET', 'ADDRESS'] as const;

  async detect(text: string): Promise<Span[]> {
    const spans: Span[] = [];
    for (const p of PATTERNS) {
      for (const m of text.matchAll(new RegExp(p.re.source, p.re.flags + 'd'))) {
        const [start, end] = m.indices![p.group ?? 0]!;
        const value = text.slice(start, end);
        if (p.check && !p.check(value)) continue;
        const parts = p.parts?.(m).filter((g) => m.indices![g.group]).map((g) => ({ start: m.indices![g.group]![0], end: m.indices![g.group]![1], kind: g.kind }));
        spans.push({ start, end, label: p.label, score: 1, detector: this.id, source: p.id, ...(parts?.length ? { parts } : {}) });
      }
    }
    return spans;
  }
}
