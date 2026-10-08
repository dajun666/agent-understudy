// Realistic stand-ins ("surrogates") so the model can still reason about redacted values:
// "Maria Santos <maria.santos@gmail.com>" goes out as "Elena Park <elena.park@example.net>".
// Generation is deterministic (seeded per value) so the same value gets the same stand-in every turn.
// Structure comes from the taggers' sub-spans when they have them: a given name becomes a given name,
// a house number keeps its digit count, punctuation and street suffixes stay where they were.
import { Faker, base, en } from '@faker-js/faker';
import type { Label, PartKind, SpanPart } from './types.ts';

export type Style = 'surrogate' | 'numbered' | 'token';

/** Labels that get surrogates by default. Secrets stay opaque tokens: a real-looking fake key could be
 *  copied somewhere it does damage, and the model gains nothing from reading one. */
export const DEFAULT_STYLES: Record<Label, Style> = {
  PERSON: 'surrogate', EMAIL: 'surrogate', PHONE: 'surrogate', ADDRESS: 'surrogate', ACCOUNT: 'surrogate',
  ID: 'surrogate', IP: 'surrogate', SECRET: 'token', URL: 'token', DATE: 'token',
};

const faker = new Faker({ locale: [en, base] });
const FEMALE = new Set((faker.definitions.person.first_name as { female: string[] }).female);
const MALE = new Set((faker.definitions.person.first_name as { male: string[] }).male);

/** Name particles kept as written ("de la", "van", "bin"). */
const PARTICLES = new Set(['de', 'la', 'del', 'della', 'di', 'da', 'van', 'von', 'der', 'den', 'du', 'le', 'bin', 'binti', 'al', 'el', 'ibn', 'st.', 'mc']);
/** Address words that carry no identity and keep the surrogate looking like an address. */
const STREET_SUFFIX = /^(?:street|st|avenue|ave|road|rd|lane|ln|drive|dr|boulevard|blvd|court|ct|way|place|pl|terrace|ter|circle|cir|highway|hwy|parkway|pkwy|square|sq|apt|suite|ste|unit|#)\.?$/i;
const US_STATE = /^[A-Z]{2}$/;
/** Webmail providers: an address there identifies nobody by its domain. */
const PUBLIC_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com',
  'icloud.com', 'me.com', 'mac.com', 'proton.me', 'protonmail.com', 'pm.me', 'aol.com', 'gmx.com', 'gmx.de', 'mail.com',
  'fastmail.com', 'hey.com', 'tutanota.com', 'zoho.com', 'yandex.com', 'qq.com', '163.com', '126.com', 'naver.com']);
/** Local-part segments that are roles or habits, not identities. */
const GENERIC_LOCAL = new Set(['dev', 'work', 'mail', 'info', 'admin', 'team', 'hello', 'contact', 'office', 'home', 'me',
  'personal', 'private', 'test', 'noreply', 'no', 'reply', 'support', 'sales', 'billing', 'hi', 'the', 'real', 'official']);

/** Maps one word of a name or address to its surrogate; owned by the vault (persistent, collision-checked). */
export interface WordMapper {
  (word: string, kind: PartKind, make: (seed: number) => string): string;
  /** The surrogate a name word already has (case-insensitive), for building matching emails. */
  peek?: (word: string) => string | undefined;
  /** How the vault already knows this word (a lone "Okonkwo-Hale" is the family name it was before). */
  kindOf?: (word: string) => PartKind | undefined;
}

export interface SurrogateInput {
  label: Label;
  value: string;
  /** Sub-spans relative to value (from masker/piiranha); may be empty. */
  parts: SpanPart[];
  seed: number;
  word: WordMapper;
}

function seeded<T>(seed: number, f: (fk: Faker) => T): T { faker.seed(seed); return f(faker); }

function sameCase(model: string, out: string): string {
  if (model === model.toUpperCase() && /[A-Z]/.test(model)) return out.toUpperCase();
  if (model === model.toLowerCase()) return out.toLowerCase();
  return out;
}

/** Replaces each digit with a seeded digit, keeping separators and length. */
export function shapeDigits(value: string, seed: number, fixed: Record<number, string> = {}): string {
  let i = 0;
  return seeded(seed, (fk) => value.replace(/\d/g, () => fixed[i++] ?? String(fk.number.int({ min: 0, max: 9 }))));
}

function luhnFix(digits: string): string {
  const body = digits.slice(0, -1);
  let sum = 0;
  for (let i = 0; i < body.length; i++) {
    let d = Number(body[body.length - 1 - i]);
    if (i % 2 === 0) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return body + String((10 - (sum % 10)) % 10);
}

function personWord(word: string, kind: PartKind, seed: number): string {
  return seeded(seed, (fk) => {
    if (kind === 'family') return fk.person.lastName();
    const sex = FEMALE.has(word) && !MALE.has(word) ? 'female' : MALE.has(word) && !FEMALE.has(word) ? 'male' : undefined;
    return fk.person.firstName(sex);
  });
}

/** Splits a name without tagger parts: first word given, last word family, particles kept. */
function guessNameParts(value: string): SpanPart[] {
  // A hyphenated surname is one part ("Okonkwo-Hale" is family); its pieces are mapped one by one later.
  const words = [...value.matchAll(/[\p{L}][\p{L}'’.]*(?:-[\p{L}][\p{L}'’.]*)*/gu)];
  const named = words.filter((w) => !PARTICLES.has(w[0].toLowerCase()) && !/^(?:mr|mrs|ms|dr|prof|sir)\.?$/i.test(w[0]));
  return named.map((w, i) => ({
    start: w.index!, end: w.index! + w[0].length,
    kind: (named.length > 1 && i === named.length - 1 ? 'family' : 'given') as PartKind,
  }));
}

/** Rewrites value part by part; text between parts is kept when it carries no identity, else replaced. */
function rebuild(value: string, parts: SpanPart[], map: (p: SpanPart, text: string) => string, gap: (text: string, offset: number) => string): string {
  let out = '';
  let at = 0;
  for (const p of [...parts].sort((a, b) => a.start - b.start)) {
    if (p.start < at) continue;
    out += gap(value.slice(at, p.start), at) + map(p, value.slice(p.start, p.end));
    at = p.end;
  }
  return out + gap(value.slice(at), at);
}

export function makeSurrogate({ label, value, parts, seed, word }: SurrogateInput): string {
  switch (label) {
    case 'PERSON': {
      // A handle ("jdoe42", "jane_dev") gets a username, not a person's name.
      if (/^[A-Za-z0-9._-]+$/.test(value) && (/[0-9._]/.test(value) || /^[a-z]/.test(value))) {
        return seeded(seed, (fk) => fk.internet.username().toLowerCase().replace(/[^a-z0-9._-]/g, ''));
      }
      let ps = parts.some((p) => p.kind === 'given' || p.kind === 'family') ? parts : guessNameParts(value);
      // A name written alone keeps the role it had in the full name, so it maps to the same stand-in.
      ps = ps.map((p) => {
        const w = value.slice(p.start, p.end);
        const known = word.kindOf?.(w) ?? word.kindOf?.(w.split('-')[0]!);
        return known ? { ...p, kind: known } : p;
      });
      if (!ps.length) return seeded(seed, (fk) => fk.person.fullName());
      // Words the tagger left unlabeled are names too: given before the family name, family after it.
      const familyAt = ps.filter((p) => p.kind === 'family').map((p) => p.start);
      return rebuild(value, ps,
        // Hyphenated names keep their shape: each part gets its own stand-in ("Okonkwo-Hale" -> "Volkman-Price").
        (p, t) => t.split(/(\s+|-)/).map((w) => (/^(?:\s*|-)$/.test(w) || PARTICLES.has(w.toLowerCase()) ? w
          : sameCase(w, word(w, p.kind, (s) => personWord(w, p.kind, s))))).join(''),
        (g, off) => g.replace(/[\p{L}][\p{L}'’]*/gu, (w, i: number) => {
          if (PARTICLES.has(w.toLowerCase()) || /^(?:mr|mrs|ms|dr|prof)$/i.test(w)) return w;
          const kind: PartKind = familyAt.some((f) => f > off + i) ? 'given' : 'family';
          return sameCase(w, word(w, kind, (s) => personWord(w, kind, s)));
        }));
    }
    case 'ADDRESS': {
      if (!parts.length) {
        return seeded(seed, (fk) => fk.location.streetAddress() + (value.includes(',') ? `, ${fk.location.city()}` : ''));
      }
      return rebuild(value, parts,
        (p, t) => {
          if (p.kind === 'number' || p.kind === 'zip') return shapeDigits(t, seed + p.start);
          if (p.kind === 'city') return word(t, 'city', (s) => seeded(s, (fk) => fk.location.city()));
          // street: replace the name words, keep "Lane"/"St."
          return t.split(/(\s+)/).map((w) => (/^\s*$/.test(w) || STREET_SUFFIX.test(w) ? w
            : word(w, 'street', (s) => seeded(s, (fk) => fk.person.lastName())))).join('');
        },
        (g) => g.split(/(\s+|,)/).map((w) => (!w || /^[\s,]+$/.test(w) || STREET_SUFFIX.test(w) || US_STATE.test(w) ? w
          : /\d/.test(w) ? shapeDigits(w, seed + w.length) : word(w, 'street', (s) => seeded(s, (fk) => fk.person.lastName())))).join(''));
    }
    case 'EMAIL': {
      const at = value.lastIndexOf('@');
      const local = value.slice(0, at);
      const domain = value.slice(at + 1);
      // Reuse the person's surrogate inside the address so the conversation stays coherent;
      // generic segments ("dev", "work") carry no identity and stay.
      const segs = local.split(/([._+-])/);
      const mapped = segs.map((s) => (/^[a-z]{3,}$/i.test(s) ? word.peek?.(s) : undefined));
      const newLocal = mapped.some(Boolean)
        ? segs.map((s, i) => (mapped[i] ? sameCase(s, mapped[i]!) : /\d/.test(s) ? shapeDigits(s, seed + i)
          : /^[\p{L}]+$/u.test(s) && !GENERIC_LOCAL.has(s.toLowerCase()) ? sameCase(s, seeded(seed + i, (fk) => fk.word.noun())) : s)).join('')
        : seeded(seed, (fk) => fk.internet.username().toLowerCase());
      // Webmail domains say nothing about who you are and keep answers about "the domain" true.
      // Anything else (a company) maps to a stand-in under the reserved .example TLD (RFC 2606),
      // remembered as a word so "acme.com" alone is restored too.
      const newDomain = PUBLIC_MAIL.has(domain.toLowerCase()) ? domain
        : word(domain.toLowerCase(), 'domain', (s) => `${seeded(s, (fk) => fk.word.noun().toLowerCase())}.example`);
      return `${newLocal}@${newDomain}`;
    }
    case 'PHONE': {
      const digits = value.replace(/\D/g, '');
      // NANP numbers: 555-01xx is reserved for fiction.
      if (digits.length === 10 || (digits.length === 11 && digits[0] === '1')) {
        const off = digits.length - 10;
        const fixed: Record<number, string> = { [off + 3]: '5', [off + 4]: '5', [off + 5]: '5', [off + 6]: '0', [off + 7]: '1' };
        if (off) fixed[0] = '1';
        return shapeDigits(value, seed, fixed);
      }
      return shapeDigits(value, seed);
    }
    case 'ACCOUNT': {
      const digits = value.replace(/\D/g, '');
      if (digits.length >= 12) {
        // Same issuer digit and grouping, valid Luhn so code that checks it still runs.
        const fake = luhnFix(digits[0] + seeded(seed, (fk) => fk.string.numeric(digits.length - 1)));
        let i = 0;
        return value.replace(/\d/g, () => fake[i++]!);
      }
      return value.replace(/[A-Z]/g, () => seeded(seed++, (fk) => fk.string.alpha({ casing: 'upper', length: 1 })))
        .replace(/\d/g, () => String(seeded(seed++, (fk) => fk.number.int(9))));
    }
    case 'ID': {
      // US SSNs: the 9xx area is never issued, and the SSN pattern ignores it.
      if (/^\d{3}-\d{2}-\d{4}$/.test(value)) return shapeDigits(value, seed, { 0: '9' });
      return value.replace(/[A-Z]/g, () => seeded(seed++, (fk) => fk.string.alpha({ casing: 'upper', length: 1 })))
        .replace(/[a-z]/g, () => seeded(seed++, (fk) => fk.string.alpha({ casing: 'lower', length: 1 })))
        .replace(/\d/g, () => String(seeded(seed++, (fk) => fk.number.int(9))));
    }
    case 'IP':
      // TEST-NET-3 (RFC 5737): documentation-only addresses.
      return `203.0.113.${1 + (seed % 254)}`;
    default:
      throw new Error(`no surrogate for ${label}`);
  }
}

/** "Person A", "Person B", ... "Person AA". */
export function numbered(label: Label, n: number): string {
  let s = '';
  for (let k = n; k >= 0; k = Math.floor(k / 26) - 1) s = String.fromCharCode(65 + (k % 26)) + s;
  const noun: Partial<Record<Label, string>> = { PERSON: 'Person', ADDRESS: 'Address', EMAIL: 'Email', PHONE: 'Phone', ACCOUNT: 'Account', ID: 'ID', IP: 'Host' };
  return `${noun[label] ?? label} ${s}`;
}
