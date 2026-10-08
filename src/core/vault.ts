// Value <-> stand-in mapping. Stand-ins are deterministic (seeded by an HMAC of the value under a local
// key), so the same value yields byte-identical text on every turn — required for prompt caching and for
// Anthropic's thinking-signature check, which rejects history that changes between requests.
//
// Three stand-in styles, chosen per label:
//   token      RDX_SECRET_5cc16aa867   opaque, can't collide with real text
//   surrogate  Elena Park              realistic, so the model can reason about it
//   numbered   Person A                obviously fake, still readable
// Names and addresses are mapped word by word ("Maria" -> "Elena" everywhere), so a model that writes
// only the first name is still restored. A word stand-in that also shows up as real text in what you
// send is marked ambiguous and no longer restored on its own.
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { appendFileSync, chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_STYLES, makeSurrogate, numbered, type Style, type WordMapper } from './surrogates.ts';
import { isCommonWord } from './common-words.ts';
import type { Finding, Label, PartKind, SpanPart } from './types.ts';

/** RDX_<LABEL>_<10 hex>. Plain ASCII word characters: survives tokenizers, JSON escaping and markdown. */
export const PLACEHOLDER_RE = /RDX_[A-Z]+_[0-9a-f]{10}/g;

export function defaultHome(): string {
  return process.env.AGENT_UNDERSTUDY_HOME ?? path.join(os.homedir(), '.agent-understudy');
}

/** credential: a project secret shown as Hide(NAME); redacted everywhere, never restored, never persisted here. */
/**
 * sticky: once redacted, redact this value (and its name words and spellings) everywhere afterwards, even where no
 * detector fires. Only confident findings become sticky; a misread made sticky would spread to every later text.
 */
interface Entry { label: Label; value: string; style: Style | 'credential'; sticky?: boolean }
interface WordEntry { kind: PartKind; word: string; sticky?: boolean }

const NAME_KINDS: ReadonlySet<PartKind> = new Set(['given', 'family']);
const WORD_CHAR = /[\p{L}\p{N}_]/u;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Whether a match sits on a word joint: a non-letter on each side, or a camelCase seam
 * ("get|ElenaPark", "elenaPark|Id"), but not inside a longer word ("Park" in "Parking").
 */
export function joint(text: string, at: number, m: string): boolean {
  const p = text[at - 1]; const n = text[at + m.length];
  const isL = (c?: string) => !!c && /\p{L}/u.test(c);
  const before = !isL(p) || (/\p{Ll}/u.test(p!) && /\p{Lu}/u.test(m[0]!));
  const after = !isL(n) || (/\p{Lu}/u.test(n!) && !/\p{Lu}/u.test(m.at(-1)!));
  return before && after;
}

/** Confident enough to spread: a rule or the vault voted, two models agreed, or one model was very sure. */
function confident(f: Finding): boolean {
  const rules = new Set(['gitleaks', 'patterns', 'vault']);
  const models = f.voters.filter((v) => !rules.has(v.detector));
  return f.voters.some((v) => rules.has(v.detector) || v.source === 'known') || models.length >= 2 || models.some((v) => v.score > 0.92);
}

/** A match inside a path (~/.claude/x, /Users/a/b) or an env/constant name (AGENT_SECRET_X): never rewritten. */
export function inPathOrEnvName(text: string, at: number, len: number): boolean {
  let a = at; let b = at + len;
  while (a > 0 && !/[\s"'`(),;<>[\]{}=]/.test(text[a - 1]!)) a--;
  while (b < text.length && !/[\s"'`(),;<>[\]{}=]/.test(text[b]!)) b++;
  const token = text.slice(a, b);
  return token.includes('/') || /^\$?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(token.replace(/^\$\{?|\}$/g, ''));
}

/** Same-shape spellings of a two-or-more-word name: [stand-in form, real form]. */
export function nameVariants(standIn: string, value: string): Array<[string, string]> {
  const words = (x: string) => x.split(/\s+/).filter((w) => /^\p{L}/u.test(w));
  const a = words(standIn); const b = words(value);
  if (a.length < 2 || a.length !== b.length) return [];
  const [af, al, bf, bl] = [a[0]!, a.at(-1)!, b[0]!, b.at(-1)!];
  if (al.split('-').length !== bl.split('-').length) return [];
  const cap = (w: string) => w.charAt(0).toUpperCase() + w.slice(1); // keep inner capitals (McClure)
  const low = (w: string) => w.toLowerCase();
  // l = surname as written ("Okonkwo-Hale"); p = its pieces (["Okonkwo", "Hale"]) for forms that drop the hyphen.
  const forms: Array<(f: string, l: string, p: string[]) => string> = [
    (f, l) => `${f[0]}. ${l}`, (f, l) => `${l}, ${f}`, (f, l) => `${f} ${l[0]}.`,
    (f, l) => low(`${f}.${l}`), (f, _l, p) => low([f, ...p].join('_')), (f, _l, p) => low([f, ...p].join('-')),
    (f, _l, p) => low(f + p.join('')), (f, _l, p) => cap(f) + p.map(cap).join(''), (f, _l, p) => low(f) + p.map(cap).join(''),
    (f, l) => low(`${f[0]}${l}`), (f, _l, p) => low(f[0] + p.join('')), (f, l) => low(`${f[0]}.${l}`), (f, _l, p) => low([f[0], ...p].join('_')),
    (f, _l, p) => low([...p, f].join('_')), (f, _l, p) => [f, ...p].join('_').toUpperCase(),
  ];
  // Short joined forms ("epark") could be real words; keep only ones with some length to them.
  // Forms with punctuation or a space ("E. Park", "Park, Elena") are distinctive at any length.
  const seen = new Set<string>();
  return forms.map((g) => [g(af, al, al.split('-')), g(bf, bl, bl.split('-'))] as [string, string])
    .filter(([x]) => (/[\s.,]/.test(x) || x.length >= 5) && !seen.has(x) && seen.add(x));
}

export interface VaultOptions { styles?: Partial<Record<Label, Style>> }

export class Vault {
  private readonly key: Buffer;
  private readonly file?: string;
  readonly styles: Record<Label, Style>;
  private readonly byStandIn = new Map<string, Entry>();
  private readonly byValue = new Map<string, string>();
  private readonly wordByStandIn = new Map<string, WordEntry>();
  private readonly wordByKey = new Map<string, string>();
  private readonly ambiguous = new Set<string>();
  private version = 0;
  private cache?: {
    version: number; re?: RegExp; map: Map<string, string>; prefixes: Set<string>; maxLen: number; sticky?: RegExp; stickyWords: Map<string, string>;
    /** Real spellings of known names -> the same spelling of their stand-in (outbound). */
    outVariants: Map<string, string>; outRe?: RegExp;
    /** Keys of outVariants that are a lone name word (need identifier glue to count). */
    outWords: Set<string>;
    knownRe?: RegExp;
  };

  /** dir undefined = in-memory only (tests, MCP dry runs). */
  constructor(dir?: string, opts: VaultOptions = {}) {
    this.styles = { ...DEFAULT_STYLES, ...(opts.styles ?? {}) };
    if (!dir) { this.key = randomBytes(32); return; }
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const keyFile = path.join(dir, 'vault.key');
    if (!existsSync(keyFile)) writeFileSync(keyFile, randomBytes(32).toString('hex'), { mode: 0o600 });
    chmodSync(keyFile, 0o600);
    this.key = Buffer.from(readFileSync(keyFile, 'utf8').trim(), 'hex');
    this.file = path.join(dir, 'vault.jsonl');
    this.sync();
  }

  /** Bytes of vault.jsonl already applied: other engines (other agent sessions) append to the same file. */
  private offset = 0;

  /**
   * Applies records other processes appended since the last look. Cheap when nothing changed (one stat),
   * so every entry point calls it: a stand-in issued in one session restores in another.
   */
  sync(): void {
    if (!this.file) return;
    let size: number;
    try { size = statSync(this.file).size; } catch { return; }
    if (size <= this.offset) return;
    const fd = openSync(this.file, 'r');
    try {
      const buf = Buffer.alloc(size - this.offset);
      readSync(fd, buf, 0, buf.length, this.offset);
      const text = buf.toString('utf8');
      // Only whole lines: a line another process is still writing is read next time.
      const end = text.lastIndexOf('\n') + 1;
      for (const line of text.slice(0, end).split('\n')) {
        if (!line) continue;
        try {
          const rec = JSON.parse(line);
          const d = JSON.parse(this.decrypt(rec.d));
          if (rec.t === 'word') this.rememberWord(rec.p, d);
          else if (rec.t === 'ambiguous') { this.ambiguous.add(d.s); this.version++; }
          else this.remember(rec.p, { style: 'token', ...d });
        } catch { /* skip a torn line */ }
      }
      this.offset += Buffer.byteLength(text.slice(0, end));
    } finally { closeSync(fd); }
  }

  get size(): number { return this.byStandIn.size; }

  /** Returns the stand-in for a value, creating and persisting it on first sight. */
  placeholder(value: string, label: Label, parts: SpanPart[] = [], context = '', sticky = true): string {
    this.sync();
    const known = this.byValue.get(value);
    if (known) {
      const e = this.byStandIn.get(known)!;
      if (sticky && e.sticky === false) this.makeSticky(known, e);
      return known;
    }
    const variant = this.compiled().outVariants.get(value);
    if (variant) return variant; // a known name in another spelling: same spelling of its stand-in
    let style = this.styles[label] ?? 'token';
    if (style === 'numbered' && label !== 'PERSON' && label !== 'ADDRESS') style = 'surrogate';
    let p: string | undefined;
    if (style === 'surrogate') {
      try {
        for (let attempt = 0; attempt < 50 && !p; attempt++) {
          const c = makeSurrogate({ label, value, parts, seed: this.seed(`${label}:${value}`, attempt), word: this.wordMapper(context, sticky) });
          if (this.free(c, context)) p = c;
        }
      } catch { p = undefined; } // a label with no surrogate generator falls back to a token
    } else if (style === 'numbered') {
      const n = [...this.byStandIn.values()].filter((e) => e.style === 'numbered' && e.label === label).length;
      p = numbered(label, n);
    }
    if (!p) { style = 'token'; p = `RDX_${label}_${createHmac('sha256', this.key).update(value).digest('hex').slice(0, 10)}`; }
    this.remember(p, { label, value, style, sticky });
    this.persist({ p, d: this.encrypt(JSON.stringify({ label, value, style, sticky })) });
    return p;
  }

  /** A value first seen in a doubtful finding, now confirmed: it (and its name words) start spreading. */
  private makeSticky(p: string, e: Entry) {
    e.sticky = true;
    this.persist({ p, d: this.encrypt(JSON.stringify(e)) });
    if (e.label === 'PERSON') {
      for (const w of e.value.split(/[\s-]+/)) {
        for (const kind of NAME_KINDS) {
          const s = this.wordByKey.get(`${kind}:${w}`);
          const we = s ? this.wordByStandIn.get(s) : undefined;
          if (s && we && we.sticky === false) { we.sticky = true; this.persist({ t: 'word', p: s, d: this.encrypt(JSON.stringify(we)) }); }
        }
      }
    }
    this.version++;
  }

  /** Names the user listed in config (their own name, handles): always redacted, wherever they appear. */
  private readonly known = new Set<string>();
  seedKnownNames(names: string[]) {
    for (const n of names.map((x) => x.trim()).filter((x) => x.length >= 3)) {
      this.placeholder(n, 'PERSON', [], '', true);
      this.known.add(n);
    }
    this.version++;
  }

  lookup(standIn: string): string | undefined {
    this.sync();
    const e = this.byStandIn.get(standIn);
    return e?.style === 'credential' ? undefined : e?.value;
  }

  /**
   * Registers a project credential: its value is redacted to Hide(NAME) wherever it appears and is never
   * put back (commands get it from the environment instead). Kept in memory only; the credential store
   * holds the encrypted copy.
   */
  addCredential(name: string, value: string): string {
    this.removeCredential(name);
    const ref = `Hide(${name})`;
    const prior = this.byValue.get(value);
    if (prior) this.byStandIn.delete(prior); // the same value seen earlier as plain PII: credential wins
    this.remember(ref, { label: 'SECRET', value, style: 'credential' });
    return ref;
  }

  removeCredential(name: string): void {
    const ref = `Hide(${name})`;
    const e = this.byStandIn.get(ref);
    if (!e) return;
    this.byStandIn.delete(ref);
    this.byValue.delete(e.value);
    this.version++;
  }

  /** Replaces credential values (only those) with Hide(NAME): for records the person reads too, where PII stays. */
  scrubCredentials(text: string): string {
    this.fingerprintSpans(text); // registers session values remembered only by fingerprint
    let out = text;
    for (const [ref, e] of this.byStandIn) if (e.style === 'credential' && out.includes(e.value)) out = out.split(e.value).join(ref);
    return out;
  }

  private fingerprints: Array<{ name: string; h: string; len: number }> = [];
  private fingerprintFn?: (s: string) => string;
  /** Session credentials the gateway no longer holds: recognised by keyed fingerprint (HMAC + length). */
  setFingerprints(list: Array<{ name: string; h: string; len: number }>, fn: (s: string) => string) {
    this.fingerprints = list;
    this.fingerprintFn = fn;
  }

  /** Values in text matching a stored fingerprint; each match is registered as a credential from then on. */
  private fingerprintSpans(text: string): Array<{ start: number; end: number; label: Label; source?: string }> {
    if (!this.fingerprints.length || !this.fingerprintFn) return [];
    const lens = new Set(this.fingerprints.map((f) => f.len));
    const out: Array<{ start: number; end: number; label: Label; source?: string }> = [];
    for (const m of text.matchAll(/[A-Za-z0-9_\-.+/~=]{8,}/g)) {
      // "KEY=value" glued together: also try the part after the first "=".
      const eq = m[0].indexOf('=');
      const cands: Array<[string, number]> = [[m[0], m.index!]];
      if (eq > 0) cands.push([m[0].slice(eq + 1), m.index! + eq + 1]);
      for (const [cand, at] of cands) {
        if (!lens.has(cand.length)) continue;
        const h = this.fingerprintFn(cand);
        const f = this.fingerprints.find((x) => x.h === h && x.len === cand.length);
        if (!f) continue;
        this.addCredential(f.name, cand);
        out.push({ start: at, end: at + cand.length, label: 'SECRET', source: 'fingerprint' });
      }
    }
    return out;
  }

  credentialNames(): string[] {
    return [...this.byStandIn].filter(([, e]) => e.style === 'credential').map(([s]) => s.slice(5, -1));
  }

  /** Spans of values the vault already knows: once redacted, always redacted, even where detectors miss. */
  stickySpans(text: string): Array<{ start: number; end: number; label: Label; source?: string }> {
    this.sync();
    const fp = this.fingerprintSpans(text);
    const c = this.compiled();
    const out: Array<{ start: number; end: number; label: Label; source?: string }> = [...fp];
    if (c.outRe) {
      for (const m of text.matchAll(c.outRe)) {
        if (!joint(text, m.index!, m[0])) continue;
        if (inPathOrEnvName(text, m.index!, m[0].length)) continue;
        // A single lower/upper-case name word counts only when glued into an identifier (okafor_team, OKAFOR-ID).
        if (c.outWords.has(m[0])) {
          const p = text[m.index! - 1] ?? ''; const n = text[m.index! + m[0].length] ?? '';
          const glue = /[_\-.0-9]/.test(p) || /[_\-.0-9]/.test(n) || (/\p{Ll}/u.test(p) && /\p{Lu}/u.test(m[0][0]!)) || /\p{Lu}/u.test(n);
          if (!glue) continue;
        }
        out.push({ start: m.index!, end: m.index! + m[0].length, label: 'PERSON', source: 'variant' });
      }
    }
    if (c.knownRe) {
      for (const m of text.matchAll(c.knownRe)) {
        if (!joint(text, m.index!, m[0]) || inPathOrEnvName(text, m.index!, m[0].length)) continue;
        out.push({ start: m.index!, end: m.index! + m[0].length, label: 'PERSON', source: 'known' });
      }
    }
    for (const [value, p] of this.byValue) {
      if (value.length < 4) continue;
      const entry = this.byStandIn.get(p)!;
      if (entry.sticky === false) continue;
      const label = entry.label;
      for (let i = text.indexOf(value); i >= 0; i = text.indexOf(value, i + value.length)) out.push({ start: i, end: i + value.length, label });
    }
    // Name words on their own ("Maria" after "Maria Santos" was redacted), whole words, as capitalized.
    if (c.sticky) {
      for (const m of text.matchAll(c.sticky)) {
        if (inPathOrEnvName(text, m.index!, m[0].length)) continue;
        out.push({ start: m.index!, end: m.index! + m[0].length, label: 'PERSON' });
      }
    }
    return out;
  }

  /**
   * Whether text carries a whole stand-in or token we issued — a sign that something before us already
   * redacted it (the Claude Code mod, the opencode plugin) or a restore missed. Such text is not "real".
   */
  hasIssuedStandIns(text: string): boolean {
    PLACEHOLDER_RE.lastIndex = 0;
    if (PLACEHOLDER_RE.test(text) || /Hide\([A-Z][A-Z0-9_]{1,63}\)/.test(text)) { PLACEHOLDER_RE.lastIndex = 0; return true; }
    PLACEHOLDER_RE.lastIndex = 0;
    const c = this.compiled();
    if (!c.re) return false;
    for (const m of text.matchAll(c.re)) if (this.byStandIn.has(m[0])) return true;
    return false;
  }

  /** Where our own stand-ins occur in text (so detectors don't redact a stand-in a second time). */
  standInSpans(text: string): Array<[number, number]> {
    const out: Array<[number, number]> = [...text.matchAll(PLACEHOLDER_RE)].map((m) => [m.index!, m.index! + m[0].length]);
    for (const m of text.matchAll(/Hide\([A-Z][A-Z0-9_]{1,63}\)/g)) out.push([m.index!, m.index! + m[0].length]);
    const c = this.compiled();
    if (c.re) for (const m of text.matchAll(c.re)) if (this.byStandIn.has(m[0]) || this.wordByStandIn.has(m[0])) out.push([m.index!, m.index! + m[0].length]);
    return out;
  }

  /**
   * Marks word stand-ins that occur in real outgoing text as ambiguous: if "Elena" is both Maria's
   * stand-in and a real person in your data, a lone "Elena" in a reply can't be restored safely.
   */
  observe(text: string): void {
    for (const [s, w] of this.wordByStandIn) {
      if (w.kind === 'domain') continue; // *.example is reserved: never a real word
      if (this.ambiguous.has(s) || !text.includes(s)) continue;
      const re = new RegExp(`(?<![\\p{L}\\p{N}_])${escapeRe(s)}(?![\\p{L}\\p{N}_])`, 'u');
      if (!re.test(text)) continue;
      this.ambiguous.add(s);
      this.version++;
      this.persist({ t: 'ambiguous', d: this.encrypt(JSON.stringify({ s })) });
    }
  }

  /** Replaces redactable findings (non-overlapping, any order) with stand-ins. */
  apply(text: string, findings: Finding[]): string {
    const todo = findings.filter((f) => f.redact);
    // Names first, so an email built from the same person reuses the name's stand-in.
    for (const f of todo.filter((f) => f.label === 'PERSON')) this.placeholder(f.value, f.label, f.parts, text, confident(f));
    let out = text;
    let floor = Infinity;
    for (const f of todo.sort((a, b) => b.start - a.start)) {
      if (f.end > floor) continue; // overlaps a later one already replaced
      out = out.slice(0, f.start) + this.placeholder(f.value, f.label, f.parts, text, confident(f)) + out.slice(f.end);
      floor = f.start;
    }
    return out;
  }

  /** Puts real values back: tokens, whole stand-ins and their case variants, then unambiguous name words. */
  restore(text: string, escape: (v: string) => string = (v) => v): string {
    this.sync();
    let out = text.replace(PLACEHOLDER_RE, (p) => { const v = this.lookup(p); return v === undefined ? p : escape(v); });
    const c = this.compiled();
    if (c.re) {
      out = out.replace(c.re, (m, offset: number, whole: string) => {
        const v = c.map.get(m);
        return v === undefined || !joint(whole, offset, m) ? m : escape(v);
      });
    }
    return out;
  }

  /**
   * Stand-in fragments still present in text that was already restored: a surrogate name glued into an
   * identifier ("rubieCremin2"), a stand-in domain, a fictional 555-01xx number, an unknown RDX token.
   * Realistic stand-ins look like real data, so anything about to be written to disk is checked.
   * Words that are also real in your data (ambiguous) are not reported.
   */
  residue(text: string): string[] {
    this.sync();
    const found = new Set<string>();
    for (const m of text.matchAll(PLACEHOLDER_RE)) found.add(m[0]);
    // A credential reference where a value was meant: the command should read $AGENT_SECRET_<NAME>.
    for (const m of text.matchAll(/Hide\(([A-Z][A-Z0-9_]{1,63})\)/g)) if (this.byStandIn.has(m[0])) found.add(m[0]);
    const lower = text.toLowerCase();
    for (const [standIn, w] of this.wordByStandIn) {
      if (this.ambiguous.has(standIn) || standIn.length < 4) continue;
      if (w.kind === 'domain') { if (lower.includes(standIn.toLowerCase())) found.add(standIn); continue; }
      if (!lower.includes(standIn.toLowerCase())) continue;
      // A word on its own or glued into an identifier at a case/underscore/digit joint
      // ("rubieCremin", "CREMIN_ID"), but not inside a longer word ("parking" for "Park").
      for (const m of text.matchAll(new RegExp(escapeRe(standIn), 'giu'))) {
        if (joint(text, m.index!, m[0])) { found.add(m[0]); break; }
      }
    }
    for (const [standIn, e] of this.byStandIn) {
      if (e.style === 'token' || e.style === 'credential' || e.label === 'PERSON') continue;
      // Numbers may be re-punctuated ("7435550115"): match the digits with any separators between them.
      const digits = standIn.replace(/\D/g, '');
      if (digits.length >= 7 ? new RegExp(`(?<!\\d)${[...digits].join('[\\s.()+-]*')}(?!\\d)`).test(text) : text.includes(standIn)) found.add(standIn);
    }
    return [...found];
  }

  /** How many trailing characters of a stream could still turn into something restore() rewrites. */
  holdLength(s: string): number {
    this.sync();
    const c = this.compiled();
    for (let k = Math.min(c.maxLen, s.length); k > 0; k--) {
      const start = s.length - k;
      if (start > 0 && WORD_CHAR.test(s[start - 1]!)) continue;
      if (c.prefixes.has(s.slice(start))) return k;
    }
    return 0;
  }

  // ---------------------------------------------------------------------------------------------------

  private seed(key: string, attempt: number): number {
    return createHmac('sha256', this.key).update(`${key}#${attempt}`).digest().readUInt32BE(0);
  }

  /** A stand-in must not equal a real value, another stand-in, or anything already in the text. */
  private free(c: string, context: string): boolean {
    if (!c || this.byStandIn.has(c) || this.byValue.has(c)) return false;
    return !new RegExp(`(?<![\\p{L}\\p{N}_])${escapeRe(c)}(?![\\p{L}\\p{N}_])`, 'iu').test(context);
  }

  private wordMapper(context: string, sticky = true): WordMapper {
    const map: WordMapper = (word, kind, make) => {
      const key = `${kind}:${word}`;
      const known = this.wordByKey.get(key);
      if (known) {
        const we = this.wordByStandIn.get(known);
        if (sticky && we && we.sticky === false) { we.sticky = true; this.version++; this.persist({ t: 'word', p: known, d: this.encrypt(JSON.stringify(we)) }); }
        return known;
      }
      let s = '';
      for (let attempt = 0; attempt < 50; attempt++) {
        const c = make(this.seed(key, attempt));
        // Name stand-ins of 4+ letters: short ones collide with real words and slip past the residue check.
        // Same shape: a plain word maps to a plain word (Faker has "Stiedemann-Koelpin", "O'Connell"), so
        // identifiers built from the stand-in stay valid and spelling variants line up.
        if (c && !(/[\s'’-]/.test(c) && !/[\s'’-]/.test(word))
          && (!NAME_KINDS.has(kind) || c.length >= Math.min(4, word.length)) && c.toLowerCase() !== word.toLowerCase() && !this.wordByStandIn.has(c) && !this.wordByKey.has(`${kind}:${c}`)
          && !this.isRealWord(c) && !new RegExp(`(?<![\\p{L}\\p{N}_])${escapeRe(c)}(?![\\p{L}\\p{N}_])`, 'iu').test(context)) { s = c; break; }
      }
      if (!s) s = make(this.seed(key, 99)) + String(this.seed(key, 100) % 90 + 10); // guaranteed distinct
      this.rememberWord(s, { kind, word, sticky });
      this.persist({ t: 'word', p: s, d: this.encrypt(JSON.stringify({ kind, word, sticky })) });
      return s;
    };
    map.kindOf = (w) => (this.wordByKey.has(`family:${w}`) ? 'family' : this.wordByKey.has(`given:${w}`) ? 'given' : undefined);
    map.peek = (w) => {
      const lw = w.toLowerCase();
      for (const k of NAME_KINDS) for (const [key, s] of this.wordByKey) if (key.startsWith(`${k}:`) && key.slice(k.length + 1).toLowerCase() === lw) return s;
      return undefined;
    };
    return map;
  }

  private isRealWord(s: string): boolean {
    for (const k of this.wordByKey.keys()) if (k.slice(k.indexOf(':') + 1) === s) return true;
    return false;
  }

  private remember(p: string, e: Entry) { this.byStandIn.set(p, e); this.byValue.set(e.value, p); this.version++; }
  private rememberWord(s: string, e: WordEntry) { this.wordByStandIn.set(s, e); this.wordByKey.set(`${e.kind}:${e.word}`, s); this.version++; }

  private persist(rec: Record<string, unknown>) {
    if (!this.file) return;
    // Catch up first, so the offset still marks where our own line starts (it is applied already).
    this.sync();
    const line = JSON.stringify(rec) + '\n';
    // One write with O_APPEND: lines from concurrent engines never interleave.
    appendFileSync(this.file, line, { mode: 0o600 });
    const size = statSync(this.file).size;
    if (size === this.offset + Buffer.byteLength(line)) this.offset = size;
  }

  /** Restore table, stream prefixes and the sticky-word matcher, rebuilt when the vault changes. */
  private compiled() {
    if (this.cache?.version === this.version) return this.cache;
    const map = new Map<string, string>();
    const add = (s: string, v: string) => {
      if (!map.has(s)) map.set(s, v);
      if (!map.has(s.toLowerCase())) map.set(s.toLowerCase(), v.toLowerCase());
      if (!map.has(s.toUpperCase())) map.set(s.toUpperCase(), v.toUpperCase());
    };
    for (const [s, e] of this.byStandIn) {
      if (e.style === 'token' || e.style === 'credential') continue;
      add(s, e.value);
      // Written-differently forms of a person ("E. Park", "elena_park", "ElenaPark") restore explicitly
      // to the same form of the real name, instead of hoping the model copies the stand-in verbatim.
      if (e.label === 'PERSON' && e.style === 'surrogate') for (const [sv, vv] of nameVariants(s, e.value)) add(sv, vv);
    }
    for (const [s, w] of this.wordByStandIn) if (!this.ambiguous.has(s)) add(s, w.word);
    const keys = [...map.keys()].filter((k) => k.length >= 2).sort((a, b) => b.length - a.length);
    // Boundaries are checked per match (joint()), so stand-ins inside identifiers are found too.
    const re = keys.length ? new RegExp(`(?:${keys.map(escapeRe).join('|')})`, 'gu') : undefined;
    const prefixes = new Set<string>();
    let maxLen = 0;
    for (const k of keys) { maxLen = Math.max(maxLen, k.length); for (let i = 1; i <= k.length; i++) prefixes.add(k.slice(0, i)); }
    const stickyWords = new Map<string, string>();
    for (const [key, s] of this.wordByKey) {
      const [kind, word] = [key.slice(0, key.indexOf(':')), key.slice(key.indexOf(':') + 1)];
      // Never spread an ordinary word or product name learned from a misread ("Asking Claude").
      if (NAME_KINDS.has(kind as PartKind) && word.length >= 3 && /^\p{Lu}/u.test(word) && !isCommonWord(word)
        && this.wordByStandIn.get(s)?.sticky !== false) stickyWords.set(word, s);
    }
    const sw = [...stickyWords.keys()].sort((a, b) => b.length - a.length);
    const sticky = sw.length ? new RegExp(`(?<![\\p{L}\\p{N}_])(?:${sw.map(escapeRe).join('|')})(?![\\p{L}\\p{N}_])`, 'gu') : undefined;
    // Outbound: the real name written the ways code writes it ("daniel-okafor", "danielOkaforId", "dokafor",
    // "Okafor, Daniel", "OKAFOR") becomes the same form of the stand-in, so history the model wrote with
    // stand-ins comes back to it unchanged and no spelling of the real name slips out.
    const outVariants = new Map<string, string>();
    for (const [s, e] of this.byStandIn) {
      if (e.label !== 'PERSON' || e.style !== 'surrogate' || e.sticky === false) continue;
      for (const [sv, rv] of nameVariants(s, e.value)) { outVariants.set(rv, sv); outVariants.set(rv.toUpperCase(), sv.toUpperCase()); }
    }
    const outWords = new Set<string>();
    for (const [key, s] of this.wordByKey) {
      const kind = key.slice(0, key.indexOf(':')); const w = key.slice(key.indexOf(':') + 1);
      if (!NAME_KINDS.has(kind as PartKind) || w.length < 4 || isCommonWord(w) || /\d/.test(w) || this.wordByStandIn.get(s)?.sticky === false) continue;
      // Lone name words in lower/upper case: only inside identifiers (see stickySpans), never as prose words.
      for (const [rv, sv] of [[w.toLowerCase(), s.toLowerCase()], [w.toUpperCase(), s.toUpperCase()]] as const) {
        if (!outVariants.has(rv)) { outVariants.set(rv, sv); outWords.add(rv); }
      }
    }
    const ov = [...outVariants.keys()].sort((a, b) => b.length - a.length);
    const outRe = ov.length ? new RegExp(`(?:${ov.map(escapeRe).join('|')})`, 'gu') : undefined;
    const kn = [...this.known].sort((a, b) => b.length - a.length);
    const knownRe = kn.length ? new RegExp(`(?:${kn.map(escapeRe).join('|')})`, 'giu') : undefined;
    this.cache = { version: this.version, re, map, prefixes, maxLen, sticky, stickyWords, outVariants, outRe, outWords, knownRe };
    return this.cache;
  }

  private encrypt(s: string): string {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.key, iv);
    const ct = Buffer.concat([c.update(s, 'utf8'), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
  }

  private decrypt(b64: string): string {
    const b = Buffer.from(b64, 'base64');
    const d = createDecipheriv('aes-256-gcm', this.key, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
  }
}
