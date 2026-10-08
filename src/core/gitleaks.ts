// Runs gitleaks rules (rules/gitleaks.toml, MIT) in JS.
// Go RE2 syntax is translated to JS: mid-pattern (?i) flags become (?i:...) modifier groups,
// (?P<name> becomes a plain capture group (keeps group numbering), \z becomes $, POSIX classes expand.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parse } from 'smol-toml';
import type { Detector, Span } from './types.ts';

interface RawAllowlist {
  condition?: 'AND' | 'OR';
  regexTarget?: 'match' | 'line' | 'secret';
  regexes?: string[];
  stopwords?: string[];
  paths?: string[];
}
interface RawRule {
  id: string;
  regex?: string;
  entropy?: number;
  keywords?: string[];
  secretGroup?: number;
  path?: string;
  allowlists?: RawAllowlist[];
}

interface Allowlist {
  and: boolean;
  target: 'match' | 'line' | 'secret';
  regexes: RegExp[];
  stopwords: string[];
  /** Path-only allowlists can't apply to free text; they are dropped at load time. */
}
interface Rule {
  id: string;
  re: RegExp;
  entropy?: number;
  keywords: string[];
  secretGroup?: number;
  allowlists: Allowlist[];
}

const POSIX: Record<string, string> = {
  alnum: 'a-zA-Z0-9', alpha: 'a-zA-Z', digit: '0-9', lower: 'a-z', upper: 'A-Z',
  space: '\\s', xdigit: '0-9a-fA-F', word: '\\w', punct: '!-\\/:-@\\[-`{-~',
};

/** Translates a Go RE2 pattern to a JS RegExp source. Exported for tests. */
export function goToJs(src: string): string {
  src = src.replace(/\[:(\w+):\]/g, (m, n: string) => POSIX[n] ?? m);
  let out = '';
  // For each open group: the modifier groups we opened inside it, which must close with it.
  const pending: string[][] = [[]];
  const top = () => pending[pending.length - 1];
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') {
      const n = src[i + 1];
      if (n === 'z') out += '$';
      else if (n === 'A') out += '^';
      else out += c + (n ?? '');
      i++;
      continue;
    }
    if (inClass) { if (c === ']') inClass = false; out += c; continue; }
    if (c === '[') {
      inClass = true; out += c;
      // A leading ']' (or '^]') is a literal in RE2.
      if (src[i + 1] === ']') { out += '\\]'; i++; } else if (src[i + 1] === '^' && src[i + 2] === ']') { out += '^\\]'; i += 2; }
      continue;
    }
    if (c === '(') {
      const flag = /^\(\?([a-zA-Z]+)\)/.exec(src.slice(i));
      if (flag) {
        // RE2: flags apply to the rest of the enclosing group.
        const flags = flag[1].replace(/[^ims]/g, '');
        if (flags) { out += `(?${flags}:`; top().push(flags); }
        i += flag[0].length - 1;
        continue;
      }
      if (src.startsWith('(?P<', i)) { out += '('; i = src.indexOf('>', i); pending.push([]); continue; }
      out += c;
      pending.push([]);
      continue;
    }
    if (c === ')') {
      out += ')'.repeat((pending.pop() ?? []).length) + ')';
      if (!pending.length) pending.push([]);
      continue;
    }
    if (c === '|' && top().length) {
      // RE2 keeps the flags on for later branches of the same group; JS modifier groups can't span a
      // top-level bar without changing precedence, so close them and reopen them after it.
      out += ')'.repeat(top().length) + '|' + top().map((f) => `(?${f}:`).join('');
      continue;
    }
    out += c;
  }
  return out + ')'.repeat(pending.reduce((a, b) => a + b.length, 0));
}

export function shannon(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

function compile(src: string): RegExp | undefined {
  try { return new RegExp(goToJs(src), 'gd'); } catch { return undefined; }
}

export interface GitleaksLoad { rules: Rule[]; global: Allowlist; skipped: string[] }

export function loadGitleaks(file = path.resolve(import.meta.dirname, '../../rules/gitleaks.toml')): GitleaksLoad {
  const raw = parse(readFileSync(file, "utf8")) as unknown as { rules: RawRule[]; allowlist?: RawAllowlist };
  const skipped: string[] = [];
  const toAllow = (a: RawAllowlist): Allowlist | undefined => {
    const regexes = (a.regexes ?? []).map(compile).filter((r): r is RegExp => !!r).map((r) => new RegExp(r.source, ''));
    const stopwords = (a.stopwords ?? []).map((s) => s.toLowerCase());
    if (!regexes.length && !stopwords.length) return undefined; // path-only
    // AND with a path condition can never be satisfied on free text.
    if (a.condition === 'AND' && a.paths?.length) return undefined;
    return { and: a.condition === 'AND', target: a.regexTarget ?? 'secret', regexes, stopwords };
  };
  const rules: Rule[] = [];
  for (const r of raw.rules) {
    if (!r.regex) { skipped.push(`${r.id} (path-only)`); continue; }
    const re = compile(r.regex);
    if (!re) { skipped.push(`${r.id} (regex)`); continue; }
    rules.push({
      id: r.id, re, entropy: r.entropy, secretGroup: r.secretGroup,
      keywords: (r.keywords ?? []).map((k) => k.toLowerCase()),
      allowlists: (r.allowlists ?? []).map(toAllow).filter((a): a is Allowlist => !!a),
    });
  }
  const global = toAllow(raw.allowlist ?? {}) ?? { and: false, target: 'secret', regexes: [], stopwords: [] };
  return { rules, global, skipped };
}

function lineAt(text: string, start: number, end: number): string {
  const s = text.lastIndexOf('\n', start - 1) + 1;
  const e = text.indexOf('\n', end);
  return text.slice(s, e < 0 ? text.length : e);
}

function allowed(a: Allowlist, secret: string, match: string, line: string): boolean {
  const target = a.target === 'match' ? match : a.target === 'line' ? line : secret;
  const checks: boolean[] = [];
  if (a.regexes.length) checks.push(a.regexes.some((r) => r.test(target)));
  if (a.stopwords.length) { const l = secret.toLowerCase(); checks.push(a.stopwords.some((w) => l.includes(w))); }
  return a.and ? checks.every(Boolean) : checks.some(Boolean);
}

export class GitleaksDetector implements Detector {
  readonly id = 'gitleaks';
  readonly labels = ['SECRET'] as const;
  readonly loaded: GitleaksLoad;
  constructor(loaded = loadGitleaks()) { this.loaded = loaded; }

  async detect(text: string): Promise<Span[]> {
    const lower = text.toLowerCase();
    const spans: Span[] = [];
    for (const rule of this.loaded.rules) {
      if (rule.keywords.length && !rule.keywords.some((k) => lower.includes(k))) continue;
      rule.re.lastIndex = 0;
      for (const m of text.matchAll(rule.re)) {
        const idx = m.indices!;
        // secretGroup, else the first non-empty capture group, else the whole match.
        let g = rule.secretGroup ?? 0;
        if (!g) g = m.findIndex((v, i) => i > 0 && v !== undefined && v !== '');
        if (g < 0 || !idx[g]) g = 0;
        const [start, end] = idx[g]!;
        const secret = text.slice(start, end);
        if (!secret.trim()) continue;
        if (rule.entropy && shannon(secret) < rule.entropy) continue;
        const line = lineAt(text, start, end);
        if ([this.loaded.global, ...rule.allowlists].some((a) => allowed(a, secret, m[0], line))) continue;
        spans.push({ start, end, label: 'SECRET', score: 1, detector: this.id, source: rule.id });
      }
    }
    return spans;
  }
}
