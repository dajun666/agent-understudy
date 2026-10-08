// Ordinary words and product names that taggers mistake for names ("Asking Claude", "Claude Agent SDK").
// A wrong name is not just one bad replacement: the vault remembers its words and rewrites them everywhere
// afterwards (~/.claude -> ~/.isaias). These checks keep such words from becoming name material.
import { existsSync, readFileSync } from 'node:fs';

/** Product, vendor and tooling names that show up title-cased in agent traffic. */
const TECH = new Set([
  'claude', 'codex', 'anthropic', 'openai', 'gpt', 'gemini', 'opencode', 'copilot', 'cursor', 'github', 'gitlab', 'google',
  'microsoft', 'apple', 'amazon', 'aws', 'azure', 'docker', 'kubernetes', 'linux', 'macos', 'windows', 'python', 'node',
  'typescript', 'javascript', 'rust', 'go', 'swift', 'kotlin', 'java', 'react', 'vue', 'svelte', 'next', 'vite', 'npm',
  'pnpm', 'yarn', 'bun', 'deno', 'git', 'slack', 'discord', 'notion', 'obsidian', 'figma', 'vercel', 'netlify', 'cloudflare',
  'stripe', 'twilio', 'sentry', 'postgres', 'redis', 'sqlite', 'mysql', 'mongo', 'supabase', 'firebase', 'tmux', 'herdr',
  'sdk', 'api', 'cli', 'mcp', 'agent', 'agents', 'hooks', 'plugin', 'plugins', 'skill', 'skills', 'model', 'models', 'sonnet',
  'opus', 'haiku', 'fable', 'mod', 'mods', 'gateway', 'sidecar', 'vault', 'hide', 'redact',
]);

let dict: Set<string> | undefined;
let proper: Set<string> | undefined;
function lowercaseDictionary(): Set<string> {
  if (dict) return dict;
  dict = new Set();
  proper = new Set();
  for (const f of ['/usr/share/dict/words', '/usr/dict/words']) {
    if (!existsSync(f)) continue;
    // Lower-case entries are ordinary words; capitalised ones are proper names (Maria, Grace, Mark).
    for (const w of readFileSync(f, 'utf8').split('\n')) {
      if (!w) continue;
      if (w === w.toLowerCase()) dict.add(w); else proper.add(w.toLowerCase());
    }
    break;
  }
  return dict;
}

/** A plain dictionary word (incl. common inflections) or a product/tool name. */
export function isCommonWord(word: string): boolean {
  const w = word.toLowerCase().replace(/['’]s$/, '');
  if (TECH.has(w)) return true;
  const d = lowercaseDictionary();
  if (!d.size) return false;
  // Names that are also words (Maria, Grace, Mark) are listed as proper names too: treat them as names.
  if (proper!.has(w)) return false;
  if (d.has(w)) return true;
  for (const [suffix, add] of [['ing', ''], ['ing', 'e'], ['ed', ''], ['ed', 'e'], ['es', ''], ['s', ''], ['ly', ''], ['er', ''], ['ers', '']] as const) {
    if (w.endsWith(suffix) && w.length - suffix.length >= 3 && d.has(w.slice(0, -suffix.length) + add)) return true;
  }
  return false;
}

export function isTechWord(word: string): boolean { return TECH.has(word.toLowerCase()); }

/** Languages, peoples and writing systems: models tag "Russian", "Tangut", "Nüshu" as people. */
const LANGUAGES = new Set(`afrikaans albanian amharic arabic aramaic armenian assamese avestan azerbaijani balinese basque belarusian
bengali bosnian braille breton bulgarian burmese cantonese catalan cherokee chinese coptic cornish croatian cuneiform cyrillic czech
danish devanagari dutch egyptian english esperanto estonian ethiopic faroese farsi filipino finnish flemish french frisian galician
georgian german glagolitic gothic greek gujarati gurmukhi haitian hangul hausa hawaiian hebrew hieroglyphs hindi hiragana hmong
hungarian icelandic igbo indonesian inuktitut irish italian japanese javanese kannada kashmiri katakana kazakh khmer kinyarwanda
korean kurdish kyrgyz lao latin latvian lithuanian luxembourgish macedonian malagasy malay malayalam maltese mandarin manx maori
marathi mongolian nepali norwegian nushu nüshu occitan odia ogham oriya oromo pashto persian phoenician polish portuguese punjabi
quechua romanian runic russian samoan sanskrit scottish serbian sindhi sinhala slovak slovenian somali spanish sundanese swahili
swedish syriac tagalog tajik tamil tangut tatar telugu thaana thai tibetan tifinagh tigrinya tongan turkish turkmen ugaritic
ukrainian urdu uyghur uzbek vietnamese welsh wolof xhosa yiddish yoruba zulu american british canadian australian european asian
african latino hispanic`.split(/\s+/));
export function isLanguageOrPeople(word: string): boolean { return LANGUAGES.has(word.toLowerCase()); }

/** Account names on machines and in containers, not people. */
export const SYSTEM_USERS = new Set(['root', 'admin', 'administrator', 'nobody', 'daemon', 'www-data', 'ubuntu', 'ec2-user', 'git',
  'postgres', 'mysql', 'nginx', 'apache', 'runner', 'user', 'guest', 'staff', 'wheel', 'docker', 'node', 'app', 'bin', 'sys']);
