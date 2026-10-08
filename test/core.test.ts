import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { GitleaksDetector, goToJs } from '../src/core/gitleaks.ts';
import { PatternDetector, luhn } from '../src/core/patterns.ts';
import { DEFAULT_POLICY, vote } from '../src/core/ensemble.ts';
import { Redactor } from '../src/core/redactor.ts';
import { Vault } from '../src/core/vault.ts';
import type { Detector, Label, Span } from '../src/core/types.ts';

const alnum = (n: number) => Array.from(randomBytes(n), (b) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[b % 62]).join('');
const ghp = 'ghp_' + alnum(36);
const anthropic = 'sk-ant-api03-' + alnum(93) + 'AA';

/** A fake model detector that flags fixed substrings. */
function fake(id: string, labels: Label[], hits: Array<[string, Label, number]>): Detector {
  return {
    id, labels,
    async detect(text) {
      const out: Span[] = [];
      for (const [s, label, score] of hits) {
        const i = text.indexOf(s);
        if (i >= 0) out.push({ start: i, end: i + s.length, label, score, detector: id });
      }
      return out;
    },
  };
}

test('go regex translation', () => {
  assert.equal(goToJs('x(?i)a|b'), 'x(?i:a)|(?i:b)');
  assert.equal(goToJs('(?P<n>a)\\z'), '(a)$');
  assert.equal(goToJs('[[:alnum:]]'), '[a-zA-Z0-9]');
  assert.ok(new RegExp(goToJs('\\b(p8e-(?i)[a-z0-9]{32})(?:x|$)')).test('p8e-' + 'A'.repeat(16) + 'b'.repeat(16) + 'x'));
});

test('gitleaks finds real-shaped keys, skips placeholders and env refs', async () => {
  const d = new GitleaksDetector();
  assert.ok(d.loaded.rules.length > 200);
  const text = `token = "${ghp}"\nANTHROPIC_API_KEY=${anthropic}\napi_key = "\${API_KEY}"\n`;
  const spans = await d.detect(text);
  const vals = spans.map((s) => text.slice(s.start, s.end));
  assert.ok(vals.includes(ghp), 'github pat');
  assert.ok(vals.includes(anthropic), 'anthropic key');
  assert.ok(!vals.some((v) => v.includes('${')), 'env reference allowed');
});

test('patterns: email, luhn card, ssn, url password', async () => {
  assert.ok(luhn('4111111111111111'));
  const text = 'mail sam.rivera@mailbox.org or a@example.com, card 4111 1111 1111 1111, bad 4111 1111 1111 1112, ssn 123-45-6789, db postgres://app:hunter2pw@db:5432/x';
  const spans = await new PatternDetector().detect(text);
  const got = spans.map((s) => `${s.source}:${text.slice(s.start, s.end)}`);
  assert.ok(got.includes('email:sam.rivera@mailbox.org'));
  assert.ok(!got.some((g) => g.includes('example.com')));
  assert.ok(got.includes('credit-card:4111 1111 1111 1111'));
  assert.ok(!got.some((g) => g.endsWith('1112')));
  assert.ok(got.includes('us-ssn:123-45-6789'));
  assert.ok(got.includes('url-credentials:hunter2pw'));
});

test('voting: one confident model suffices for PERSON/ADDRESS, a weak one does not', () => {
  const text = 'Alice Zhang lives at 12 Oak St';
  const a = fake('masker', ['PERSON', 'ADDRESS'], [['Alice Zhang', 'PERSON', 0.95], ['12 Oak St', 'ADDRESS', 0.9]]);
  const b = fake('gliner-pii', ['PERSON', 'ADDRESS'], [['Alice', 'PERSON', 0.7]]);
  const spans = [{ start: 0, end: 11, label: 'PERSON' as const, score: 0.95, detector: 'masker' },
    { start: 0, end: 5, label: 'PERSON' as const, score: 0.7, detector: 'gliner-pii' },
    { start: 21, end: 30, label: 'ADDRESS' as const, score: 0.9, detector: 'masker' }];
  const f = vote(text, spans, [a, b]);
  assert.equal(f.length, 2);
  assert.equal(f[0].value, 'Alice Zhang'); // union extent
  assert.ok(f[0].redact, `person votes ${f[0].votes}`);
  assert.ok(f[1].redact, `confident single-model address ${f[1].votes}`);
  assert.deepEqual(f[1].abstained, ['gliner-pii']);
  const weak = vote(text, [{ ...spans[2], score: 0.5 }], [a, b]);
  assert.ok(!weak[0].redact, `weak single-model address stays ${weak[0].votes}`);
  const any = vote(text, spans, [a, b], { ...DEFAULT_POLICY, mode: 'any' });
  assert.ok(any[1].redact);
  const maj = vote(text, spans, [a, b], { ...DEFAULT_POLICY, mode: 'majority' });
  assert.ok(maj[0].redact && !maj[1].redact);
});

test('redactor: deterministic placeholders, sticky values, restore, persistence', async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'rdx-'));
  const mk = () => new Redactor({ detectors: [new GitleaksDetector(), new PatternDetector()], vault: new Vault(dir) });
  const r = mk();
  const text = `export GITHUB_TOKEN=${ghp} # ask sam.rivera@mailbox.org`;
  const a = await r.redact(text);
  assert.ok(a.changed);
  assert.ok(!a.text.includes(ghp) && !a.text.includes('sam.rivera@mailbox.org'));
  assert.match(a.text, /RDX_SECRET_[0-9a-f]{10}/);
  assert.match(a.text, /# ask [\w.+-]+@[\w-]+\.example$/, 'company-domain email becomes a surrogate under .example');
  const b = await r.redact(text);
  assert.equal(a.text, b.text, 'same text every turn');
  assert.equal(r.restore(a.text), text);
  // A bare occurrence no detector would catch on its own is still redacted once known.
  const bare = await r.redact(`value: ${ghp.slice(0)}`);
  assert.ok(!bare.text.includes(ghp));
  // Placeholders are not re-redacted.
  const again = await r.redact(a.text);
  assert.equal(again.text, a.text);
  // New process, same dir: same placeholders, restore works.
  const r2 = mk();
  assert.equal((await r2.redact(text)).text, a.text);
  assert.equal(r2.restore(a.text), text);
  // JSON escaping on restore.
  assert.equal(r2.restore('RDX_EMAIL_0000000000 stays'), 'RDX_EMAIL_0000000000 stays');
});

test('failed detector is reported and not cached', async () => {
  let calls = 0;
  const flaky: Detector = { id: 'flaky', labels: ['PERSON'], async detect() { calls++; throw new Error('sidecar down'); } };
  const r = new Redactor({ detectors: [flaky, new PatternDetector()], vault: new Vault() });
  const x = await r.redact('hello Bob');
  assert.equal(x.errors[0].detector, 'flaky');
  await r.redact('hello Bob');
  assert.equal(calls, 2);
});

test('extent: regex span wins over a wider model span; model secrets drop the NAME= prefix', () => {
  const t1 = 'DATABASE_URL=postgres://app:Wint3rpass@db:5432/prod';
  const pw = t1.indexOf('Wint3rpass');
  const f1 = vote(t1, [
    { start: 13, end: t1.length, label: 'SECRET', score: 0.9, detector: 'privacy-filter' },
    { start: pw, end: pw + 10, label: 'SECRET', score: 1, detector: 'patterns' },
  ], []);
  assert.equal(f1[0].value, 'Wint3rpass');
  // Built at run time: a literal live-key shape in the source trips secret scanners on push.
  const stripe = ['sk', 'live', '51HvQpWLk2mN8xRtY4bZ0aQ9c'].join('_');
  const t2 = `STRIPE_KEY="${stripe}"`;
  const f2 = vote(t2, [{ start: 0, end: t2.length, label: 'SECRET', score: 0.95, detector: 'privacy-filter' },
    { start: 0, end: t2.length, label: 'SECRET', score: 0.9, detector: 'gliner-pii' }], []);
  assert.equal(f2[0].value, stripe);
});

test('model-only clusters shaped like code identifiers are kept', () => {
  const t = 'open /Users/dev/projects/app-5e1f0c2a/skills/SKILL.md and commit 3f9a2c1d';
  const p = t.indexOf('/Users'); const pe = t.indexOf(' and');
  const h = t.indexOf('3f9a2c1d');
  const f = vote(t, [
    { start: p, end: pe, label: 'ID', score: 0.95, detector: 'privacy-filter' },
    { start: p, end: pe, label: 'ID', score: 0.95, detector: 'masker' },
    { start: h, end: h + 8, label: 'ACCOUNT', score: 0.9, detector: 'privacy-filter' },
    { start: h, end: h + 8, label: 'ACCOUNT', score: 0.9, detector: 'masker' },
  ], []);
  assert.deepEqual(f.map((x) => [x.redact, x.suppressed]), [[false, 'path'], [false, 'hex']]);
});

test('surrogates: names map word by word, emails follow the name, restore handles case and lone names', async () => {
  const r = new Redactor({ detectors: [new PatternDetector(), fake('masker', ['PERSON'], [['Maria Santos', 'PERSON', 0.95]]), fake('privacy-filter', ['PERSON'], [['Maria Santos', 'PERSON', 0.9]])], vault: new Vault() });
  const text = 'Ask Maria Santos <maria.santos@gmail.com> about the deploy.';
  const a = await r.redact(text);
  const m = /^Ask (\S+) (\S+) <([^>]+)> about the deploy\.$/.exec(a.text);
  assert.ok(m, a.text);
  const [, first, last, email] = m!;
  assert.notEqual(first, 'Maria'); assert.notEqual(last, 'Santos');
  assert.equal(email, `${first.toLowerCase()}.${last.toLowerCase()}@gmail.com`, 'email built from the name surrogate; webmail domain kept');
  assert.equal((await r.redact(text)).text, a.text, 'deterministic');
  // The model answers with pieces of the surrogate; each piece comes back as the real value.
  assert.equal(r.restore(`Her first name is ${first}. ${last.toUpperCase()} signed it. Mail ${email}.`),
    'Her first name is Maria. SANTOS signed it. Mail maria.santos@gmail.com.');
  assert.equal(r.restore(`${first}'s change`), "Maria's change", 'possessive');
  // Company domains get a stand-in under .example, restored on their own too.
  const c = await r.redact('cc maria.santos.dev@acme-robotics.com');
  const dom = /@([\w.-]+)$/.exec(c.text)![1]!;
  assert.match(c.text, new RegExp(`^cc ${first.toLowerCase()}\\.${last.toLowerCase()}\\.dev@[\\w-]+\\.example$`), c.text);
  assert.equal(r.restore(`the domain is ${dom}`), 'the domain is acme-robotics.com');
  // A lone "Maria" later is redacted to the same first-name surrogate, even if no detector fires.
  const lone = await new Redactor({ detectors: [], vault: r.vault }).redact('thanks Maria!');
  assert.equal(lone.text, `thanks ${first}!`);
});

test('surrogates: collisions with real text are avoided, real uses of a stand-in make it ambiguous', async () => {
  const v = new Vault();
  const det = fake('masker', ['PERSON'], [['Maria Santos', 'PERSON', 0.95]]);
  const r = new Redactor({ detectors: [det, fake('privacy-filter', ['PERSON'], [['Maria Santos', 'PERSON', 0.9]])], vault: v });
  const a = await r.redact('Maria Santos wrote this.');
  const first = a.text.split(' ')[0];
  // The same first name now appears as a real word in outgoing text: lone mentions stop being restored.
  await r.redact(`Note from ${first} in accounting.`, { observe: true });
  assert.equal(r.restore(`${first} approved`), `${first} approved`);
  assert.match(r.restore(a.text), /^Maria Santos wrote this\.$/, 'the full stand-in still restores');
});

test('surrogates: phone, card, ssn keep their shape and stay out of real ranges', async () => {
  const r = new Redactor({ detectors: [new PatternDetector(), fake('privacy-filter', ['PHONE'], [['(510) 864-2297', 'PHONE', 0.9]])], vault: new Vault() });
  const a = await r.redact('call (510) 864-2297, card 4111 1111 1111 1111, ssn 123-45-6789');
  const m = /^call \((\d{3})\) 555-01(\d{2}), card (\d{4} \d{4} \d{4} \d{4}), ssn (9\d\d-\d\d-\d{4})$/.exec(a.text);
  assert.ok(m, a.text);
  assert.ok(luhn(m![3].replace(/ /g, '')), 'card still passes Luhn');
  assert.equal(r.restore(a.text), 'call (510) 864-2297, card 4111 1111 1111 1111, ssn 123-45-6789');
});

test('surrogates: numbered and token styles', async () => {
  const det = [fake('masker', ['PERSON'], [['Maria Santos', 'PERSON', 0.95]]), fake('privacy-filter', ['PERSON'], [['Maria Santos', 'PERSON', 0.9]])];
  const n = new Redactor({ detectors: det, vault: new Vault(undefined, { styles: { PERSON: 'numbered' } }) });
  assert.equal((await n.redact('hi Maria Santos')).text, 'hi Person A');
  assert.equal(n.restore('Person A said hi'), 'Maria Santos said hi');
  const t = new Redactor({ detectors: det, vault: new Vault(undefined, { styles: { PERSON: 'token' } }) });
  assert.match((await t.redact('hi Maria Santos')).text, /^hi RDX_PERSON_[0-9a-f]{10}$/);
});

test('surrogates: written-differently forms of a name restore to the same form of the real name', async () => {
  const r = new Redactor({ detectors: [fake('masker', ['PERSON'], [['Maria Santos', 'PERSON', 0.95]]), fake('privacy-filter', ['PERSON'], [['Maria Santos', 'PERSON', 0.9]])], vault: new Vault() });
  const out = (await r.redact('owner Maria Santos')).text;
  const [f, l] = out.split(' ').slice(1) as [string, string];
  const lf = f.toLowerCase(); const ll = l.toLowerCase();
  const said = `${f[0]}. ${l} | ${l}, ${f} | ${lf}.${ll} | ${lf}_${ll} | ${f}${l} | ${lf}${l} | ${lf[0]}${ll} | ${lf}_${ll}`.replace(`${lf}_${ll}`, `${lf}_${ll}`);
  assert.equal(r.restore(said), 'M. Santos | Santos, Maria | maria.santos | maria_santos | MariaSantos | mariaSantos | msantos | maria_santos');
});

test('residue: stand-in fragments left after restore are found; real words are not', async () => {
  const r = new Redactor({ detectors: [new PatternDetector(), fake('masker', ['PERSON'], [['Maria Santos', 'PERSON', 0.95]]),
    fake('privacy-filter', ['PERSON', 'PHONE'], [['Maria Santos', 'PERSON', 0.9], ['(510) 864-2297', 'PHONE', 0.9]])], vault: new Vault() });
  const out = (await r.redact('Maria Santos, (510) 864-2297, maria@acme-robotics.com')).text;
  const [f, l] = out.split(/[ ,]+/) as [string, string];
  const phone = /\(\d{3}\) 555-01\d\d/.exec(out)![0];
  const dom = /@([\w.-]+)/.exec(out)![1]!;
  // Everything the restore table knows comes back clean.
  assert.deepEqual(r.vault.residue(r.restore(out)), []);
  // Names glued into identifiers are restored outright (joint-aware), so they are not residue.
  const glued = `const ${f.toLowerCase()}${l}Id = 1; // call ${phone.replace(/\D/g, '')} at ${dom.toUpperCase()}, ref RDX_SECRET_0123456789`;
  const restored = r.restore(glued);
  assert.match(restored, /^const mariaSantosId = 1;/);
  assert.ok(restored.includes('ACME-ROBOTICS.COM'), 'upper-cased stand-in domain is restored');
  // What can't be mapped back is reported, so a tool call carrying it can be refused.
  const res = r.vault.residue(restored);
  assert.ok(res.includes(phone), 'phone stand-in written without separators');
  assert.ok(res.includes('RDX_SECRET_0123456789'), 'unknown token');
  // A longer real word that merely contains a stand-in is not residue.
  assert.deepEqual(r.vault.residue(`${l.toLowerCase()}ology and the ${f.toLowerCase()}ish era`), []);
});

test('restore: stand-ins inside identifiers come back at camelCase and underscore joints', async () => {
  const r = new Redactor({ detectors: [fake('masker', ['PERSON'], [['Maria Santos', 'PERSON', 0.95]]), fake('privacy-filter', ['PERSON'], [['Maria Santos', 'PERSON', 0.9]])], vault: new Vault() });
  const [f, l] = (await r.redact('x Maria Santos')).text.split(' ').slice(1) as [string, string];
  const lf = f.toLowerCase(); const ll = l.toLowerCase();
  const code = `const ${lf}${l}Id = 1; get${f}${l}(); ${lf}_${ll}_id; ${l.toUpperCase()}_TEAM`;
  assert.equal(r.restore(code), 'const mariaSantosId = 1; getMariaSantos(); maria_santos_id; SANTOS_TEAM');
  assert.deepEqual(r.vault.residue(r.restore(code)), []);
});

test('model-only secrets that are plain identifiers are kept', () => {
  const t = 'call mcp__agent-understudy__secret_request with OPENROUTER_API_KEY';
  const a = t.indexOf('mcp'); const ae = t.indexOf(' with'); const b = t.indexOf('OPENROUTER');
  const f = vote(t, [{ start: a, end: ae, label: 'SECRET', score: 0.9, detector: 'privacy-filter' },
    { start: b, end: t.length, label: 'SECRET', score: 0.9, detector: 'privacy-filter' }], []);
  assert.deepEqual(f.map((x) => [x.redact, x.suppressed]), [[false, 'identifier'], [false, 'identifier']]);
});

test('names: one confident model is enough; neighbours and hyphenated surnames join the name', async () => {
  // Only masker covers PERSON and it tagged just the surname.
  const r = new Redactor({ detectors: [fake('masker', ['PERSON'], [['Okonkwo-Hale', 'PERSON', 0.93]])], vault: new Vault() });
  const out = (await r.redact('Ask Priya Okonkwo-Hale about it.')).text;
  const m = /^Ask (\p{Lu}\p{L}+) (\p{Lu}\p{L}+)-(\p{Lu}\p{L}+) about it\.$/u.exec(out);
  assert.ok(m, out);
  assert.ok(!/\b(?:Priya|Okonkwo|Hale)\b/.test(out), out);
  assert.equal(r.restore(out), 'Ask Priya Okonkwo-Hale about it.');
});

test('outbound: real names written as identifiers become the same form of the stand-in', async () => {
  const r = new Redactor({ detectors: [fake('masker', ['PERSON'], [['Daniel Okafor', 'PERSON', 0.95]]), fake('privacy-filter', ['PERSON'], [['Daniel Okafor', 'PERSON', 0.9]])], vault: new Vault() });
  const [f, l] = (await r.redact('owner Daniel Okafor')).text.split(' ').slice(1) as [string, string];
  const lf = f.toLowerCase(); const ll = l.toLowerCase();
  // History the agent wrote after restore: real spellings in code. A detector-free redactor must still catch them.
  const bare = new Redactor({ detectors: [], vault: r.vault });
  const code = 'const danielOkaforId = 1; slug = "id-daniel-okafor"; handle = "dokafor"; // Signed: Okafor, Daniel; team okafor_team; and a park bench';
  const out = (await bare.redact(code)).text;
  assert.ok(!/daniel|okafor/i.test(out), out);
  assert.equal(out, `const ${lf}${l}Id = 1; slug = "id-${lf}-${ll}"; handle = "${lf[0]}${ll}"; // Signed: ${l}, ${f}; team ${ll}_team; and a park bench`);
  assert.equal(r.restore(out), code, 'round trip');
});

test('E2E regressions: phones before a period, Read line numbers, city/state/zip, phone label', async () => {
  const pf = (hits: Array<[string, Label, number]>) => fake('privacy-filter', ['PERSON', 'PHONE', 'ID', 'ADDRESS'], hits);
  // A model span that swallows the next Read line's number ("…4472\n  4") is cut at the line break.
  const text = '  3\tphone (650) 318-4472\n  4\tLives at 1847 Juniper Hollow Lane, Sunnyvale, CA 94087.\nCall (707) 461-8853.';
  const r = new Redactor({ detectors: [new PatternDetector(), pf([['(650) 318-4472\n  4', 'ID', 0.9]])], vault: new Vault() });
  const out = (await r.redact(text)).text;
  assert.match(out, /^ {2}3\tphone \(\d{3}\) 555-01\d\d\n {2}4\t/, out); // phone label (rule wins over the model's ID), line number intact
  assert.ok(!out.includes('461-8853') && !out.includes('Sunnyvale') && !out.includes('94087'), out);
  assert.match(out, /, CA \d{5}\./, 'state kept, zip replaced');
  assert.equal(r.restore(out), text);
});

test('E2E regressions: misreads do not spread; paths and env names are never rewritten', async () => {
  const v = new Vault();
  const det = fake('privacy-filter', ['PERSON'], [['Asking Claude', 'PERSON', 0.9], ['Claude Agent SDK', 'PERSON', 0.85], ['Maria Santos', 'PERSON', 0.95]]);
  const r = new Redactor({ detectors: [det], vault: v });
  const out = (await r.redact('| Asking Claude right inside a note |\nClaude Agent SDK by Maria Santos')).text;
  assert.ok(out.includes('Asking Claude') && out.includes('Claude Agent SDK'), out);
  assert.ok(!/\b(?:Maria|Santos)\b/.test(out), out);
  // Later text: the real name's words are sticky, but never inside paths or env-style names.
  const later = (await new Redactor({ detectors: [], vault: v }).redact('see ~/.claude/settings and /home/maria/santos.txt, $AGENT_SECRET_X, MARIA_SANTOS_ID; thanks Maria')).text;
  assert.ok(later.startsWith('see ~/.claude/settings and /home/maria/santos.txt, $AGENT_SECRET_X, MARIA_SANTOS_ID;'), later);
  assert.ok(!later.endsWith('thanks Maria'), later);
});

test('E2E regressions: a hyphenated surname alone gets the same stand-in as in the full name', async () => {
  const r = new Redactor({ detectors: [fake('privacy-filter', ['PERSON'], [['Priya Okonkwo-Hale', 'PERSON', 0.95], ['Okonkwo-Hale', 'PERSON', 0.9]])], vault: new Vault() });
  const full = (await r.redact('Owner: Priya Okonkwo-Hale')).text.slice('Owner: '.length);
  const surname = full.split(' ').slice(1).join(' ');
  assert.equal((await r.redact('Surname: Okonkwo-Hale.')).text, `Surname: ${surname}.`);
  const camel = (await r.redact('const priyaOkonkwoHaleId = 1')).text;
  assert.ok(!/okonkwo|HaleId|(?<![a-z])hale(?![a-z])/i.test(camel), camel); // whole words: a stand-in like "Haley" is fine
});

test('bench fixes: full addresses, dotted phones, escaped text, hex ids, doubtful findings do not spread, known handles', async () => {
  const masker = fake('masker', ['ADDRESS', 'PERSON', 'SECRET'], [['1847 Juniper Hollow', 'ADDRESS', 0.97], ['Sunnyvale', 'ADDRESS', 0.9], ['Claude Opus', 'PERSON', 0.85]]);
  const pf = fake('privacy-filter', ['SECRET', 'PHONE'], [['3f9a2c1d7e', 'SECRET', 0.9], ['650.724.1188', 'PHONE', 0.9]]);
  const v = new Vault();
  v.seedKnownNames(['jdoe42']);
  const r = new Redactor({ detectors: [new PatternDetector(), masker, pf], vault: v });
  const text = 'Lives at 1847 Juniper Hollow Lane, Sunnyvale, CA 94087. Cell 650.724.1188. commit 3f9a2c1d7e by jdoe42; "\\n@click.command(" Ask Claude Opus.';
  const out = (await r.redact(text)).text;
  for (const real of ['1847', 'Juniper', 'Hollow', 'Sunnyvale', '94087', '650.724.1188', 'jdoe42']) assert.ok(!out.includes(real), `${real} leaked: ${out}`);
  assert.ok(out.includes(', CA '), 'state code kept');
  assert.ok(out.includes('commit 3f9a2c1d7e'), 'a bare hex id is not a secret');
  assert.ok(out.includes('"\\n@click.command("'), 'escaped text is not an email');
  assert.match(out, /by [a-z0-9._-]+;/, 'handle becomes a username');
  assert.equal(r.restore(out), text.replace('Ask Claude Opus', 'Ask Claude Opus'));
  // "Claude Opus" (one model, 0.85, ordinary product words) is not spread to later text.
  const later = (await new Redactor({ detectors: [], vault: v }).redact('Claude Opus wrote it; ask jdoe42')).text;
  assert.ok(later.startsWith('Claude Opus wrote it;'), later);
  assert.ok(!later.includes('jdoe42'), 'known handles are always redacted');
});

test('model-only misreads in tool output are kept: ls listings, file sizes, languages, tool attrs; real logins are not', () => {
  const m = (id: string, hits: Array<[string, Label, number]>) => fake(id, ['PERSON', 'ADDRESS'], hits);
  const text = '-rw-r--r-- 1 root root 28191 Jun 29 20:09 agent.py\ndrwxr-xr-x 2 dana staff 640 Jun 29 20:09 notes\n' +
    "langs ['Russian', 'Ukrainian'] <tool_call name=bash> 48875 warnings; @author Dangelo Simonis; ping @Marcelle";
  const at = (s: string, from = 0) => text.indexOf(s, from);
  const spans: Span[] = [
    { start: at('root root'), end: at('root root') + 9, label: 'PERSON', score: 0.9, detector: 'privacy-filter' },
    { start: at('28191'), end: at('28191') + 5, label: 'ADDRESS', score: 0.95, detector: 'masker' },
    { start: at('agent.py'), end: at('agent.py') + 8, label: 'PERSON', score: 0.9, detector: 'privacy-filter' },
    { start: at('dana'), end: at('dana') + 4, label: 'PERSON', score: 0.9, detector: 'privacy-filter' },
    { start: at('Russian'), end: at('Russian') + 7, label: 'PERSON', score: 0.9, detector: 'privacy-filter' },
    { start: at('=bash'), end: at('=bash') + 5, label: 'PERSON', score: 0.9, detector: 'privacy-filter' },
    { start: at('48875'), end: at('48875') + 5, label: 'ADDRESS', score: 0.99, detector: 'masker' },
    { start: at('@author'), end: at('Simonis') + 7, label: 'PERSON', score: 0.95, detector: 'masker' },
    { start: at('@Marcelle'), end: at('@Marcelle') + 9, label: 'PERSON', score: 0.9, detector: 'privacy-filter' },
  ];
  const f = vote(text, spans, [m('masker', []), m('privacy-filter', [])]);
  const redacted = f.filter((x) => x.redact).map((x) => x.value);
  assert.deepEqual(redacted, ['dana', 'Dangelo Simonis', 'Marcelle']);
});

test('names and addresses can be turned off; knownNames still apply', async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { loadConfig } = await import('../src/config.ts');
  const home = mkdtempSync(path.join(tmpdir(), 'ar-cfg-'));
  writeFileSync(path.join(home, 'config.json'), JSON.stringify({ names: false, addresses: false }));
  const policy = loadConfig(home).resolvedPolicy;
  assert.ok(!policy.labels.includes('PERSON') && !policy.labels.includes('ADDRESS') && policy.labels.includes('EMAIL'));
  const text = 'Dana Whitfield lives at 1847 Juniper Hollow Lane; mail dana@corp-mail.net; I am jroe77';
  const at = (s: string) => text.indexOf(s);
  const spans: Span[] = [
    { start: at('Dana'), end: at('Dana') + 14, label: 'PERSON', score: 0.99, detector: 'masker' },
    { start: at('1847'), end: at('Lane') + 4, label: 'ADDRESS', score: 0.99, detector: 'masker' },
    { start: at('dana@'), end: at('.net') + 4, label: 'EMAIL', score: 1, detector: 'patterns' },
    { start: at('jroe77'), end: at('jroe77') + 6, label: 'PERSON', score: 1, detector: 'vault', source: 'known' },
  ];
  const f = vote(text, spans, [fake('masker', ['PERSON', 'ADDRESS'], []), fake('patterns', ['EMAIL'], []), fake('vault', [], [])], policy);
  assert.deepEqual(f.filter((x) => x.redact).map((x) => x.value), ['dana@corp-mail.net', 'jroe77']);
});
