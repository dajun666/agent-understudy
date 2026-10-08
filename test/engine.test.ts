// No daemon: one engine per agent session, sharing the vault and credentials through files.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../src/config.ts';
import { Vault } from '../src/core/vault.ts';
import { apiToken } from '../src/core/api-token.ts';
import { startEngine } from '../src/engine.ts';

process.env.AGENT_UNDERSTUDY_CREDENTIALS_KEY = randomBytes(32).toString('hex'); // never touch the real keychain in tests

const home = () => {
  const h = mkdtempSync(path.join(os.tmpdir(), 'ar-engine-'));
  writeFileSync(path.join(h, 'config.json'), JSON.stringify({ models: [] }));
  return h;
};

test('two vaults on one file: a stand-in issued in one session restores in the other, with the same spelling', () => {
  const h = home();
  const a = new Vault(h);
  const b = new Vault(h);
  const p = a.placeholder('Dana Whitfield', 'PERSON');
  assert.equal(b.restore(`ping ${p} today`), 'ping Dana Whitfield today');
  // b issues the same stand-in for the same value instead of minting another.
  assert.equal(b.placeholder('Dana Whitfield', 'PERSON'), p);
  const q = b.placeholder('dana.whitfield@fastmail.com', 'EMAIL');
  assert.equal(a.restore(q), 'dana.whitfield@fastmail.com');
  // A third session starting later loads all of it.
  assert.equal(new Vault(h).restore(`${p} <${q}>`), 'Dana Whitfield <dana.whitfield@fastmail.com>');
});

test('engines: each on its own port; a credential stored through one is redacted by the other', async () => {
  const h = home();
  const config = loadConfig(h);
  const [one, two] = await Promise.all([startEngine({ config }), startEngine({ config })]);
  try {
    assert.notEqual(one.port, two.port);
    const auth = { 'content-type': 'application/json', authorization: `Bearer ${apiToken(h)}` };
    const post = (e: { url: string }, route: string, body: unknown) =>
      fetch(e.url + route, { method: 'POST', headers: auth, body: JSON.stringify(body) }).then((r) => r.json() as Promise<any>);
    const value = 'sk-test-' + randomBytes(16).toString('hex');
    await post(one, '/api/secret/put', { cwd: h, name: 'SERVICE_KEY', value, scope: 'project' });
    const r = await post(two, '/api/redact-json', { value: `export SERVICE_KEY=${value}`, protocol: 'raw' });
    assert.equal(r.value, 'export SERVICE_KEY=Hide(SERVICE_KEY)');
    // A session-only value is known to the other engine by fingerprint, never by value.
    const session = 'tok-' + randomBytes(12).toString('hex');
    await post(one, '/api/secret/put', { cwd: h, name: 'SESSION_TOKEN', value: session, scope: 'session' });
    const s = await post(two, '/api/scrub', { value: `echo ${session}` });
    assert.equal(s.value, 'echo Hide(SESSION_TOKEN)');
    // Names on one engine restore on the other.
    const red = await post(one, '/api/redact-json', { value: 'mail dana.whitfield@fastmail.com', protocol: 'raw' });
    assert.ok(!red.value.includes('dana.whitfield@fastmail.com'));
    assert.equal((await post(two, '/api/restore', { text: red.value })).text, 'mail dana.whitfield@fastmail.com');
  } finally {
    await Promise.all([one.close(), two.close()]);
  }
});
