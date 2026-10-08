import { test } from 'node:test';
import assert from 'node:assert/strict';
import { configPatch, hostSteps, identityCandidates, recommendedPreset } from '../src/setup.ts';

test('setup recommends models by RAM, and none when names and addresses are off', () => {
  assert.equal(recommendedPreset(16, true, true), 'pair');
  assert.equal(recommendedPreset(12, true, false), 'privacy-filter');
  assert.equal(recommendedPreset(8, false, true), 'masker');
  assert.equal(recommendedPreset(64, false, false), 'none');
});

test('setup config patch: stand-in style applies to personal data only, secrets keep their choice', () => {
  const base = { names: true, addresses: false, models: ['masker'], knownNames: ['Jane Roe', 'Jane Roe', 'jroe42'] };
  const numbered = configPatch({ ...base, style: 'numbered' }, { placeholders: { SECRET: 'token', URL: 'numbered' } });
  assert.deepEqual(numbered.knownNames, ['Jane Roe', 'jroe42']);
  assert.equal((numbered.placeholders as any).PERSON, 'numbered');
  assert.equal((numbered.placeholders as any).SECRET, 'token');
  const back = configPatch({ ...base, style: 'surrogate' }, { placeholders: numbered.placeholders as any });
  assert.deepEqual(back.placeholders, { SECRET: 'token', URL: 'numbered' });
  assert.equal(back.addresses, false);
});

test('setup host steps point at this checkout; nothing needs a running gateway', () => {
  assert.match(hostSteps('claude'), /\/plugin install agent-understudy@agent-understudy/);
  assert.match(hostSteps('codex'), /understudy run codex/);
  assert.match(hostSteps('opencode'), /hooks\/opencode\/agent-understudy\.ts/);
  for (const c of identityCandidates()) assert.ok(c.value.length >= 2 && c.from);
});
