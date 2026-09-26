import assert from 'node:assert/strict';
import test from 'node:test';

import { hostAllowed, identityHeaders, resolveTarget, validateRelayEnv } from '../api/logic.js';

const ENV = {
  SECRET_PREFIX: 'my-secret-1',
  HWID: 'UE42LJXu4DbiCaBv',
  USER_AGENT: 'Happ/1.16.0 (iOS 18.3; iPhone 14 Pro)',
  PANEL_BASE: 'https://panel.example.com/sub',
  DEVICE_OS: 'iOS',
  VER_OS: '18.3',
  DEVICE_MODEL: 'iPhone 14 Pro',
};

test('validateRelayEnv accepts a complete configuration', () => {
  assert.equal(validateRelayEnv(ENV).ok, true);
});

test('validateRelayEnv reports invalid or missing settings without leaking values', () => {
  const result = validateRelayEnv({ SECRET_PREFIX: 'x', HWID: 'short', USER_AGENT: '', PANEL_BASE: 'http://insecure' });
  assert.equal(result.ok, false);
  assert.equal(result.missing.length, 4);
  for (const entry of result.missing) assert.ok(!entry.includes('insecure'));
});

test('validateRelayEnv: PANEL_BASE is optional, ALLOWED_HOSTS entries are validated', () => {
  const { PANEL_BASE, ...withoutBase } = ENV;
  assert.equal(validateRelayEnv(withoutBase).ok, true);
  assert.equal(validateRelayEnv({ ...ENV, ALLOWED_HOSTS: 'a.com,sub.b.com' }).ok, true);
  assert.equal(validateRelayEnv({ ...ENV, ALLOWED_HOSTS: 'a.com, bad host' }).ok, false);
});

test('wrong secret resolves to 404 and does not reveal the relay', () => {
  assert.throws(() => resolveTarget(ENV, 'wrong-secret', 'https://panel.example.com/sub/t'), e => e.status === 404);
});

test('identityHeaders always sends x-hwid and user-agent, optional fields only when set', () => {
  const full = identityHeaders(ENV);
  assert.equal(full['x-hwid'], 'UE42LJXu4DbiCaBv');
  assert.equal(full['x-device-os'], 'iOS');
  const { DEVICE_OS, VER_OS, DEVICE_MODEL, ...minimalEnv } = ENV;
  const minimal = identityHeaders(minimalEnv);
  assert.deepEqual(Object.keys(minimal).sort(), ['user-agent', 'x-hwid']);
});

test('resolveTarget: bare token joins PANEL_BASE, full https URL is used as-is', () => {
  assert.equal(resolveTarget(ENV, 'my-secret-1', 'token-uuid'), 'https://panel.example.com/sub/token-uuid');
  assert.equal(resolveTarget(ENV, 'my-secret-1', 'https://other.example.com/sub/t'), 'https://other.example.com/sub/t');
});

test('resolveTarget: rejects http targets and disallowed hosts', () => {
  const strict = { ...ENV, ALLOWED_HOSTS: 'panel.example.com' };
  assert.throws(() => resolveTarget(strict, 'my-secret-1', 'http://other.example.com/sub/t'), /https/i);
  assert.throws(() => resolveTarget(strict, 'my-secret-1', 'https://evil.example.com/sub/t'), /not allowed/);
  assert.equal(
    resolveTarget(strict, 'my-secret-1', 'https://sub.panel.example.com/sub/t'),
    'https://sub.panel.example.com/sub/t',
  );
});

test('resolveTarget: relative tokens require PANEL_BASE', () => {
  const { PANEL_BASE, ...withoutBase } = ENV;
  assert.throws(() => resolveTarget(withoutBase, 'my-secret-1', 'token'), /PANEL_BASE/);
});

test('hostAllowed: empty allowlist permits everything; subdomains match their root', () => {
  const open = { ALLOWED_HOSTS: '' };
  assert.equal(hostAllowed(open, 'anything.tld'), true);
  const limited = { ALLOWED_HOSTS: 'panel.example.com' };
  assert.equal(hostAllowed(limited, 'panel.example.com'), true);
  assert.equal(hostAllowed(limited, 'sub.panel.example.com'), true);
  assert.equal(hostAllowed(limited, 'example.com'), false);
  assert.equal(hostAllowed(limited, 'evil-panel.example.com'), false);
});
