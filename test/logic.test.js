import assert from 'node:assert/strict';
import test from 'node:test';

import { escapeHtml, flagImage, hostAllowed, identityHeaders, listServers, outboundToUri, parseSubscriptionUris, resolveTarget, uriName, validateRelayEnv } from '../api/logic.js';

const ENV = {
  SECRET_PREFIX: 'my-secret-1',
  HWID: 'UE42LJXu4DbiCaBv',
  USER_AGENT: 'Happ/1.16.0 (iOS 18.3; iPhone 14 Pro)',
  ALLOWED_HOSTS: '',
  DEVICE_OS: 'iOS',
  VER_OS: '18.3',
  DEVICE_MODEL: 'iPhone 14 Pro',
};

test('validateRelayEnv accepts a complete configuration', () => {
  assert.equal(validateRelayEnv(ENV).ok, true);
});

test('validateRelayEnv works without optional variables', () => {
  const { ALLOWED_HOSTS, DEVICE_OS, VER_OS, DEVICE_MODEL, ...requiredOnly } = ENV;
  assert.equal(validateRelayEnv(requiredOnly).ok, true);
});

test('validateRelayEnv reports invalid or missing required settings without leaking values', () => {
  const result = validateRelayEnv({ SECRET_PREFIX: 'x', HWID: 'short', USER_AGENT: '', ALLOWED_HOSTS: 'a.com, bad host' });
  assert.equal(result.ok, false);
  assert.equal(result.missing.length, 4);
  for (const entry of result.missing) assert.ok(!entry.includes('bad host'));
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

test('resolveTarget: full https URL is used as-is', () => {
  assert.equal(resolveTarget(ENV, 'my-secret-1', 'https://other.example.com/sub/t'), 'https://other.example.com/sub/t');
});

test('resolveTarget: collapsed and scheme-less URLs are normalized to https', () => {
  assert.equal(resolveTarget(ENV, 'my-secret-1', 'https:/other.example.com/sub/t'), 'https://other.example.com/sub/t');
  assert.equal(resolveTarget(ENV, 'my-secret-1', 'other.example.com/sub/t'), 'https://other.example.com/sub/t');
});

test('resolveTarget: bare tokens are rejected вЂ” a full panel URL is required', () => {
  assert.throws(() => resolveTarget(ENV, 'my-secret-1', 't'), /full https panel URL/);
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

test('resolveTarget: rejects credentials inside the target URL', () => {
  assert.throws(() => resolveTarget(ENV, 'my-secret-1', 'https://user:pass@panel.example.com/sub/t'), /credentials/);
});

test('resolveTarget: happ links get a clear hint', () => {
  assert.throws(() => resolveTarget(ENV, 'my-secret-1', 'happ://crypt5/xyz'), /decrypt it first/);
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

test('parseSubscriptionUris: plain text and base64 bodies', () => {
  const text = 'vless://a-uuid@host:443#Node1\nss://b#Node2\n\nnot-a-uri';
  assert.deepEqual(parseSubscriptionUris(text), ['vless://a-uuid@host:443#Node1', 'ss://b#Node2']);
  const encoded = Buffer.from('vless://a#One\nvless://b#Two', 'utf8').toString('base64');
  assert.deepEqual(parseSubscriptionUris(encoded), ['vless://a#One', 'vless://b#Two']);
});

const XRAY_CONFIG = JSON.stringify([
  {
    remarks: '🇵🇱 8 | Польша',
    outbounds: [
      {
        tag: 'proxy',
        protocol: 'vless',
        settings: { vnext: [{ address: 'pl11k.example.icu', port: 8825, users: [{ id: 'uuid-1', encryption: 'none', flow: 'xtls-rprx-vision' }] }] },
        streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: 'yahoo.com', fingerprint: 'chrome', publicKey: 'pbk-x', shortId: 'sid-x' } },
      },
      { tag: 'block', protocol: 'blackhole' },
      { tag: 'direct', protocol: 'freedom' },
    ],
  },
  {
    remarks: '🇩🇪 13 | Германия',
    outbounds: [
      {
        tag: 'proxy',
        protocol: 'hysteria',
        settings: { address: 'de4d.example.icu', port: 8825, version: 2 },
        streamSettings: { network: 'hysteria', hysteriaSettings: { version: 2, auth: 'auth-uuid' }, security: 'tls', tlsSettings: { serverName: 'de4d.example.icu' } },
      },
      { tag: 'direct', protocol: 'freedom' },
    ],
  },
]);

test('parseSubscriptionUris: Happ-style Xray config array -> one URI per element, named by remarks', () => {
  const uris = parseSubscriptionUris(XRAY_CONFIG);
  assert.equal(uris.length, 2);
  assert.match(uris[0], /^vless:\/\/uuid-1@pl11k\.example\.icu:8825\?/);
  assert.match(uris[0], /security=reality/);
  assert.match(uris[0], /sni=yahoo\.com/);
  assert.equal(uriName(uris[0]), '🇵🇱 8 | Польша');
  assert.equal(uriName(uris[1]), '🇩🇪 13 | Германия');
});

test('parseSubscriptionUris: loopback placeholder outbounds (127.0.0.1) are skipped', () => {
  const cfg = JSON.stringify([{
    remarks: 'x',
    outbounds: [
      { tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: '127.0.0.1', port: 5555, users: [{ id: 'u' }] }] } },
      { tag: 'proxy-2', protocol: 'vless', settings: { vnext: [{ address: 'real.example.com', port: 443, users: [{ id: 'u2' }] }] } },
    ],
  }]);
  const uris = parseSubscriptionUris(cfg);
  assert.equal(uris.length, 1);
  assert.match(uris[0], /real\.example\.com/);
});

const TRANSPORT_MATRIX = [
  ['ws',    { wsSettings: { path: '/wspath', headers: { Host: 'h.example.com' } } },          'type=ws&path=%2Fwspath&host=h.example.com'],
  ['grpc',  { grpcSettings: { serviceName: 'svc', authority: 'au', multiMode: true } },       'type=grpc&serviceName=svc&authority=au&mode=multi'],
  ['kcp',   { kcpSettings: { header: { type: 'dtls' }, seed: 's3cret', mtu: 1400, tti: 50 } }, 'type=kcp&headerType=dtls&seed=s3cret&mtu=1400&tti=50'],
  ['httpupgrade', { httpupgradeSettings: { path: '/hu', host: 'h.example.com' } },            'type=httpupgrade&path=%2Fhu&host=h.example.com'],
  ['xhttp', { xhttpSettings: { mode: 'auto', host: 'x.example.com', path: '/plxh' } },        'type=xhttp&path=%2Fplxh&host=x.example.com&mode=auto'],
  ['tcp',   { tcpSettings: { header: { type: 'http', request: { path: ['/p'], headers: { Host: 'h.example.com' } } } } }, 'type=tcp&headerType=http&path=%2Fp&host=h.example.com'],
];

test('streamParams: every Xray transport maps to its documented share-link parameters', () => {
  for (const [network, settings, expected] of TRANSPORT_MATRIX) {
    const uri = outboundToUri({
      protocol: 'vless',
      settings: { vnext: [{ address: 'h.example.com', port: 443, users: [{ id: 'u1', encryption: 'none' }] }] },
      streamSettings: { network, ...settings, security: 'tls', tlsSettings: { serverName: 'sni.example.com' } },
    });
    assert.ok(uri, network);
    const query = uri.slice(uri.indexOf('?'), uri.indexOf('#'));
    for (const pair of expected.split('&')) {
      assert.ok(query.includes(pair), `${network}: query "${query}" lacks "${pair}"`);
    }
    assert.ok(query.includes('security=tls'), `${network}: security=tls missing`);
    assert.ok(query.includes('sni=sni.example.com'), `${network}: sni missing`);
  }
});

test('outboundToUri: reality shortId array takes first value; IPv6 is bracketed; hysteria2 obfs from finalmask', () => {
  const v6 = outboundToUri({
    protocol: 'vless',
    settings: { vnext: [{ address: '2001:db8::1', port: 443, users: [{ id: 'u1', encryption: 'none' }] }] },
    streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: 'sni', shortIds: ['aa', 'bb'], publicKey: 'pbk', fingerprint: 'chrome', spiderX: '/' } },
  });
  assert.ok(v6.includes('@[2001:db8::1]:443'), v6);
  assert.ok(v6.includes('sid=aa'), v6);
  assert.ok(v6.includes('spx=%2F'), v6);

  const hy2 = outboundToUri({
    protocol: 'hysteria2',
    settings: { servers: [{ address: 'hy.example.com', port: 8443 }], password: 'pw' },
    streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 'hy.example.com' }, finalmask: { udp: [{ type: 'salamander', settings: { password: 'obfspw' } }] } },
  });
  assert.match(hy2, /^hysteria2:\/\/pw@hy\.example\.com:8443\?/);
  assert.ok(hy2.includes('obfs=salamander'));
  assert.ok(hy2.includes('obfs-password=obfspw'));
});

test('outboundToUri: vmess outbound becomes base64 JSON link; non-server outbound yields null', () => {
  const vmess = outboundToUri({
    protocol: 'vmess',
    settings: { vnext: [{ address: 'v.example.com', port: 443, users: [{ id: 'vm-id', alterId: 0 }] }] },
    streamSettings: { network: 'ws', security: 'tls', tlsSettings: { serverName: 'v.example.com' }, wsSettings: { path: '/ws' } },
  });
  assert.match(vmess, /^vmess:\/\//);
  const decoded = JSON.parse(Buffer.from(vmess.slice(8), 'base64').toString('utf8'));
  assert.equal(decoded.add, 'v.example.com');
  assert.equal(decoded.id, 'vm-id');
  assert.equal(decoded.net, 'ws');
  assert.equal(decoded.tls, 'tls');
  assert.equal(decoded.path, '/ws');
  assert.equal(outboundToUri({ protocol: 'freedom', settings: {} }), null);
  assert.equal(outboundToUri({ protocol: 'vless', settings: { vnext: [] } }), null);
});

test('uriName: decodes fragment, falls back to empty', () => {
  assert.equal(uriName('vless://a@h:443?x=1#%D0%9D%D0%BE%D0%B4%D0%B0%201'), 'Нода 1');
  assert.equal(uriName('vless://a@h:443'), '');
});

test('listServers: names, indexes and order preserved; default name when no fragment', () => {
  const servers = listServers('vless://a#Р¤СЂР°РЅРєС„СѓСЂС‚\nvless://b');
  assert.deepEqual(servers, [
    { index: 1, name: 'Р¤СЂР°РЅРєС„СѓСЂС‚', uri: 'vless://a#Р¤СЂР°РЅРєС„СѓСЂС‚' },
    { index: 2, name: 'Server 2', uri: 'vless://b' },
  ]);
});

test('escapeHtml escapes dangerous characters', () => {
  assert.equal(escapeHtml('<img src=x onerror="alert(1)">&\''), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&amp;&#39;');
});

test('flagImage: converts emoji flag to flagcdn URL; empty without flag', () => {
  assert.equal(flagImage('🇵🇱 9 | Польша'), 'https://flagcdn.com/w40/pl.png');
  assert.equal(flagImage('🇦🇹 13 РђРІСЃС‚СЂРёСЏ'), 'https://flagcdn.com/w40/at.png');
  assert.equal(flagImage('Р‘РµР· С„Р»Р°РіР°'), '');
});

test('parseSubscriptionUris: JSON entries with identical endpoints are NOT deduplicated (each remark = one server)', () => {
  const cfg = JSON.stringify([
    {
      remarks: '🇷🇺 1 | Р‘РµР»С‹Рµ СЃРїРёСЃРєРё',
      outbounds: [{ tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'same.example.com', port: 443, users: [{ id: 'u' }] }] } }],
    },
    {
      remarks: '🇷🇺 2 | Р‘РµР»С‹Рµ СЃРїРёСЃРєРё',
      outbounds: [{ tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'same.example.com', port: 443, users: [{ id: 'u' }] }] } }],
    },
  ]);
  const uris = parseSubscriptionUris(cfg);
  assert.equal(uris.length, 2);
  assert.equal(uriName(uris[0]), '🇷🇺 1 | Р‘РµР»С‹Рµ СЃРїРёСЃРєРё');
  assert.equal(uriName(uris[1]), '🇷🇺 2 | Р‘РµР»С‹Рµ СЃРїРёСЃРєРё');
});

test('parseSubscriptionUris: plain text duplicates are still collapsed', () => {
  assert.deepEqual(parseSubscriptionUris('vless://a#One\nvless://a#One'), ['vless://a#One']);
});
