import { identityHeaders, resolveTarget, validateRelayEnv } from './logic.js';

const PASS_HEADERS = [
  'content-type',
  'subscription-userinfo',
  'profile-title',
  'profile-update-interval',
  'profile-web-page-url',
  'support-url',
  'x-hwid-active',
  'x-hwid-not-supported',
  'x-hwid-max-devices-reached',
  'x-hwid-limit',
];

export default async function handler(req, res) {
  const env = process.env;
  const { ok, missing } = validateRelayEnv(env);
  if (!ok) {
    res.status(500).send(`Configuration error: missing ${missing[0]}`);
    return;
  }

  let target;
  try {
    target = resolveTarget(env, String(req.query.secret || ''), String(req.query.token || ''));
  } catch (e) {
    res.status(e.status || 400).send(e.message);
    return;
  }

  try {
    const upstream = await fetch(target, { headers: identityHeaders(env), redirect: 'follow' });
    res.status(upstream.status);
    res.setHeader('cache-control', 'no-store');
    for (const name of PASS_HEADERS) {
      const value = upstream.headers.get(name);
      if (value) res.setHeader(name, value);
    }
    res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch {
    res.status(502).send('upstream error');
  }
}
