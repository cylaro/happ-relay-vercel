/**
 * Pure relay logic — no Vercel-specific APIs, unit-testable in Node.
 * Shared by /api/relay and /api/health.
 */

const HWID_PATTERN = /^[A-Za-z0-9=-]{10,64}$/;

const err = (message, status = 400) => Object.assign(new Error(message), { status });

/** Check project configuration. Returns { ok, missing } without leaking values. */
export function validateRelayEnv(env) {
  const missing = [];
  if (!/^[A-Za-z0-9_-]{8,}$/.test(String(env?.SECRET_PREFIX || ''))) missing.push('SECRET_PREFIX (8+ chars: A-Z a-z 0-9 _ -)');
  if (!HWID_PATTERN.test(String(env?.HWID || ''))) missing.push('HWID (10-64 chars: A-Z a-z 0-9 = -)');
  if (!env?.USER_AGENT) missing.push('USER_AGENT');
  const base = String(env?.PANEL_BASE || '');
  if (base && !/^https:\/\/[a-z0-9.-]+(:\d+)?(\/[^\s]*)?$/i.test(base)) missing.push('PANEL_BASE (https URL of the panel subscription endpoint)');
  const hosts = String(env?.ALLOWED_HOSTS || '');
  if (hosts.split(',').some(h => h.trim() && !/^[a-z0-9.-]+$/i.test(h.trim()))) missing.push('ALLOWED_HOSTS (comma-separated hostnames)');
  return { ok: missing.length === 0, missing };
}

/** Identity headers presented to the panel. */
export function identityHeaders(env) {
  const headers = {
    'x-hwid': env.HWID,
    'user-agent': env.USER_AGENT,
  };
  if (env.DEVICE_OS) headers['x-device-os'] = env.DEVICE_OS;
  if (env.VER_OS) headers['x-ver-os'] = env.VER_OS;
  if (env.DEVICE_MODEL) headers['x-device-model'] = env.DEVICE_MODEL;
  return headers;
}

export function parseAllowedHosts(env) {
  return String(env?.ALLOWED_HOSTS || '')
    .split(',')
    .map(h => h.trim().toLowerCase())
    .filter(Boolean);
}

/** Empty ALLOWED_HOSTS means every https host is allowed. */
export function hostAllowed(env, hostname) {
  const hosts = parseAllowedHosts(env);
  if (hosts.length === 0) return true;
  const host = String(hostname || '').toLowerCase();
  return hosts.some(h => host === h || host.endsWith('.' + h));
}

/**
 * Resolve the request secret + token path to an upstream URL.
 *   token is a bare token        -> PANEL_BASE + '/' + token (if configured)
 *   token is a full https URL    -> used as-is (host must pass ALLOWED_HOSTS if set)
 * Wrong secret -> error with status 404 (does not reveal the relay exists).
 */
export function resolveTarget(env, secret, tokenPath) {
  const expected = String(env?.SECRET_PREFIX || '');
  if (!expected || secret !== expected) throw err('not found', 404);

  const raw = String(tokenPath || '').replace(/^\/+/, '');
  if (/^https?:\/\//i.test(raw)) {
    let url;
    try {
      url = new URL(raw);
    } catch {
      throw err('invalid target URL');
    }
    if (url.protocol !== 'https:') throw err('only https targets are allowed');
    if (!hostAllowed(env, url.hostname)) throw err('target host is not allowed', 403);
    return url.href;
  }

  if (!env?.PANEL_BASE) throw err('PANEL_BASE is not configured for bare tokens');
  const base = String(env.PANEL_BASE).replace(/\/+$/, '');
  const target = `${base}/${raw}`;
  try {
    const parsed = new URL(target);
    if (!hostAllowed(env, parsed.hostname)) throw err('target host is not allowed', 403);
  } catch (e) {
    if (e.status) throw e;
    throw err('invalid PANEL_BASE');
  }
  return target;
}
