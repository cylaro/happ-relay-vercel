/**
 * Pure relay logic — no Vercel-specific APIs, unit-testable in Node.
 * Shared by /api/relay and /api/health.
 */

const HWID_PATTERN = /^[A-Za-z0-9=-]{10,64}$/;

const err = (message, status = 400) => Object.assign(new Error(message), { status });

/** Length-safe constant-time string comparison (length itself is public — it is in the URL). */
export function safeEqual(a, b) {
  const A = new TextEncoder().encode(String(a));
  const B = new TextEncoder().encode(String(b));
  if (A.length !== B.length) return false;
  let diff = 0;
  for (let i = 0; i < A.length; i++) diff |= A[i] ^ B[i];
  return diff === 0;
}

/** Check project configuration. Returns { ok, missing } without leaking values. */
export function validateRelayEnv(env) {
  const missing = [];
  if (!/^[A-Za-z0-9_-]{8,}$/.test(String(env?.SECRET_PREFIX || ''))) missing.push('SECRET_PREFIX (8+ chars: A-Z a-z 0-9 _ -)');
  if (!HWID_PATTERN.test(String(env?.HWID || ''))) missing.push('HWID (10-64 chars: A-Z a-z 0-9 = -)');
  if (!env?.USER_AGENT) missing.push('USER_AGENT');
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
 * Resolve the request secret + target URL to an upstream URL.
 *   secret must equal SECRET_PREFIX (mismatch -> 404, does not reveal the relay exists)
 *   tokenPath must point to the panel subscription endpoint:
 *     full https URL (single or doubled slashes are tolerated)
 *     or scheme-less host/path (https:// is assumed)
 *   host must pass ALLOWED_HOSTS if the allowlist is set
 */
export function resolveTarget(env, secret, tokenPath) {
  const expected = String(env?.SECRET_PREFIX || '');
  if (!expected || !safeEqual(secret, expected)) throw err('not found', 404);

  let raw = String(tokenPath || '').trim().replace(/^\/+/, '');
  // Apps and CDNs sometimes collapse "https://" into "https:/": restore it.
  raw = raw.replace(/^(https?):\/{1,}/i, '$1://');
  if (/^happ:\/\//i.test(raw)) throw err('this is an encrypted happ link — decrypt it first with happ-decryptor');
  if (!/^https:\/\//i.test(raw)) {
    // Scheme-less host/path: assume https.
    if (/^[a-z0-9.-]+\.[a-z]{2,}([/?#]|$)/i.test(raw)) raw = 'https://' + raw;
    else throw err('token must be a full https panel URL');
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw err('invalid target URL');
  }
  if (url.protocol !== 'https:') throw err('only https targets are allowed');
  if (url.username || url.password) throw err('credentials in target URL are not allowed');
  if (!hostAllowed(env, url.hostname)) throw err('target host is not allowed', 403);
  return url.href;
}

const URI_LINE_RE = /^(?:vless|vmess|ss|socks|trojan|hysteria2|hy2):\/\//i;

/** Decode a base64 subscription body if it does not already look like plain URIs. */
function decodeIfBase64(text) {
  if (URI_LINE_RE.test(text)) return text;
  try {
    return Buffer.from(text.replace(/\s+/g, ''), 'base64').toString('utf-8');
  } catch {
    return text;
  }
}

/**
 * Extract proxy URIs (vless://, vmess://, ss://, …) from a subscription body:
 * plain text, base64 text, or a mix of both. Order is preserved.
 */
export function parseSubscriptionUris(text) {
  const body = decodeIfBase64(String(text || '').trim());
  if (!body) return [];
  return body.split(/\r?\n/).map(l => l.trim()).filter(URI_LINE_RE.test.bind(URI_LINE_RE));
}

/** Human-readable name from a proxy URI fragment (#Node), decoded and sanitized. */
export function uriName(uri) {
  const m = String(uri).match(/#([^#?]*)$/);
  if (!m) return '';
  try {
    return decodeURIComponent(m[1]).replace(/[\r\n\t<>&"]/g, ' ').trim();
  } catch {
    return m[1].replace(/[\r\n\t<>&"]/g, ' ').trim();
  }
}

/** Escape a string for safe interpolation into HTML text/attributes. */
export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/** One entry per server: index (1-based), display name, proxy URI. */
export function listServers(text) {
  return parseSubscriptionUris(text).map((uri, i) => ({
    index: i + 1,
    name: uriName(uri) || `Server ${i + 1}`,
    uri,
  }));
}

/** Minimal HTML page listing every server with its name and copyable link. */
export function serversHtml(servers) {
  const cards = servers.map(s => `
  <section class="card">
    <h2>${escapeHtml(s.index)}. ${escapeHtml(s.name)}</h2>
    <code>${escapeHtml(s.uri)}</code>
    <div class="actions">
      <a href="${escapeHtml(s.uri)}">Подключить</a>
      <a href="${escapeHtml(s.uri)}" class="copy" data-uri="${escapeHtml(s.uri)}">Копировать</a>
    </div>
  </section>`).join('\n');
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Серверы подписки (${servers.length})</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; background: #12161d; color: #dde3ea; margin: 0 auto; padding: 1rem; max-width: 46rem; }
  h1 { font-size: 1.2rem; }
  .card { background: #1a2028; border: 1px solid #2a3340; border-radius: 10px; padding: 0.9rem 1rem; margin: 0.8rem 0; }
  h2 { font-size: 1rem; margin: 0 0 0.6rem; word-break: break-word; }
  code { display: block; font-size: 0.78rem; color: #9fb0c3; background: #12161d; border-radius: 6px; padding: 0.6rem; overflow-wrap: anywhere; }
  .actions { display: flex; gap: 0.8rem; margin-top: 0.6rem; }
  a { color: #6db3f2; }
  a.copy { cursor: pointer; }
</style>
</head>
<body>
<h1>Серверы подписки (${servers.length})</h1>
${cards}
<script>
document.querySelectorAll('a.copy').forEach(a => a.addEventListener('click', e => {
  e.preventDefault();
  navigator.clipboard.writeText(a.dataset.uri).then(() => {
    const t = a.textContent; a.textContent = 'Скопировано';
    setTimeout(() => { a.textContent = t; }, 1200);
  });
}));
</script>
</body>
</html>`;
}
