// functions/_middleware.js
import { sha256Hex, extractSessionCookie } from './api/_utils';

const BOT_PATTERNS = [
  { name: 'ClaudeBot', regex: /ClaudeBot/i },
  { name: 'anthropic-ai', regex: /anthropic-ai/i },
  { name: 'GPTBot', regex: /GPTBot/i },
  { name: 'ChatGPT-User', regex: /ChatGPT-User/i },
  { name: 'OAI-SearchBot', regex: /OAI-SearchBot/i },
  { name: 'PerplexityBot', regex: /PerplexityBot/i },
  { name: 'Perplexity-User', regex: /Perplexity-User/i },
  { name: 'Grok', regex: /Grok|xAI/i },
  { name: 'Google-Extended', regex: /Google-Extended/i },
  { name: 'Googlebot', regex: /Googlebot/i },
  { name: 'Bingbot', regex: /bingbot/i },
  { name: 'DuckDuckBot', regex: /DuckDuckBot/i },
  { name: 'Applebot', regex: /Applebot/i },
  { name: 'Bytespider', regex: /Bytespider/i },
  { name: 'YandexBot', regex: /YandexBot/i },
  { name: 'FacebookBot', regex: /facebookexternalhit|Meta-ExternalAgent/i },
  { name: 'CCBot', regex: /CCBot/i },
  { name: 'KimiBot', regex: /KimiBot/i },
  { name: 'Kimi-SearchBot', regex: /Kimi-SearchBot/i },
  { name: 'Kimi-User', regex: /Kimi-User/i },
  { name: 'MistralAI-User', regex: /MistralAI-User/i },
  { name: 'Diffbot', regex: /Diffbot/i },
  { name: 'AhrefsBot', regex: /AhrefsBot/i },
  { name: 'SemrushBot', regex: /SemrushBot/i },
  { name: 'MJ12bot', regex: /MJ12bot/i },
];

// Fallback: UA looks bot-like but matched no known name above.
const GENERIC_BOT_HINT = /bot|spider|crawl|slurp|fetch|scrape|http[-_]?client|curl|wget|python-requests|scrapy/i;

function classifyBot(ua) {
  if (!ua || typeof ua !== 'string') return 'Unidentified Bot';
  for (const b of BOT_PATTERNS) if (b.regex.test(ua)) return b.name;
  if (GENERIC_BOT_HINT.test(ua)) return 'Unidentified Bot';
  return 'Human';
}

function classifyEndpoint(p) {
  if (p === '/llms.txt') return 'llms-txt';
  if (p.startsWith('/raw/')) return 'raw-content';
  if (p.startsWith('/api/')) return 'api';
  return 'frontend';
}

const toNum = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };

function ipToBigInt(ip) {
  if (ip.includes(':')) {
    let [head, tail] = ip.split('::');
    let headParts = head ? head.split(':') : [];
    let tailParts = tail ? tail.split(':') : [];
    const missing = 8 - headParts.length - tailParts.length;
    const parts = [...headParts, ...Array(missing >= 0 ? missing : 0).fill('0'), ...tailParts];
    if (parts.length !== 8) return null;
    let val = 0n;
    for (const p of parts) val = (val << 16n) | BigInt(parseInt(p || '0', 16));
    return val;
  }
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => Number.isNaN(p) || p < 0 || p > 255)) return null;
  return parts.reduce((acc, p) => (acc << 8n) | BigInt(p), 0n);
}

function ipInCidr(ip, cidr) {
  const [range, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const ipVal = ipToBigInt(ip);
  const rangeVal = ipToBigInt(range);
  if (ipVal === null || rangeVal === null) return false;
  const isV6 = ip.includes(':');
  const totalBits = isV6 ? 128n : 32n;
  if (BigInt(bits) > totalBits) return false;
  const shift = totalBits - BigInt(bits);
  const mask = shift === totalBits ? 0n : (((1n << BigInt(bits)) - 1n) << shift);
  return (ipVal & mask) === (rangeVal & mask);
}

let RANGES_CACHE = null;
let RANGES_CACHE_AT = 0;
const RANGES_TTL_MS = 10 * 60 * 1000;

async function getBotRanges(env) {
  const now = Date.now();
  if (RANGES_CACHE && (now - RANGES_CACHE_AT) < RANGES_TTL_MS) return RANGES_CACHE;
  const { results } = await env.DB.prepare('SELECT bot_name, cidr FROM bot_asn_ranges').all();
  const map = new Map();
  for (const row of results || []) {
    if (!map.has(row.bot_name)) map.set(row.bot_name, []);
    map.get(row.bot_name).push(row.cidr);
  }
  RANGES_CACHE = map;
  RANGES_CACHE_AT = now;
  return map;
}

async function identity(request) {
  const rawIp = request.headers.get('CF-Connecting-IP') || '';
  const rawUa = request.headers.get('User-Agent') || '';
  const botCategory = classifyBot(rawUa);
  const timeBucket = Math.floor(Date.now() / 1800000);
  const sessionHash = (await sha256Hex(`${rawIp}-${botCategory}-${timeBucket}`)).slice(0, 16);
  return { rawUa, botCategory, sessionHash };
}

async function writeTelemetry(context, response, ttfb, statusOverride, bytesPromise, id) {
  const { request, env } = context;
  const url = new URL(request.url);
  const cf = request.cf || {};
  const h = request.headers;

  let respBytes = 0;
  if (bytesPromise) {
    respBytes = await bytesPromise.catch(() => 0);
  } else if (response) {
    respBytes = parseInt(response.headers.get('content-length') || '0', 10) || 0;
  }

  let botVerified = 0;
  if (id.botCategory !== 'Human' && id.botCategory !== 'Unidentified Bot') {
    try {
      const ranges = await getBotRanges(env);
      const cidrs = ranges.get(id.botCategory) || [];
      const clientIp = h.get('CF-Connecting-IP') || '';
      if (clientIp && cidrs.some(c => ipInCidr(clientIp, c))) botVerified = 1;
    } catch (e) { /* non-fatal */ }
  }

  await env.DB.prepare(
    `INSERT INTO request_events
     (ts, country, region, city, asn, as_org, path, method, query_string, endpoint_group,
      status, resp_bytes, cache_status, ttfb_ms, bot_category, session_hash, http_ver, tls_ver, sec_fetch_site,
      colo, timezone, continent, latitude, longitude, tcp_rtt,
      user_agent, ua_hints, accept_language, accept_encoding, referer,
      sec_fetch_mode, sec_fetch_dest, resp_content_type, bot_verified)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?,
             ?, ?, ?, ?)`
  ).bind(
    new Date().toISOString(), cf.country || 'Unknown', cf.region || 'Unknown', cf.city || 'Unknown',
    cf.asn || 0, cf.asOrganization || 'Unknown', url.pathname, request.method, url.search || null,
    classifyEndpoint(url.pathname), statusOverride ?? response?.status ?? 0, respBytes,
    response?.headers.get('cf-cache-status') || 'BYPASS', ttfb, id.botCategory, id.sessionHash,
    cf.httpProtocol || 'Unknown', cf.tlsVersion || 'Unknown', h.get('sec-fetch-site') || null,
    cf.colo || null, cf.timezone || null, cf.continent || null, toNum(cf.latitude), toNum(cf.longitude),
    toNum(cf.clientTcpRtt), id.rawUa || null, h.get('sec-ch-ua') || null, h.get('accept-language') || null,
    h.get('accept-encoding') || null, h.get('referer') || null, h.get('sec-fetch-mode') || null,
    h.get('sec-fetch-dest') || null, response?.headers.get('content-type') || null, botVerified
  ).run();
}

async function logFailedPath(env, request, url, status, rawUa) {
  let safePath = url.pathname;
  if (url.search) {
    safePath += url.search.replace(/([?&])(email|token|password|key|secret|api_key)=([^&]*)/gi, '$1$2=[REDACTED]');
  }
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const recentFail = await env.DB.prepare(
    'SELECT 1 FROM failed_path_alerts WHERE path = ? AND status = ? AND created_at > ? LIMIT 1'
  ).bind(safePath, status, oneHourAgo).first();
  if (!recentFail) {
    await env.DB.prepare(
      'INSERT INTO failed_path_alerts (path, status, request_id, user_agent, referrer) VALUES (?, ?, ?, ?, ?)'
    ).bind(safePath, status, request.headers.get('cf-ray') || null, rawUa, request.headers.get('referer') || null).run();
  }
}

export async function onRequest(context) {
  const { request, env, waitUntil } = context;
  const url = new URL(request.url);

  if (url.pathname.startsWith('/api/')) {
    const token = extractSessionCookie(request);
    if (token) {
      try {
        const tokenHash = await sha256Hex(token);
        const now = new Date().toISOString();
        const row = await env.DB.prepare(
          `SELECT u.id, u.email, u.role FROM sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > ?`
        ).bind(tokenHash, now).first();
        if (row) {
          context.data = context.data || {};
          context.data.user = { id: row.id, email: row.email, role: row.role };
        }
      } catch (e) { /* non-fatal */ }
    }
  }

  const startMs = Date.now();
  let response;
  try {
    response = await context.next();
  } catch (err) {
    console.error('context.next() failed:', err);
    waitUntil((async () => {
      try {
        const id = await identity(request);
        await writeTelemetry(context, null, Date.now() - startMs, 500, null, id);
        await logFailedPath(env, request, url, 500, id.rawUa);
      } catch (e) { console.error('Telemetry/Fail log write failed:', e); }
    })());
    return new Response('Internal Server Error', {
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff' },
    });
  }

  const ttfb = Date.now() - startMs;
  const id = await identity(request);

  let bodyOut = response.body;
  let bytesPromise = null;
  const body = response.body;
  if (body && typeof body.pipeTo === 'function' && !body.locked) {
    let counted = 0;
    let resolveCount = () => {};
    bytesPromise = new Promise(r => { resolveCount = r; });
    const { readable, writable } = new TransformStream({
      transform(chunk, c) { counted += chunk?.byteLength ?? 0; c.enqueue(chunk); },
      flush() { resolveCount(counted); },
    });
    body.pipeTo(writable).catch(() => resolveCount(counted));
    bodyOut = readable;
  }

  waitUntil((async () => {
    try {
      await writeTelemetry(context, response, ttfb, null, bytesPromise, id);
      if (response.status >= 400) {
        await logFailedPath(env, request, url, response.status, id.rawUa);
      }
    } catch (e) {
      console.error('Telemetry/Fail log write failed:', e);
    }
  })());

  const newHeaders = new Headers(response.headers);
  newHeaders.set('X-Content-Type-Options', 'nosniff');
  newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  if ((response.headers.get('content-type') || '').includes('text/html')) {
    newHeaders.append('Set-Cookie', `rum_session=${id.sessionHash}; Path=/; SameSite=Strict; Max-Age=1800`);
  }

  return new Response(bodyOut, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}
