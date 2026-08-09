// functions/_middleware.js
import { sha256Hex, extractSessionCookie } from './api/_utils';

const BOT_PATTERNS = [
  { name: 'ClaudeBot', regex: /ClaudeBot/i },
  { name: 'GPTBot', regex: /GPTBot/i },
  { name: 'PerplexityBot', regex: /PerplexityBot/i },
  { name: 'Bytespider', regex: /Bytespider/i },
  { name: 'Applebot', regex: /Applebot/i },
  { name: 'Googlebot', regex: /Googlebot/i },
  { name: 'OAI-SearchBot', regex: /OAI-SearchBot/i },
  { name: 'Meta-ExternalAgent', regex: /Meta-ExternalAgent/i },
];

function classifyBot(ua) {
  if (!ua || typeof ua !== 'string') return 'Human';
  for (const b of BOT_PATTERNS) if (b.regex.test(ua)) return b.name;
  return 'Human';
}

function classifyEndpoint(p) {
  if (p === '/llms.txt') return 'llms-txt';
  if (p.startsWith('/raw/')) return 'raw-content';
  if (p.startsWith('/api/')) return 'api';
  return 'frontend';
}

const toNum = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };

async function identity(request) {
  const rawIp = request.headers.get('CF-Connecting-IP') || '';
  const rawUa = request.headers.get('User-Agent') || '';
  const botCategory = classifyBot(rawUa);
  const timeBucket = Math.floor(Date.now() / 1800000); // 30-min rotation
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
  if (id.botCategory !== 'Human') {
    try {
      const reg = await env.DB.prepare(
        'SELECT expected_asn FROM bot_asn_registry WHERE bot_name = ? AND verified = 1'
      ).bind(id.botCategory).first();
      if (reg && Number(reg.expected_asn) === Number(cf.asn)) botVerified = 1;
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
    new Date().toISOString(),                             // 1  ts
    cf.country || 'Unknown',                              // 2  country
    cf.region || 'Unknown',                               // 3  region
    cf.city || 'Unknown',                                 // 4  city
    cf.asn || 0,                                          // 5  asn
    cf.asOrganization || 'Unknown',                       // 6  as_org
    url.pathname,                                         // 7  path
    request.method,                                       // 8  method
    url.search || null,                                   // 9  query_string
    classifyEndpoint(url.pathname),                       // 10 endpoint_group
    statusOverride ?? response?.status ?? 0,              // 11 status
    respBytes,                                            // 12 resp_bytes
    response?.headers.get('cf-cache-status') || 'BYPASS', // 13 cache_status
    ttfb,                                                 // 14 ttfb_ms
    id.botCategory,                                       // 15 bot_category
    id.sessionHash,                                       // 16 session_hash
    cf.httpProtocol || 'Unknown',                         // 17 http_ver
    cf.tlsVersion || 'Unknown',                           // 18 tls_ver
    h.get('sec-fetch-site') || null,                      // 19 sec_fetch_site
    cf.colo || null,                                      // 20 colo
    cf.timezone || null,                                  // 21 timezone
    cf.continent || null,                                 // 22 continent
    toNum(cf.latitude),                                   // 23 latitude
    toNum(cf.longitude),                                  // 24 longitude
    toNum(cf.clientTcpRtt),                               // 25 tcp_rtt
    id.rawUa || null,                                     // 26 user_agent
    h.get('sec-ch-ua') || null,                           // 27 ua_hints
    h.get('accept-language') || null,                     // 28 accept_language
    h.get('accept-encoding') || null,                     // 29 accept_encoding
    h.get('referer') || null,                             // 30 referer
    h.get('sec-fetch-mode') || null,                      // 31 sec_fetch_mode
    h.get('sec-fetch-dest') || null,                      // 32 sec_fetch_dest
    response?.headers.get('content-type') || null,        // 33 resp_content_type
    botVerified                                           // 34 bot_verified
  ).run();
}

async function logFailedPath(env, request, url, status, rawUa) {
  let safePath = url.pathname;
  if (url.search) {
    // Redact PII from query strings
    safePath += url.search.replace(/([?&])(email|token|password|key|secret|api_key)=([^&]*)/gi, '$1$2=[REDACTED]');
  }
  
  // Deduplicate: only log the first failure for this path+status in the last hour
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const recentFail = await env.DB.prepare(
    'SELECT 1 FROM failed_path_alerts WHERE path = ? AND status = ? AND created_at > ? LIMIT 1'
  ).bind(safePath, status, oneHourAgo).first();

  if (!recentFail) {
    await env.DB.prepare(
      'INSERT INTO failed_path_alerts (path, status, request_id, user_agent, referrer) VALUES (?, ?, ?, ?, ?)'
    ).bind(
      safePath, 
      status, 
      request.headers.get('cf-ray') || null,
      rawUa, 
      request.headers.get('referer') || null
    ).run();
  }
}

export async function onRequest(context) {
  const { request, env, waitUntil } = context;
  const url = new URL(request.url);

  // --- Auth resolution (API routes only) ---
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

  // --- Execute request; controlled 500 on crash, telemetry still recorded ---
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

  // --- Byte counting: ALWAYS wrap when stream is usable; header only as fallback ---
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

  // --- Immutable-safe header injection ---
  const newHeaders = new Headers(response.headers);
  newHeaders.set('X-Content-Type-Options', 'nosniff');
  newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Phase 3 hook: correlation cookie on HTML only.
  if ((response.headers.get('content-type') || '').includes('text/html')) {
    newHeaders.append('Set-Cookie', `rum_session=${id.sessionHash}; Path=/; SameSite=Strict; Max-Age=1800`);
  }

  return new Response(bodyOut, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}
