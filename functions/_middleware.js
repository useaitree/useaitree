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
  for (const b of BOT_PATTERNS) {
    if (b.regex.test(ua)) return b.name;
  }
  return 'Human';
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

  // --- Execute request FIRST (needed for response metadata) ---
  const startMs = Date.now();
  const response = await context.next();
  const ttfb = Date.now() - startMs;

  // --- Telemetry extraction & privacy enforcement ---
  const rawIp = request.headers.get('CF-Connecting-IP') || '';
  const rawUa = request.headers.get('User-Agent') || '';
  const botCategory = classifyBot(rawUa);

  // ⚠️ rawUa never used after this line
  const timeBucket = Math.floor(Date.now() / 1800000);
  const sessionHash = (await sha256Hex(`${rawIp}-${botCategory}-${timeBucket}`)).slice(0, 16);
  // ⚠️ rawIp never used after this line

  const geo = {
    country: request.cf?.country || 'Unknown',
    region: request.cf?.region || 'Unknown',
    city: request.cf?.city || 'Unknown',
    asn: request.cf?.asn || 0,
    asOrg: request.cf?.asOrganization || 'Unknown',
  };

  // --- Async telemetry write (ALL 16 columns, correct column names) ---
  waitUntil(
    env.DB.prepare(
      `INSERT INTO request_events
        (ts, country, region, city, asn, as_org, path, method, status, resp_bytes, cache_status, ttfb_ms, bot_category, session_hash, http_ver, tls_ver)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      new Date().toISOString(),
      geo.country, geo.region, geo.city, geo.asn, geo.asOrg,
      url.pathname,
      request.method,
      response.status,
      parseInt(response.headers.get('content-length') || '0'),
      response.headers.get('cf-cache-status') || 'BYPASS',
      ttfb,
      botCategory,
      sessionHash,
      request.cf?.httpProtocol || 'Unknown',
      request.cf?.tlsVersion || 'Unknown'
    ).run().catch(e => console.error('Telemetry write failed:', e))
  );

  // --- Immutable-safe header injection ---
  const newHeaders = new Headers(response.headers);
  newHeaders.set('X-Content-Type-Options', 'nosniff');
  newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders,
  });
}
