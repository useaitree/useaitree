// functions/api/rum.js
import { jsonResponse, errorResponse } from './_utils';

const MAX_BODY = 4096;
const RATE_LIMIT = 6;            // beacons per IP per window (per-isolate, best-effort)
const RATE_WINDOW_MS = 60000;
const SAMPLE_RATE = 1;           // lower (e.g. 0.5) if you near the write ceiling

const rateBuckets = new Map();
const NAV_TYPES = new Set(['navigate', 'reload', 'back_forward', 'prerender']);

const toFinite = (v, min, max) => {
  const n = Number(v);
  return Number.isFinite(n) && n >= min && n <= max ? n : null;
};
const toInt = (v, min, max) => {
  const n = toFinite(v, min, max);
  return n === null ? null : Math.round(n);
};
const toStr = (v, maxLen) =>
  typeof v === 'string' && v.length > 0 && v.length <= maxLen ? v : null;

function getCookie(request, name) {
  const c = request.headers.get('cookie') || '';
  const m = c.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? m[1] : null;
}
function rateLimited(ip) {
  const now = Date.now();
  if (rateBuckets.size > 10000) rateBuckets.clear(); // crude prune
  const b = rateBuckets.get(ip);
  if (!b || now > b.resetAt) {
    rateBuckets.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return false;
  }
  b.count += 1;
  return b.count > RATE_LIMIT;
}

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method.toUpperCase() !== 'POST') return errorResponse('Method not allowed', 405);

  // Strict same-origin: EXACT host match (Origin header, Referer fallback)
  const host = new URL(request.url).host;
  let checkHost = null;
  try { checkHost = new URL(request.headers.get('origin') || '').host; } catch {}
  if (!checkHost) {
    try { checkHost = new URL(request.headers.get('referer') || '').host; } catch {}
  }
  if (checkHost !== host) return errorResponse('Forbidden', 403);

  // Abuse controls
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (rateLimited(ip)) return errorResponse('Too many requests', 429);
  if (SAMPLE_RATE < 1 && Math.random() >= SAMPLE_RATE) return jsonResponse({ ok: true, sampled: true });
  if (parseInt(request.headers.get('content-length') || '0', 10) > MAX_BODY) {
    return errorResponse('Payload too large', 413);
  }

  let b;
  try { b = await request.json(); } catch { return errorResponse('Invalid JSON', 400); }
  if (typeof b !== 'object' || b === null || Array.isArray(b)) return errorResponse('Invalid payload', 400);

  // Session correlation: rum_session cookie set by middleware (auto-sent by sendBeacon)
  const sid = getCookie(request, 'rum_session');

  // Strict validation + coercion
  const row = {
    session_hash: sid && /^[a-f0-9]{16}$/.test(sid) ? sid : null,
    path: toStr(b.path, 500),
    lcp_ms: toFinite(b.lcp, 0, 600000),
    cls: toFinite(b.cls, 0, 100),
    inp_ms: toFinite(b.inp, 0, 60000),
    ttfb_client_ms: toFinite(b.ttfb, 0, 60000),
    viewport_w: toInt(b.vw, 0, 20000),
    viewport_h: toInt(b.vh, 0, 20000),
    screen_w: toInt(b.sw, 0, 20000),
    screen_h: toInt(b.sh, 0, 20000),
    dpr: toFinite(b.dpr, 0, 10),
    time_on_page_ms: toInt(b.dur, 0, 86400000),
    scroll_depth_pct: toInt(b.scroll, 0, 100),
    js_error_count: toInt(b.errs, 0, 10000) ?? 0,
    nav_type: NAV_TYPES.has(b.nav) ? b.nav : null,
  };

  try {
    // 16 columns = 16 placeholders = 16 binds (verified)
    await env.DB.prepare(
      `INSERT INTO client_metrics
       (ts, session_hash, path, lcp_ms, cls, inp_ms, ttfb_client_ms,
        viewport_w, viewport_h, screen_w, screen_h, dpr,
        time_on_page_ms, scroll_depth_pct, js_error_count, nav_type)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      new Date().toISOString(),
      row.session_hash, row.path, row.lcp_ms, row.cls, row.inp_ms, row.ttfb_client_ms,
      row.viewport_w, row.viewport_h, row.screen_w, row.screen_h, row.dpr,
      row.time_on_page_ms, row.scroll_depth_pct, row.js_error_count, row.nav_type
    ).run();
    return jsonResponse({ ok: true });
  } catch (e) {
    console.error('RUM write failed:', e); // details server-side only
    return errorResponse('Beacon rejected', 500); // generic message to client
  }
}
