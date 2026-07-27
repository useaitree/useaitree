export async function onRequest(context) {
  const url = new URL(context.request.url);
  const ua = context.request.headers.get('user-agent') || '';

  if (url.pathname.startsWith('/api/')) {
    const tokenPart = (context.request.headers.get('cookie') || '').split(';').find(c => c.trim().startsWith('session='));
    if (tokenPart) {
      try {
        const tokenVal = tokenPart.trim().substring(tokenPart.trim().indexOf('=') + 1);
        const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(tokenVal));
        const tokenHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
        const session = await context.env.DB.prepare(`SELECT u.id, u.email, u.role FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token_hash = ? AND s.expires_at > datetime('now')`).bind(tokenHash).first();
        if (session) context.data.user = session;
      } catch (e) {}
    }
  }

  const startMs = Date.now();
  let response;
  try { response = await context.next(); } catch (e) { return new Response('Internal Server Error', { status: 500 }); }
  if (response.status === 304 || response.status === 204) return response;
  
  response = new Response(response.body, response);
  response.headers.set('X-Content-Type-Options', 'nosniff');

  const botRegex = /ClaudeBot|GPTBot|PerplexityBot|Googlebot|bingbot|Applebot-Extended/i;
  const isBot = botRegex.test(ua);
  const cacheStatus = response.headers.get('cf-cache-status') || 'BYPASS';
  
  let group = 'other';
  if (url.pathname === '/llms.txt') group = 'llms-txt';
  else if (url.pathname.startsWith('/raw/')) group = 'raw-content';
  else if (url.pathname.startsWith('/api/')) group = 'api';
  else if (url.pathname.endsWith('.html') || url.pathname === '/') group = 'frontend';

  const ttfb = Date.now() - startMs;
  const bytes = parseInt(response.headers.get('content-length') || '1000');
  const now = new Date();
  const windowStart = new Date(now.getTime() - (now.getTime() % (15 * 60 * 1000))).toISOString();

  context.waitUntil(
    context.env.DB.prepare(`
      INSERT INTO telemetry_windows (window_start, endpoint_group, req_count, sum_bytes, sum_ttfb_ms, cache_hits, cache_misses, bot_hits)
      VALUES (?, ?, 1, ?, ?, ?, ?, ?)
      ON CONFLICT(window_start, endpoint_group) DO UPDATE SET 
        req_count = req_count + 1, sum_bytes = sum_bytes + ?, sum_ttfb_ms = sum_ttfb_ms + ?, 
        cache_hits = cache_hits + ?, cache_misses = cache_misses + ?, bot_hits = bot_hits + ?
    `).bind(
      windowStart, group, bytes, ttfb, (cacheStatus === 'HIT' ? 1 : 0), (cacheStatus !== 'HIT' ? 1 : 0), (isBot ? 1 : 0),
      bytes, ttfb, (cacheStatus === 'HIT' ? 1 : 0), (cacheStatus !== 'HIT' ? 1 : 0), (isBot ? 1 : 0)
    ).run()
  );
  return response;
}
