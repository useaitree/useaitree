export async function onRequest(context) {
  const url = new URL(context.request.url);
  const ua = context.request.headers.get('user-agent') || '';
  const ip = context.request.headers.get('cf-connecting-ip') || '';

  if (url.pathname.startsWith('/api/')) {
    const cookieHeader = context.request.headers.get('cookie') || '';
    const tokenPart = cookieHeader.split(';').find(c => c.trim().startsWith('session='));
    if (tokenPart) {
      try {
        const tokenVal = tokenPart.trim().substring(tokenPart.trim().indexOf('=') + 1);
        const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(tokenVal));
        const tokenHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');

        const session = await context.env.DB.prepare(
          `SELECT u.id, u.email, u.role FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token_hash = ? AND s.expires_at > datetime('now')`
        ).bind(tokenHash).first();

        if (session) context.data.user = session;
      } catch (e) {
        console.error("Auth extraction failed:", e);
      }
    }
  }

  let response;
  try {
    response = await context.next();
  } catch (error) {
    console.error("Unhandled Exception:", error);
    return new Response('Internal Server Error', { status: 500 });
  }

  // FIX: 304 and 204 responses cannot have a body. Returning them directly prevents V8 TypeError.
  if (response.status === 304 || response.status === 204) {
    return response;
  }

  response = new Response(response.body, response);
  response.headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');

  // 100% Bot Logging to D1
  const botRegex = /ClaudeBot|GPTBot|PerplexityBot|Googlebot|bingbot|Applebot-Extended/i;
  if (botRegex.test(ua)) {
    const botType = ua.match(botRegex)[0];
    context.waitUntil(
      context.env.DB.prepare(`INSERT INTO bot_hits (timestamp, bot_type, path) VALUES (datetime('now'), ?, ?)`)
        .bind(botType, url.pathname)
        .run()
    );
  }

  return response;
}
