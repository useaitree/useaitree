export async function onRequest(context) {
  const user = context.data.user;
  if (!user) return new Response('Unauthorized', { status: 401 });

  const logs = (await context.env.DB.prepare(`SELECT * FROM audit_log ORDER BY id DESC LIMIT 100`).all()).results;
  
  const stats = (await context.env.DB.prepare(`
    SELECT date(timestamp) as date, bot_type, SUM(1) as total_hits 
    FROM bot_hits 
    GROUP BY date(timestamp), bot_type 
    ORDER BY date DESC 
    LIMIT 30
  `).all()).results;

  return new Response(JSON.stringify({ logs, stats }), {
    headers: { 'Content-Type': 'application/json' }
  });
}
