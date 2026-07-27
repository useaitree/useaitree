export async function onRequest(context) {
  const files = (await context.env.DB.prepare(`SELECT path FROM files WHERE status = 'approved' ORDER BY path`).all()).results;
  const body = files.map(f => `https://${context.request.headers.get('host')}/raw${f.path}`).join('\n');
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}
