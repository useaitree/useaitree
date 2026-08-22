// functions/sitemap.xml.js
export async function onRequest(context) {
  const { env } = context;
  const base = 'https://useaitree.online';

  const staticUrls = ['/', '/bot', '/sustainability', '/legal'];

  let fileUrls = [];
  try {
    const { results } = await env.DB.prepare(
      "SELECT path FROM files WHERE status = 'approved' AND deleted_at IS NULL"
    ).all();
    fileUrls = (results || []).map(r => `/raw${r.path}`);
  } catch (err) {
    // if DB fails, still serve static urls rather than a broken sitemap
  }

  const urls = [...staticUrls, ...fileUrls];
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `  <url><loc>${base}${u}</loc></url>`).join('\n')}
</urlset>`;

  return new Response(xml, {
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'public, max-age=3600'
    }
  });
}
