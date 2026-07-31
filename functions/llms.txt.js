// functions/llms.txt.js

import { errorResponse } from './api/_utils';

export async function onRequest(context) {
  const { env } = context;

  if (context.request.method.toUpperCase() !== 'GET') {
    return errorResponse('Method not allowed', 405);
  }

  try {
    const { results } = await env.DB.prepare(
      `SELECT f.path
       FROM files f
       WHERE f.status = 'approved' AND f.active_version_id IS NOT NULL
       ORDER BY f.path ASC`
    ).all();

    const origin = new URL(context.request.url).host;
    const files = results || [];
    const lines = ['# useaitree', '> AI-Native Knowledge Layer', '', '## Documentation'];
    files.forEach(f => lines.push(`- [${f.path}](https://${origin}/raw${f.path})`));
    const body = lines.join('\n');

    return new Response(body, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'public, max-age=60, stale-while-revalidate=86400',
        'X-Content-Type-Options': 'nosniff'
      }
    });
  } catch (err) {
    return errorResponse('Failed to generate llms.txt', 500);
  }
}
