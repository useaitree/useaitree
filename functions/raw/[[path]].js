// functions/raw/[[path]].js

import { errorResponse } from '../api/_utils';

export async function onRequest(context) {
  const { request, env, params } = context;

  if (request.method.toUpperCase() !== 'GET') {
    return errorResponse('Method not allowed', 405);
  }

  let pathParam = params.path;
  if (Array.isArray(pathParam)) {
    pathParam = pathParam.join('/');
  }
  if (!pathParam) {
    return errorResponse('Path required', 400);
  }

  const path = pathParam.startsWith('/') ? pathParam : `/${pathParam}`;

  if (path.includes('..') || path.includes('\\')) {
    return errorResponse('Invalid path', 400);
  }

  if (!path.endsWith('.md')) {
    return errorResponse('Only .md files are served', 400);
  }

  const cache = caches.default;
  const cacheKey = new Request(request.url, request);
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  try {
    const row = await env.DB.prepare(
      `SELECT v.content, v.content_hash
       FROM files f
       JOIN file_versions v ON v.id = f.active_version_id
       WHERE f.path = ? AND f.status = 'approved' AND f.deleted_at IS NULL`
    ).bind(path).first();

    if (!row) {
      return new Response('Not Found', {
        status: 404,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'public, max-age=60, stale-while-revalidate=86400',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }

    const response = new Response(row.content, {
      status: 200,
      headers: {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Cache-Control': 'public, max-age=60, stale-while-revalidate=86400',
        'X-Content-Hash': row.content_hash,
        'X-Content-Type-Options': 'nosniff'
      }
    });

    context.waitUntil(cache.put(cacheKey, response.clone()));
    return response;
  } catch (err) {
    return errorResponse('Failed to serve file', 500);
  }
}
