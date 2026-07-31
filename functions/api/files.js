// functions/api/files.js

import {
  sha256Hex,
  jsonResponse,
  errorResponse
} from './_utils';

export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method.toUpperCase();
  const user = context.data?.user || null;

  if (method === 'GET') {
    return handleGet(env, user);
  }

  if (method === 'POST') {
    return handlePost(request, env, user);
  }

  if (method === 'PATCH') {
    return handlePatch(request, env, user);
  }

  return errorResponse('Method not allowed', 405);
}

async function handleGet(env, user) {
  const isAdmin = user?.role === 'admin';

  const query = isAdmin
    ? `SELECT f.id, f.path, f.status, f.active_version_id,
              v.id AS version_id, v.content_hash, v.author_email, v.note, v.created_at
       FROM files f
       LEFT JOIN file_versions v ON v.id = f.active_version_id
       ORDER BY f.path ASC`
    : `SELECT f.id, f.path, f.status, f.active_version_id,
              v.id AS version_id, v.content_hash, v.author_email, v.note, v.created_at
       FROM files f
       LEFT JOIN file_versions v ON v.id = f.active_version_id
       WHERE f.status = 'approved'
       ORDER BY f.path ASC`;

  try {
    const { results } = await env.DB.prepare(query).all();
    return jsonResponse({ files: results || [] });
  } catch (err) {
    return errorResponse('Failed to fetch files', 500);
  }
}

async function handlePost(request, env, user) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const path = (body.path || '').trim();
  const content = body.content ?? '';
  const note = body.note || null;

  if (!path) {
    return errorResponse('Path is required', 400);
  }
  if (!/^[a-zA-Z0-9\-_\/\.]+$/.test(path)) {
    return errorResponse('Invalid path characters', 400);
  }
  if (!path.endsWith('.md')) {
    return errorResponse('Path must end with .md', 400);
  }

  const contentHash = await sha256Hex(content);
  const isAdmin = user?.role === 'admin';
  const status = isAdmin ? 'approved' : 'pending';
  const authorEmail = user?.email || 'anonymous';

  try {
    const existing = await env.DB.prepare(
      'SELECT id FROM files WHERE path = ?'
    ).bind(path).first();

    let fileId;
    if (existing) {
      fileId = existing.id;
    } else {
      const insertFile = await env.DB.prepare(
        'INSERT INTO files (path, status, active_version_id) VALUES (?, ?, NULL)'
      ).bind(path, status).run();
      fileId = insertFile.meta.last_row_id;
    }

    // Uses author_email + note, NO version_num
    const insertVer = await env.DB.prepare(
      `INSERT INTO file_versions (file_id, content, content_hash, author_email, note)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(fileId, content, contentHash, authorEmail, note).run();

    const versionId = insertVer.meta.last_row_id;

    await env.DB.prepare(
      'UPDATE files SET active_version_id = ?, status = ? WHERE id = ?'
    ).bind(versionId, status, fileId).run();

    // Uses target + note + created_at
    await env.DB.prepare(
      `INSERT INTO audit_log (actor_email, action, target, note, created_at)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(authorEmail, 'Submitted', path, note, new Date().toISOString()).run();

    const origin = new URL(request.url).origin;
    try {
      await caches.default.delete(new Request(`${origin}/raw${path}`));
      await caches.default.delete(new Request(`${origin}/llms.txt`));
    } catch {
      // best-effort
    }

    return jsonResponse({
      ok: true,
      file_id: fileId,
      version_id: versionId,
      status
    }, 201);
  } catch (err) {
    return errorResponse('Failed to save file: ' + err.message, 500);
  }
}

async function handlePatch(request, env, user) {
  if (user?.role !== 'admin') {
    return errorResponse('Admin only', 403);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const action = (body.action || '').toLowerCase();
  const path = (body.path || '').trim();
  const versionId = body.version_id;

  if (!path) {
    return errorResponse('Path is required', 400);
  }

  const file = await env.DB.prepare(
    'SELECT id, active_version_id, status FROM files WHERE path = ?'
  ).bind(path).first();

  if (!file) {
    return errorResponse('File not found', 404);
  }

  try {
    if (action === 'approve') {
      await env.DB.prepare(
        "UPDATE files SET status = 'approved' WHERE id = ?"
      ).bind(file.id).run();

      await env.DB.prepare(
        'INSERT INTO audit_log (actor_email, action, target, note, created_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(user.email, 'Approved', path, '', new Date().toISOString()).run();
    } else if (action === 'reject') {
      await env.DB.prepare(
        "UPDATE files SET status = 'rejected' WHERE id = ?"
      ).bind(file.id).run();

      await env.DB.prepare(
        'INSERT INTO audit_log (actor_email, action, target, note, created_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(user.email, 'Rejected', path, '', new Date().toISOString()).run();
    } else if (action === 'revert') {
      if (!versionId) {
        return errorResponse('version_id required for revert', 400);
      }

      const ver = await env.DB.prepare(
        'SELECT id FROM file_versions WHERE id = ? AND file_id = ?'
      ).bind(versionId, file.id).first();

      if (!ver) {
        return errorResponse('Version not found for this file', 404);
      }

      await env.DB.prepare(
        'UPDATE files SET active_version_id = ? WHERE id = ?'
      ).bind(versionId, file.id).run();

      await env.DB.prepare(
        'INSERT INTO audit_log (actor_email, action, target, note, created_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(user.email, 'Reverted', path, `To v${versionId}`, new Date().toISOString()).run();
    } else {
      return errorResponse('Unknown action. Use approve, reject, or revert.', 400);
    }

    const origin = new URL(request.url).origin;
    try {
      await caches.default.delete(new Request(`${origin}/raw${path}`));
      await caches.default.delete(new Request(`${origin}/llms.txt`));
    } catch {
      // best-effort
    }

    return jsonResponse({ ok: true, action, path });
  } catch (err) {
    return errorResponse('Failed to update file: ' + err.message, 500);
  }
}
