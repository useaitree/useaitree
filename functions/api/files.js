// functions/api/files.js

import {
  sha256Hex,
  jsonResponse,
  errorResponse,
  isReviewer
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
  const reviewer = isReviewer(user);

  // Reviewers (admin/maintainer) see everything not deleted, including content,
  // so they can actually read submissions before approving/rejecting.
  // Everyone else only sees approved, non-deleted files.
  const query = reviewer
    ? `SELECT f.id, f.path, f.status, f.active_version_id, f.review_note, f.reviewed_by, f.reviewed_at,
              v.id AS version_id, v.content, v.content_hash, v.author_email, v.note, v.created_at
       FROM files f
       LEFT JOIN file_versions v ON v.id = f.active_version_id
       WHERE f.deleted_at IS NULL
       ORDER BY f.path ASC`
    : `SELECT f.id, f.path, f.status, f.active_version_id, f.review_note, f.reviewed_by, f.reviewed_at,
              v.id AS version_id, v.content, v.content_hash, v.author_email, v.note, v.created_at
       FROM files f
       LEFT JOIN file_versions v ON v.id = f.active_version_id
       WHERE f.deleted_at IS NULL
         AND (f.status = 'approved' OR v.author_email = ?)
       ORDER BY f.path ASC`;

  try {
    const stmt = reviewer
      ? env.DB.prepare(query)
      : env.DB.prepare(query).bind(user?.email || '__none__');
    const { results } = await stmt.all();
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
  const reviewer = isReviewer(user);
  const status = reviewer ? 'approved' : 'pending';
  const authorEmail = user?.email || 'anonymous';

  try {
    const existing = await env.DB.prepare(
      'SELECT id, deleted_at FROM files WHERE path = ?'
    ).bind(path).first();

    let fileId;
    if (existing) {
      fileId = existing.id;
      // Resubmitting to a soft-deleted path revives it
      if (existing.deleted_at) {
        await env.DB.prepare('UPDATE files SET deleted_at = NULL WHERE id = ?').bind(fileId).run();
      }
    } else {
      const insertFile = await env.DB.prepare(
        'INSERT INTO files (path, status, active_version_id) VALUES (?, ?, NULL)'
      ).bind(path, status).run();
      fileId = insertFile.meta.last_row_id;
    }

    const insertVer = await env.DB.prepare(
      `INSERT INTO file_versions (file_id, content, content_hash, author_email, note)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(fileId, content, contentHash, authorEmail, note).run();

    const versionId = insertVer.meta.last_row_id;

    await env.DB.prepare(
      `UPDATE files
       SET active_version_id = ?, status = ?, review_note = NULL, reviewed_by = NULL, reviewed_at = NULL
       WHERE id = ?`
    ).bind(versionId, status, fileId).run();

    await env.DB.prepare(
      `INSERT INTO audit_log (actor_email, action, target, note, created_at)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(authorEmail, 'Submitted', path, note, new Date().toISOString()).run();

    await bustCache(request, path);

    return jsonResponse({ ok: true, file_id: fileId, version_id: versionId, status }, 201);
  } catch (err) {
    return errorResponse('Failed to save file: ' + err.message, 500);
  }
}

async function handlePatch(request, env, user) {
  if (!isReviewer(user)) {
    return errorResponse('Admin or maintainer only', 403);
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
  const note = (body.note || '').trim();
  const content = body.content;

  if (!path) {
    return errorResponse('Path is required', 400);
  }

  const file = await env.DB.prepare(
    'SELECT id, active_version_id, status FROM files WHERE path = ? AND deleted_at IS NULL'
  ).bind(path).first();

  if (!file) {
    return errorResponse('File not found', 404);
  }

  const now = new Date().toISOString();

  try {
    if (action === 'approve') {
      await env.DB.prepare(
        "UPDATE files SET status = 'approved', review_note = NULL, reviewed_by = ?, reviewed_at = ? WHERE id = ?"
      ).bind(user.email, now, file.id).run();

      await logAction(env, user.email, 'Approved', path, '');
    } else if (action === 'reject') {
      await env.DB.prepare(
        "UPDATE files SET status = 'rejected', review_note = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?"
      ).bind(note || null, user.email, now, file.id).run();

      await logAction(env, user.email, 'Rejected', path, note);
    } else if (action === 'request_changes') {
      if (!note) {
        return errorResponse('A note explaining the requested changes is required', 400);
      }
      await env.DB.prepare(
        "UPDATE files SET status = 'changes_requested', review_note = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?"
      ).bind(note, user.email, now, file.id).run();

      await logAction(env, user.email, 'Changes Requested', path, note);
    } else if (action === 'edit') {
      if (typeof content !== 'string') {
        return errorResponse('content is required for edit', 400);
      }
      const contentHash = await sha256Hex(content);
      const insertVer = await env.DB.prepare(
        `INSERT INTO file_versions (file_id, content, content_hash, author_email, note)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(file.id, content, contentHash, user.email, note || 'Edited by reviewer').run();

      const newVersionId = insertVer.meta.last_row_id;

      await env.DB.prepare(
        `UPDATE files SET active_version_id = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?`
      ).bind(newVersionId, user.email, now, file.id).run();

      await logAction(env, user.email, 'Edited', path, note || '');
    } else if (action === 'delete') {
      await env.DB.prepare(
        'UPDATE files SET deleted_at = ? WHERE id = ?'
      ).bind(now, file.id).run();

      await logAction(env, user.email, 'Deleted', path, note || '');
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

      await logAction(env, user.email, 'Reverted', path, `To v${versionId}`);
    } else {
      return errorResponse('Unknown action. Use approve, reject, request_changes, edit, delete, or revert.', 400);
    }

    await bustCache(request, path);

    return jsonResponse({ ok: true, action, path });
  } catch (err) {
    return errorResponse('Failed to update file: ' + err.message, 500);
  }
}

async function logAction(env, actorEmail, action, target, note) {
  await env.DB.prepare(
    `INSERT INTO audit_log (actor_email, action, target, note, created_at)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(actorEmail, action, target, note, new Date().toISOString()).run();
}

async function bustCache(request, path) {
  const origin = new URL(request.url).origin;
  try {
    await caches.default.delete(new Request(`${origin}/raw${path}`));
    await caches.default.delete(new Request(`${origin}/llms.txt`));
  } catch {
    // best-effort
  }
}
