import DiffMatchPatch from 'diff-match-patch';

const dmp = new DiffMatchPatch();

async function reconstructContent(env, targetVersionId) {
  let currentVersion = await env.DB.prepare(`SELECT * FROM file_versions WHERE id = ?`).bind(targetVersionId).first();
  if (!currentVersion) throw new Error('Version not found');
  const chain = [currentVersion];
  while (currentVersion && !currentVersion.is_full_snapshot) {
    currentVersion = await env.DB.prepare(`SELECT * FROM file_versions WHERE id = ?`).bind(currentVersion.base_version_id).first();
    if (!currentVersion) throw new Error('Missing base snapshot in chain');
    chain.push(currentVersion);
  }
  chain.reverse();
  let content = chain[0].content;
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].is_full_snapshot) content = chain[i].content;
    else {
      const patches = dmp.patch_fromText(chain[i].patch);
      content = dmp.patch_apply(patches, content)[0];
    }
  }
  return content;
}

function validatePath(path) {
  if (!path.startsWith('/')) return false;
  if (path.includes('..')) return false;
  if (!/^[a-zA-Z0-9\-_\/\.]+$/.test(path)) return false;
  return true;
}

export async function onRequest(context) {
  const url = new URL(context.request.url);
  const path = url.searchParams.get('path');
  const user = context.data.user; // Might be undefined if not logged in

  // GET: PUBLIC (Anyone can view the file tree)
  if (context.request.method === 'GET') {
    const showDeleted = user && user.role === 'admin' && url.searchParams.has('deleted');
    const query = showDeleted ? `SELECT * FROM files ORDER BY path` : `SELECT * FROM files WHERE status != 'deleted' ORDER BY path`;
    const files = (await context.env.DB.prepare(query).all()).results;
    return new Response(JSON.stringify(files), { headers: { 'Content-Type': 'application/json' } });
  }

  // POST: PUBLIC SUBMISSION (Anyone can suggest a file, goes to pending queue)
  if (context.request.method === 'POST' && path) {
    if (path && !validatePath(path)) return new Response(JSON.stringify({ error: 'Invalid path' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    
    const file = await context.env.DB.prepare(`SELECT * FROM files WHERE path = ?`).bind(path).first();
    if (file) return new Response(JSON.stringify({ error: 'Path already exists' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

    const { content, note } = await context.request.json();
    if (new TextEncoder().encode(content).length > 500 * 1024) return new Response(JSON.stringify({ error: 'File > 500KB' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

    const safeNote = note ?? null;
    const authorEmail = user ? user.email : 'public_submission';
    const status = (user && user.role === 'admin') ? 'approved' : 'pending';

    try {
      const res = await context.env.DB.prepare(`INSERT INTO files (path, status, version_count) VALUES (?, ?, 1)`).bind(path, status).run();
      const fileId = res.meta.last_row_id;

      await context.env.DB.prepare(`INSERT INTO file_versions (file_id, base_version_id, is_full_snapshot, content, patch, author_email, timestamp, note) VALUES (?, NULL, 1, ?, NULL, ?, datetime('now'), ?)`).bind(fileId, content, authorEmail, safeNote).run();
      await context.env.DB.prepare(`UPDATE files SET active_version_id = (SELECT id FROM file_versions WHERE file_id = ?) WHERE id = ?`).bind(fileId, fileId).run();
      
      await context.env.DB.prepare(`INSERT INTO audit_log (timestamp, user_email, action, target, note) VALUES (datetime('now'), ?, 'Public Submission', ?, ?)`).bind(authorEmail, path, safeNote).run();

      return new Response(JSON.stringify({ success: true, message: 'Submitted for review' }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Database update failed' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  }

  // ALL OTHER ROUTES REQUIRE AUTHENTICATION
  if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });

  if (context.request.method === 'DELETE' && path) {
    const file = await context.env.DB.prepare(`SELECT * FROM files WHERE path = ?`).bind(path).first();
    if (!file) return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });

    if (url.searchParams.get('purge') === 'true' && user.role === 'admin') {
      await context.env.DB.prepare(`DELETE FROM file_versions WHERE file_id = ?`).bind(file.id).run();
      await context.env.DB.prepare(`DELETE FROM files WHERE id = ?`).bind(file.id).run();
      await context.env.DB.prepare(`INSERT INTO audit_log (timestamp, user_email, action, target) VALUES (datetime('now'), ?, 'Hard Deleted', ?)`).bind(user.email, path).run();
    } else if (user.role === 'admin') {
      await context.env.DB.prepare(`UPDATE files SET status = 'deleted', deleted_at = datetime('now') WHERE id = ?`).bind(file.id).run();
      await context.env.DB.prepare(`INSERT INTO audit_log (timestamp, user_email, action, target) VALUES (datetime('now'), ?, 'Soft Deleted', ?)`).bind(user.email, path).run();
    }
    return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  if (context.request.method === 'PUT' && path) {
    if (!validatePath(path)) return new Response(JSON.stringify({ error: 'Invalid path' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    const file = await context.env.DB.prepare(`SELECT * FROM files WHERE path = ?`).bind(path).first();
    if (!file) return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });

    const { content, note } = await context.request.json();
    if (new TextEncoder().encode(content).length > 500 * 1024) return new Response(JSON.stringify({ error: 'File > 500KB' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

    let newVersionCount = file.version_count + 1;
    let baseVersionId = null, isFull = 1, contentToStore = null, patchToStore = null;

    if (newVersionCount % 5 === 0) { contentToStore = content; } 
    else {
      isFull = 0; baseVersionId = file.active_version_id;
      const oldContent = await reconstructContent(context.env, baseVersionId);
      const diffs = dmp.diff_main(oldContent, content); dmp.diff_cleanupSemantic(diffs);
      patchToStore = dmp.patch_toText(dmp.patch_make(oldContent, diffs));
    }

    try {
      await context.env.DB.prepare(`UPDATE files SET version_count = ? WHERE id = ?`).bind(newVersionCount, file.id).run();
      const safeNote = note ?? null;
      const vRes = await context.env.DB.prepare(`INSERT INTO file_versions (file_id, base_version_id, is_full_snapshot, content, patch, author_email, timestamp, note) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)`).bind(file.id, baseVersionId, isFull, contentToStore, patchToStore, user.email, safeNote).run();
      await context.env.DB.prepare(`UPDATE files SET active_version_id = ?, status = CASE WHEN ? = 'admin' THEN 'approved' ELSE status END WHERE id = ?`).bind(vRes.meta.last_row_id, user.role, file.id).run();
      await context.env.DB.prepare(`INSERT INTO audit_log (timestamp, user_email, action, target, note) VALUES (datetime('now'), ?, 'Edited', ?, ?)`).bind(user.email, path, safeNote).run();
      return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) { return new Response(JSON.stringify({ error: 'Database update failed' }), { status: 500, headers: { 'Content-Type': 'application/json' } }); }
  }

  if (context.request.method === 'PATCH') {
    const { action, path, versionId } = await context.request.json();
    const file = await context.env.DB.prepare(`SELECT * FROM files WHERE path = ?`).bind(path).first();
    if (!file) return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
    if (user.role !== 'admin') return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers: { 'Content-Type': 'application/json' } });

    if (action === 'approve') await context.env.DB.prepare(`UPDATE files SET status = 'approved' WHERE id = ?`).bind(file.id).run();
    if (action === 'revert') await context.env.DB.prepare(`UPDATE files SET active_version_id = ?, version_count = version_count + 1 WHERE id = ?`).bind(versionId, file.id).run();
    if (action === 'restore') await context.env.DB.prepare(`UPDATE files SET status = 'approved', deleted_at = NULL WHERE id = ?`).bind(file.id).run();
    
    return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
  }
}
