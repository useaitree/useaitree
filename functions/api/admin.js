// functions/api/admin.js
// Admin-only: manage users (promote/demote maintainers, reset passwords).
// Only role === 'admin' may call this — maintainers cannot manage other users.

import {
  jsonResponse,
  errorResponse,
  generateSalt,
  pbkdf2Hash,
  generateTempPassword
} from './_utils';

export async function onRequest(context) {
  const { request, env } = context;
  const user = context.data?.user || null;

  if (!user || user.role !== 'admin') {
    return errorResponse('Admin only', 403);
  }

  const method = request.method.toUpperCase();

  if (method === 'GET') {
    return handleListUsers(env);
  }

  if (method === 'PATCH') {
    return handlePatch(request, env, user);
  }

  return errorResponse('Method not allowed', 405);
}

async function handleListUsers(env) {
  try {
    const { results } = await env.DB.prepare(
      'SELECT id, email, role, created_at FROM users ORDER BY created_at ASC'
    ).all();
    return jsonResponse({ users: results || [] });
  } catch (err) {
    return errorResponse('Failed to list users: ' + err.message, 500);
  }
}

async function handlePatch(request, env, admin) {
  let body;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const action = (body.action || '').toLowerCase();
  const email = (body.email || '').trim().toLowerCase();

  if (!email) {
    return errorResponse('Email is required', 400);
  }

  const target = await env.DB.prepare(
    'SELECT id, email, role FROM users WHERE email = ?'
  ).bind(email).first();

  if (!target) {
    return errorResponse('User not found', 404);
  }

  try {
    if (action === 'set_role') {
      const role = (body.role || '').toLowerCase();
      if (!['user', 'maintainer', 'admin'].includes(role)) {
        return errorResponse('role must be user, maintainer, or admin', 400);
      }
      if (target.email === admin.email && role !== 'admin') {
        return errorResponse('You cannot demote yourself', 400);
      }

      await env.DB.prepare('UPDATE users SET role = ? WHERE id = ?')
        .bind(role, target.id).run();

      await env.DB.prepare(
        `INSERT INTO audit_log (actor_email, action, target, note, created_at)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(admin.email, 'Role Changed', email, `Now: ${role}`, new Date().toISOString()).run();

      return jsonResponse({ ok: true, email, role });
    }

    if (action === 'reset_password') {
      const tempPassword = generateTempPassword();
      const salt = generateSalt();
      const passwordHash = await pbkdf2Hash(tempPassword, salt);

      await env.DB.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?')
        .bind(passwordHash, salt, target.id).run();

      // Invalidate any existing sessions for that user for safety
      await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?')
        .bind(target.id).run();

      await env.DB.prepare(
        `INSERT INTO audit_log (actor_email, action, target, note, created_at)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(admin.email, 'Password Reset', email, '', new Date().toISOString()).run();

      // Temp password is returned ONCE — admin must relay it to the user manually
      return jsonResponse({ ok: true, email, temp_password: tempPassword });
    }

    return errorResponse('Unknown action. Use set_role or reset_password.', 400);
  } catch (err) {
    return errorResponse('Action failed: ' + err.message, 500);
  }
}
