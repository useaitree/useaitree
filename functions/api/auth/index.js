// functions/api/auth/index.js

import {
  pbkdf2Hash,
  generateSalt,
  sha256Hex,
  jsonResponse,
  errorResponse,
  extractSessionCookie,
  generateOtp
} from '../_utils';

export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method.toUpperCase();

  if (method === 'GET') {
    return handleGetSession(request, env);
  }

  if (method === 'POST') {
    let body;
    try {
      body = await request.json();
    } catch {
      return errorResponse('Invalid JSON body', 400);
    }

    const action = (body.action || '').toLowerCase();

    if (action === 'signup') return handleSignup(body, env);
    if (action === 'login') return handleLogin(body, env);
    if (action === 'logout') return handleLogout(request, env);
    if (action === 'verify') return handleVerify(body, env);
    if (action === 'request_reset') return handleRequestReset(body, env);
    if (action === 'reset_password') return handleResetPassword(body, env);

    return errorResponse('Unknown action. Use signup, login, logout, verify, request_reset, or reset_password.', 400);
  }

  return errorResponse('Method not allowed', 405);
}

async function handleSignup(body, env) {
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  if (!email || !password) {
    return errorResponse('Email and password are required', 400);
  }
  if (password.length < 8) {
    return errorResponse('Password must be at least 8 characters', 400);
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) {
    return errorResponse('Email already registered', 409);
  }

  const salt = generateSalt();
  const passwordHash = await pbkdf2Hash(password, salt);
  const role = email === env.ADMIN_EMAIL ? 'admin' : 'user';

  // 6-digit OTP instead of a link token. No email service is wired up yet,
  // so the OTP is returned in the response for the frontend to display —
  // swap this for a real email send once a provider (Resend/SendGrid/etc) is added.
  const otp = generateOtp();
  const otpHash = await sha256Hex(otp);
  const otpExpires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  try {
    await env.DB.prepare(
      `INSERT INTO users (email, password_hash, salt, role, provider, verified, verify_token_hash, verify_token_expires)
       VALUES (?, ?, ?, ?, 'password', 0, ?, ?)`
    ).bind(email, passwordHash, salt, role, otpHash, otpExpires).run();
  } catch (err) {
    return errorResponse('Failed to create user: ' + err.message, 500);
  }

  return jsonResponse(
    { ok: true, message: 'Signup successful — enter the OTP to verify', otp },
    201
  );
}

async function handleVerify(body, env) {
  const email = (body.email || '').trim().toLowerCase();
  const otp = (body.otp || '').trim();
  if (!email || !otp) return errorResponse('Email and OTP are required', 400);

  const otpHash = await sha256Hex(otp);
  const now = new Date().toISOString();

  const user = await env.DB.prepare(
    'SELECT id, verify_token_hash, verify_token_expires FROM users WHERE email = ?'
  ).bind(email).first();

  if (!user || user.verify_token_hash !== otpHash || !user.verify_token_expires || user.verify_token_expires < now) {
    return errorResponse('Invalid or expired OTP', 400);
  }

  await env.DB.prepare(
    'UPDATE users SET verified = 1, verify_token_hash = NULL, verify_token_expires = NULL WHERE id = ?'
  ).bind(user.id).run();

  return jsonResponse({ ok: true, message: 'Email verified — you can log in now' });
}

async function handleRequestReset(body, env) {
  const email = (body.email || '').trim().toLowerCase();
  if (!email) return errorResponse('Email is required', 400);

  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE email = ? AND provider = 'password'"
  ).bind(email).first();

  // Always respond ok (don't leak which emails exist), but only actually set an OTP if the account exists.
  if (user) {
    const otp = generateOtp();
    const otpHash = await sha256Hex(otp);
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    await env.DB.prepare(
      'UPDATE users SET verify_token_hash = ?, verify_token_expires = ? WHERE id = ?'
    ).bind(otpHash, otpExpires, user.id).run();
    return jsonResponse({ ok: true, message: 'Reset OTP generated', otp });
  }

  return jsonResponse({ ok: true, message: 'If that email exists, an OTP was generated' });
}

async function handleResetPassword(body, env) {
  const email = (body.email || '').trim().toLowerCase();
  const otp = (body.otp || '').trim();
  const newPassword = body.new_password || '';

  if (!email || !otp || !newPassword) return errorResponse('Email, OTP, and new password are required', 400);
  if (newPassword.length < 8) return errorResponse('Password must be at least 8 characters', 400);

  const otpHash = await sha256Hex(otp);
  const now = new Date().toISOString();

  const user = await env.DB.prepare(
    'SELECT id, verify_token_hash, verify_token_expires FROM users WHERE email = ?'
  ).bind(email).first();

  if (!user || user.verify_token_hash !== otpHash || !user.verify_token_expires || user.verify_token_expires < now) {
    return errorResponse('Invalid or expired OTP', 400);
  }

  const salt = generateSalt();
  const passwordHash = await pbkdf2Hash(newPassword, salt);

  await env.DB.prepare(
    `UPDATE users SET password_hash = ?, salt = ?, verified = 1, verify_token_hash = NULL, verify_token_expires = NULL WHERE id = ?`
  ).bind(passwordHash, salt, user.id).run();

  return jsonResponse({ ok: true, message: 'Password reset — you can log in now' });
}

async function handleLogin(body, env) {
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';

  if (!email || !password) {
    return errorResponse('Email and password are required', 400);
  }

  const user = await env.DB.prepare(
    'SELECT id, email, password_hash, salt, role, provider, verified FROM users WHERE email = ?'
  ).bind(email).first();

  if (!user || user.provider !== 'password' || !user.password_hash) {
    return errorResponse('Invalid email or password', 401);
  }

  const candidateHash = await pbkdf2Hash(password, user.salt);
  if (candidateHash !== user.password_hash) {
    return errorResponse('Invalid email or password', 401);
  }

  if (!user.verified) {
    return errorResponse('Please verify your email before logging in', 403);
  }

  const token = crypto.randomUUID();
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  try {
    await env.DB.prepare(
      `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`
    ).bind(tokenHash, user.id, expiresAt).run();
  } catch (err) {
    return errorResponse('Failed to create session', 500);
  }

  const cookie = [
    `session=${token}`, 'HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/', 'Max-Age=604800'
  ].join('; ');

  return jsonResponse({ ok: true, email: user.email, role: user.role }, 200, { 'Set-Cookie': cookie });
}

async function handleGetSession(request, env) {
  const token = extractSessionCookie(request);
  if (!token) return errorResponse('Not authenticated', 401);

  const tokenHash = await sha256Hex(token);
  const now = new Date().toISOString();

  const row = await env.DB.prepare(
    `SELECT u.email, u.role FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > ?`
  ).bind(tokenHash, now).first();

  if (!row) return errorResponse('Not authenticated', 401);
  return jsonResponse({ email: row.email, role: row.role });
}

async function handleLogout(request, env) {
  const token = extractSessionCookie(request);
  if (token) {
    const tokenHash = await sha256Hex(token);
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(tokenHash).run();
  }
  const clearCookie = ['session=', 'HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/', 'Max-Age=0'].join('; ');
  return jsonResponse({ ok: true, message: 'Logged out' }, 200, { 'Set-Cookie': clearCookie });
}
