// functions/api/_utils.js
export function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
      ...extraHeaders
    }
  });
}
export function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}
export async function sha256Hex(input) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}
export async function pbkdf2Hash(password, saltHex) {
  const salt = hexToBytes(saltHex);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return bytesToHex(new Uint8Array(bits));
}
export function generateSalt() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}
export function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
export function extractSessionCookie(request) {
  const cookie = request.headers.get('cookie') || '';
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  return match ? match[1] : null;
}
// Generates a readable one-time temp password, e.g. "swift-anchor-4821"
const WORDS = ['swift','coral','anchor','maple','ember','quiet','solar','vivid','north','delta','cedar','ridge'];
export function generateTempPassword() {
  const w1 = WORDS[Math.floor(Math.random() * WORDS.length)];
  const w2 = WORDS[Math.floor(Math.random() * WORDS.length)];
  const num = Math.floor(1000 + Math.random() * 9000);
  return `${w1}-${w2}-${num}`;
}
// Roles that are allowed to review/edit/delete submissions
export function isReviewer(user) {
  return !!user && (user.role === 'admin' || user.role === 'maintainer');
}

// ---------- New: OAuth + email verification helpers ----------

// One-time random token (given to the user) + its hash (stored in DB), same pattern as sessions.
export function generateVerifyToken() {
  const token = crypto.randomUUID();
  return token; // caller hashes it with sha256Hex before storing
}

// 6-digit numeric OTP for email verification / password reset.
export function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Sends transactional email via Resend (https://resend.com). Requires RESEND_API_KEY
// and RESEND_FROM (a verified sender, e.g. "useaitree <noreply@useaitree.com>") as env vars.
export async function sendEmail(env, { to, subject, html }) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from: env.RESEND_FROM, to, subject, html })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error('Email send failed: ' + err);
  }
}

// Short-lived random string to protect the OAuth redirect (CSRF) — stored in a cookie, checked on callback.
export function generateOAuthState() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

export function buildRedirectUri(request, path) {
  const origin = new URL(request.url).origin;
  return `${origin}${path}`;
}

// Creates a session row + Set-Cookie header, identical to the existing email/password login flow.
export async function createSessionCookie(env, userId) {
  const token = crypto.randomUUID();
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`
  ).bind(tokenHash, userId, expiresAt).run();
  return [
    `session=${token}`,
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
    'Path=/',
    'Max-Age=604800'
  ].join('; ');
}

// Sends transactional email via Resend (https://resend.com). Requires RESEND_API_KEY
// and RESEND_FROM (a verified sender) as env vars.
export async function sendEmail(env, { to, subject, html }) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from: env.RESEND_FROM, to, subject, html })
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error('Email send failed: ' + err);
  }
}

// Upserts an OAuth user (Google/GitHub) and returns the row.
// Auto-verified since the provider already confirmed the email/account.
export async function upsertOAuthUser(env, { provider, providerId, email }) {
  const existing = await env.DB.prepare(
    'SELECT id, email, role FROM users WHERE provider = ? AND provider_id = ?'
  ).bind(provider, providerId).first();
  if (existing) return existing;

  // If an email/password (or other provider) account already uses this email, link isn't attempted —
  // keep it simple and safe: just create a separate OAuth-only account for that provider.
  const role = email === env.ADMIN_EMAIL ? 'admin' : 'user';
  const insert = await env.DB.prepare(
    `INSERT INTO users (email, password_hash, salt, role, provider, provider_id, verified)
     VALUES (?, NULL, NULL, ?, ?, ?, 1)`
  ).bind(email, role, provider, providerId).run();

  return { id: insert.meta.last_row_id, email, role };
}
