import bcrypt from 'bcryptjs';

export async function onRequest(context) {
  const url = new URL(context.request.url);

  if (context.request.method === 'GET') {
    if (!context.data.user) return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    return new Response(JSON.stringify({ email: context.data.user.email, role: context.data.user.role }), { headers: { 'Content-Type': 'application/json' } });
  }

  const { action, email, password } = await context.request.json();

  if (action === 'signup' || action === 'login') {
    const user = await context.env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
    
    if (action === 'signup') {
      if (user) return new Response(JSON.stringify({ error: 'Email exists' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      const hash = await bcrypt.hash(password, 8);
      const role = (email === context.env.ADMIN_EMAIL) ? 'admin' : 'user';
      await context.env.DB.prepare(`INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)`).bind(email, hash, role).run();
    } else {
      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
    }

    const finalUser = user || await context.env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
    const token = crypto.randomUUID();
    const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
    const tokenHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    await context.env.DB.prepare(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, datetime('now', '+24 hours'))`).bind(tokenHash, finalUser.id).run();

    // FIX: Audit Logging
    await context.env.DB.prepare(`INSERT INTO audit_log (timestamp, user_email, action, target) VALUES (datetime('now'), ?, ?, ?)`).bind(email, action === 'signup' ? 'Signed Up' : 'Logged In', 'System').run();

    return new Response(JSON.stringify({ success: true, role: finalUser.role }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400` }
    });
  }

  if (action === 'logout') {
    // FIX: Audit Logging
    if (context.data.user) {
      await context.env.DB.prepare(`INSERT INTO audit_log (timestamp, user_email, action, target) VALUES (datetime('now'), ?, 'Logged Out', 'System')`).bind(context.data.user.email).run();
    }
    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': `session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0` }
    });
  }

  return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
}
