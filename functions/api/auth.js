import bcrypt from 'bcryptjs';

export async function onRequest(context) {
  if (context.request.method === 'GET') {
    if (!context.data.user) return new Response(JSON.stringify({ error: 'Not logged in' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    return new Response(JSON.stringify({ email: context.data.user.email, role: context.data.user.role }), { headers: { 'Content-Type': 'application/json' } });
  }

  const { action, email, password } = await context.request.json();
  if (!action || !email || !password) return new Response(JSON.stringify({ error: 'Missing fields' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

  if (action === 'signup') {
    const exists = await context.env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
    if (exists) return new Response(JSON.stringify({ error: 'Email already registered' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    
    // LOWERED TO 8 ROUNDS: Prevents CPU timeout crash on Cloudflare Free Tier
    try {
      const hash = await bcrypt.hash(password, 8);
      const role = (email === context.env.ADMIN_EMAIL) ? 'admin' : 'user';
      await context.env.DB.prepare(`INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)`).bind(email, hash, role).run();
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Server timeout during encryption. Try again.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify({ success: true, message: 'Account created' }), { headers: { 'Content-Type': 'application/json' } });
  }

  if (action === 'login') {
    const user = await context.env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
    if (!user) return new Response(JSON.stringify({ error: 'No account found with this email' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    
    try {
      if (!(await bcrypt.compare(password, user.password_hash))) {
        return new Response(JSON.stringify({ error: 'Incorrect password' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
    } catch(e) {
       return new Response(JSON.stringify({ error: 'Server timeout.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    const token = crypto.randomUUID();
    const hashBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
    const tokenHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    await context.env.DB.prepare(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, datetime('now', '+24 hours'))`).bind(tokenHash, user.id).run();

    return new Response(JSON.stringify({ success: true, role: user.role }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Set-Cookie': `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400` }
    });
  }

  if (action === 'logout') {
    return new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': `session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0` } });
  }
}
