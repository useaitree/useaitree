// api/index.js — Vercel Edge Function (catches all routes)

export const config = {
  runtime: 'edge',
};

import { Pool } from '@neondatabase/serverless';

function parseCookies(request) {
  const header = request.headers.get("cookie") || "";
  const out = {};
  header.split(";").forEach(part => {
    const [k, ...v] = part.trim().split("=");
    if (k) out[k] = v.join("=");
  });
  return out;
}

async function isAuthenticated(request) {
  const cookies = parseCookies(request);
  const token = cookies["admin_session"];
  if (!token) return false;
  
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const result = await pool.query("SELECT expires_at FROM admin_sessions WHERE token = $1", [token]);
  await pool.end();
  
  if (result.rows.length === 0) return false;
  return new Date(result.rows[0].expires_at) > new Date();
}

function loginPageHTML(error) {
  return "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>useaitree admin</title><style>" +
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:#f6f8fa;color:#1f2328;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}" +
    ".topbar{position:fixed;top:0;left:0;right:0;background:#24292f;color:#fff;padding:0.75rem 1.5rem;display:flex;align-items:center;gap:0.75rem;}" +
    ".mark{width:22px;height:22px;border-radius:6px;background:linear-gradient(135deg,#0969da,#54aeff);display:inline-block;}" +
    ".box{background:#fff;border:1px solid #d1d9e0;border-radius:8px;padding:2rem;width:320px;}" +
    "h1{font-size:1.1rem;margin-top:0;}" +
    "label{display:block;font-size:0.8rem;font-weight:600;margin-bottom:0.3rem;margin-top:0.9rem;}" +
    "input{width:100%;padding:0.5rem;border:1px solid #d1d9e0;border-radius:6px;font-size:0.9rem;}" +
    "button{width:100%;margin-top:1.2rem;padding:0.55rem;background:#1a7f37;color:#fff;border:none;border-radius:6px;font-weight:600;cursor:pointer;}" +
    ".err{color:#d1242f;font-size:0.8rem;margin-top:0.8rem;}" +
    "</style></head><body>" +
    "<div class='topbar'><span class='mark'></span><strong>useaitree</strong></div>" +
    "<div class='box'><h1>Maintainer sign in</h1>" +
    "<form method='POST' action='/api/admin/login'>" +
    "<label>Email</label><input type='email' name='email' required>" +
    "<label>Password</label><input type='password' name='password' required>" +
    "<button type='submit'>Sign in</button>" +
    (error ? "<div class='err'>" + error + "</div>" : "") +
    "</form></div></body></html>";
}

function dashboardHTML(d) {
  const row = (cells) => "<tr>" + cells.map(c => "<td>" + c + "</td>").join("") + "</tr>";
  return "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>useaitree Dashboard</title><style>" +
    ":root{--canvas:#f6f8fa;--card:#ffffff;--border:#d1d9e0;--fg:#1f2328;--fg-muted:#59636e;--accent:#0969da;}" +
    "*{box-sizing:border-box;}" +
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--canvas);color:var(--fg);margin:0;padding:0;font-size:14px;}" +
    ".topbar{background:#24292f;color:#fff;padding:0.75rem 1.5rem;display:flex;align-items:center;gap:0.75rem;}" +
    ".topbar .mark{width:22px;height:22px;border-radius:6px;background:linear-gradient(135deg,var(--accent),#54aeff);display:inline-block;}" +
    "main{max-width:1080px;margin:0 auto;padding:1.5rem;}" +
    "h1{font-size:1.4rem;border-bottom:1px solid var(--border);padding-bottom:1rem;margin-top:0;}" +
    "h2{font-size:1rem;margin-top:2rem;background:var(--canvas);padding:0.6rem 0.9rem;border:1px solid var(--border);border-radius:6px 6px 0 0;margin-bottom:0;}" +
    "table{width:100%;border-collapse:collapse;font-size:0.85rem;border:1px solid var(--border);border-top:none;background:var(--card);}" +
    "th,td{text-align:left;padding:0.55rem 0.9rem;border-bottom:1px solid var(--border);}" +
    "th{background:var(--canvas);font-weight:600;color:var(--fg-muted);font-size:0.75rem;text-transform:uppercase;letter-spacing:0.03em;}" +
    "tr:last-child td{border-bottom:none;}" +
    ".stat{display:inline-block;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:1rem 1.5rem;margin-right:0.75rem;margin-bottom:0.75rem;}" +
    ".stat b{display:block;font-size:1.5rem;color:var(--accent);}" +
    "a.download{display:inline-block;margin-top:0.6rem;font-size:0.8rem;color:var(--accent);text-decoration:none;border:1px solid var(--border);padding:0.35rem 0.8rem;border-radius:6px;background:var(--card);font-weight:600;}" +
    "</style></head><body>" +
    "<div class='topbar'><span class='mark'></span><strong>useaitree</strong><a href='/api/admin/logout' style='margin-left:auto;color:#fff;font-size:0.8rem;text-decoration:none;'>Sign out</a></div>" +
    "<main><h1>Dashboard</h1>" +
    "<div class='stat'><b>" + d.totalVisits + "</b>Total logged visits</div>" +
    "<div class='stat'><b>" + d.uniqueBots + "</b>Distinct AI bots seen</div>" +
    "<div class='stat'><b>" + d.docCount + "</b>Published docs</div>" +
    "<h2>Visits by AI bot</h2><table><tr><th>Bot</th><th>Visits</th></tr>" +
    d.botBreakdown.map(r => row([r.matched_bot || "(non-bot / unclassified)", r.count])).join("") + "</table>" +
    "<h2>Most recent visits</h2><table><tr><th>Time</th><th>Path</th><th>Bot</th><th>Country</th></tr>" +
    d.recentVisits.map(r => row([r.timestamp, r.path, r.matched_bot || "-", r.country])).join("") + "</table>" +
    "<h2>Missing / broken links (404s)</h2><table><tr><th>Path</th><th>Times hit</th></tr>" +
    d.missed.map(r => row([r.path, r.count])).join("") + "</table>" +
    "</main></body></html>";
}

function toCSV(rows) {
  if (!rows.length) return "";
  const headers = Object.keys(rows[0]);
  const escape = v => '"' + String(v ?? "").replace(/"/g, '""') + '"';
  return [headers.join(","), ...rows.map(r => headers.map(h => escape(r[h])).join(","))].join("\n");
}

async function sessionHash(ip, ua) {
  const data = new TextEncoder().encode(ip + "|" + ua);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
  return hex.slice(0, 24);
}

export default async function handler(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const ua = request.headers.get("user-agent") || "unknown";
  const ip = request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "unknown";
  const timestamp = new Date().toISOString();
  const startTime = Date.now();

  const knownBots = ["ClaudeBot", "Claude-Web", "GPTBot", "OAI-SearchBot", "PerplexityBot", "Google-Extended", "Bytespider", "CCBot"];
  const matchedBot = knownBots.find(b => ua.includes(b)) || null;

  // --- Admin login page ---
  if (path === "/admin" && request.method === "GET") {
    if (await isAuthenticated(request)) {
      return Response.redirect(new URL("/api/dashboard", request.url), 302);
    }
    return new Response(loginPageHTML(null), { headers: { "content-type": "text/html" } });
  }

  // --- Admin login submission ---
  if (path === "/api/admin/login" && request.method === "POST") {
    const form = await request.formData();
    const email = (form.get("email") || "").toString().trim();
    const password = (form.get("password") || "").toString();
    const success = email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD;

    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    await pool.query(
      "INSERT INTO admin_login_attempts (timestamp, email_attempted, success, ip) VALUES ($1, $2, $3, $4)",
      [timestamp, email, success ? 1 : 0, ip]
    );
    await pool.end();

    if (!success) {
      return new Response(loginPageHTML("Incorrect email or password."), {
        status: 401, headers: { "content-type": "text/html" }
      });
    }

    const token = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const pool2 = new Pool({ connectionString: process.env.DATABASE_URL });
    await pool2.query(
      "INSERT INTO admin_sessions (token, created_at, expires_at) VALUES ($1, $2, $3)",
      [token, timestamp, expiresAt]
    );
    await pool2.end();

    return new Response(null, {
      status: 302,
      headers: {
        "Location": "/api/dashboard",
        "Set-Cookie": `admin_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`
      }
    });
  }

  // --- Admin logout ---
  if (path === "/api/admin/logout") {
    const cookies = parseCookies(request);
    if (cookies["admin_session"]) {
      const pool = new Pool({ connectionString: process.env.DATABASE_URL });
      await pool.query("DELETE FROM admin_sessions WHERE token = $1", [cookies["admin_session"]]);
      await pool.end();
    }
    return new Response(null, {
      status: 302,
      headers: { "Location": "/admin", "Set-Cookie": "admin_session=; Path=/; Max-Age=0" }
    });
  }

  // --- Dashboard ---
  if (path === "/api/dashboard" || path === "/dashboard") {
    if (!(await isAuthenticated(request))) {
      return Response.redirect(new URL("/admin", request.url), 302);
    }

    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    const totalRows = await pool.query("SELECT COUNT(*) as c FROM request_logs");
    const botBreakdown = await pool.query("SELECT matched_bot, COUNT(*) as count FROM request_logs GROUP BY matched_bot ORDER BY count DESC");
    const recentVisits = await pool.query("SELECT timestamp, path, matched_bot, country FROM request_logs ORDER BY timestamp DESC LIMIT 25");
    const missed = await pool.query("SELECT path, COUNT(*) as count FROM missed_requests GROUP BY path ORDER BY count DESC LIMIT 25");
    await pool.end();

    let docCount = "n/a";
    try {
      const manifestRes = await fetch(new URL("/manifest.json", request.url));
      if (manifestRes.ok) docCount = (await manifestRes.json()).docs.length;
    } catch {}

    const html = dashboardHTML({
      totalVisits: totalRows.rows[0]?.c || 0,
      uniqueBots: botBreakdown.rows.filter(r => r.matched_bot).length,
      docCount,
      botBreakdown: botBreakdown.rows,
      recentVisits: recentVisits.rows,
      missed: missed.rows
    });
    return new Response(html, { headers: { "content-type": "text/html" } });
  }

  // --- Export CSVs ---
  if (path === "/api/export/logs" || path === "/export/logs.csv") {
    if (!(await isAuthenticated(request))) {
      return Response.redirect(new URL("/admin", request.url), 302);
    }
    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    const result = await pool.query("SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT 5000");
    await pool.end();
    return new Response(toCSV(result.rows), { headers: { "content-type": "text/csv", "content-disposition": "attachment; filename=useaitree-logs.csv" } });
  }

  if (path === "/api/export/missed" || path === "/export/missed.csv") {
    if (!(await isAuthenticated(request))) {
      return Response.redirect(new URL("/admin", request.url), 302);
    }
    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    const result = await pool.query("SELECT * FROM missed_requests ORDER BY timestamp DESC LIMIT 5000");
    await pool.end();
    return new Response(toCSV(result.rows), { headers: { "content-type": "text/csv", "content-disposition": "attachment; filename=useaitree-missed-links.csv" } });
  }

  // --- Serve static files and log ---
  const staticUrl = new URL(path + url.search, request.url);
  const response = await fetch(staticUrl);
  const durationMs = Date.now() - startTime;

  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  await pool.query(
    `INSERT INTO request_logs (timestamp, path, query_string, user_agent, matched_bot, referrer, country, city, region, ip, method, response_bytes, duration_ms)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
    [timestamp, path, url.search, ua, matchedBot, request.headers.get("referer") || "", "unknown", "unknown", "unknown", ip, request.method, null, durationMs]
  );
  await pool.end();

  const isTrackablePath = path.endsWith(".md") || path === "/" || path === "/llms.txt" || path === "/manifest.json";

  if (matchedBot && isTrackablePath) {
    const hash = await sessionHash(ip, ua);
    const pool2 = new Pool({ connectionString: process.env.DATABASE_URL });
    await pool2.query(
      "INSERT INTO session_events (session_hash, path, timestamp, matched_bot) VALUES ($1, $2, $3, $4)",
      [hash, path, timestamp, matchedBot]
    );
    await pool2.end();

    if (path !== "/llms.txt" && path !== "/manifest.json") {
      const pool3 = new Pool({ connectionString: process.env.DATABASE_URL });
      const recentMapFetch = await pool3.query(
        `SELECT 1 FROM session_events WHERE session_hash = $1 AND (path = '/llms.txt' OR path = '/manifest.json') AND timestamp >= $2 LIMIT 1`,
        [hash, new Date(Date.now() - 3 * 60 * 1000).toISOString()]
      );
      await pool3.end();

      if (recentMapFetch.rows.length > 0) {
        const pool4 = new Pool({ connectionString: process.env.DATABASE_URL });
        await pool4.query(
          "INSERT INTO map_selections (session_hash, selected_path, timestamp, matched_bot) VALUES ($1, $2, $3, $4)",
          [hash, path, timestamp, matchedBot]
        );
        await pool4.end();
      }
    }

    if (path.startsWith("/skills/") && path !== "/skills/index.md") {
      const pool5 = new Pool({ connectionString: process.env.DATABASE_URL });
      const recentIndexFetch = await pool5.query(
        `SELECT 1 FROM session_events WHERE session_hash = $1 AND path = '/skills/index.md' AND timestamp >= $2 LIMIT 1`,
        [hash, new Date(Date.now() - 3 * 60 * 1000).toISOString()]
      );
      await pool5.end();

      if (recentIndexFetch.rows.length > 0) {
        const pool6 = new Pool({ connectionString: process.env.DATABASE_URL });
        await pool6.query(
          "INSERT INTO skill_selections (session_hash, selected_skill, timestamp, matched_bot) VALUES ($1, $2, $3, $4)",
          [hash, path, timestamp, matchedBot]
        );
        await pool6.end();
      }
    }
  }

  if (response.status === 404) {
    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    await pool.query(
      "INSERT INTO missed_requests (timestamp, path, user_agent) VALUES ($1, $2, $3)",
      [timestamp, path, ua]
    );
    await pool.end();
  }

  return response;
}
