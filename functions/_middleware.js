// functions/_middleware.js
//
// Zero CLI setup. Connect this repo to Cloudflare Pages via the dashboard
// and this runs automatically on every request.
//
// SECURITY: /dashboard and /export/* require logging in at /admin with an
// email + password. The actual password is NEVER stored in this file or
// anywhere in this public repo -- it's read from Cloudflare's encrypted
// Environment Variables (ADMIN_EMAIL, ADMIN_PASSWORD), which you set once
// in the Cloudflare dashboard during setup. This file only checks a
// submitted login against those two values, then issues a short-lived
// session token stored in D1.

function parseCookies(request) {
  const header = request.headers.get("cookie") || "";
  const out = {};
  header.split(";").forEach(part => {
    const [k, ...v] = part.trim().split("=");
    if (k) out[k] = v.join("=");
  });
  return out;
}

async function isAuthenticated(env, request) {
  const cookies = parseCookies(request);
  const token = cookies["admin_session"];
  if (!token) return false;
  const row = await env.DB.prepare(
    "SELECT expires_at FROM admin_sessions WHERE token = ?"
  ).bind(token).first().catch(() => null);
  if (!row) return false;
  return new Date(row.expires_at) > new Date();
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
    "<form method='POST' action='/admin/login'>" +
    "<label>Email</label><input type='email' name='email' required>" +
    "<label>Password</label><input type='password' name='password' required>" +
    "<button type='submit'>Sign in</button>" +
    (error ? "<div class='err'>" + error + "</div>" : "") +
    "</form></div></body></html>";
}

async function sessionHash(ip, ua) {
  const data = new TextEncoder().encode(ip + "|" + ua);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
  return hex.slice(0, 24);
}

async function pathLinksTo(env, fromPath, toPath) {
  try {
    const res = await env.ASSETS.fetch(new Request("https://internal" + fromPath));
    if (!res.ok) return false;
    const text = await res.text();
    return text.includes(toPath);
  } catch {
    return false;
  }
}

async function computeConfusionScores(env) {
  const windowStart = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const { results: events } = await env.DB.prepare(
    `SELECT session_hash, path, timestamp FROM session_events WHERE timestamp >= ? ORDER BY session_hash, timestamp ASC`
  ).bind(windowStart).all();

  const sessions = {};
  for (const e of events) {
    if (!sessions[e.session_hash]) sessions[e.session_hash] = [];
    sessions[e.session_hash].push(e);
  }

  const repeatCounts = {}, bounceCounts = {}, totalSessionsPerPath = {};
  for (const hash in sessions) {
    const evs = sessions[hash];
    for (const p of new Set(evs.map(e => e.path))) {
      totalSessionsPerPath[p] = (totalSessionsPerPath[p] || 0) + 1;
    }
    for (let i = 0; i < evs.length; i++) {
      const { path, timestamp } = evs[i];
      for (let j = i + 1; j < evs.length; j++) {
        if ((new Date(evs[j].timestamp) - new Date(timestamp)) / 60000 > 10) break;
        if (evs[j].path === path) { repeatCounts[path] = (repeatCounts[path] || 0) + 1; break; }
      }
      for (let j = i + 1; j < evs.length; j++) {
        if ((new Date(evs[j].timestamp) - new Date(timestamp)) / 60000 > 5) break;
        if (evs[j].path !== path) {
          if (await pathLinksTo(env, path, evs[j].path)) bounceCounts[path] = (bounceCounts[path] || 0) + 1;
          break;
        }
      }
    }
  }

  const allPaths = new Set([...Object.keys(repeatCounts), ...Object.keys(bounceCounts), ...Object.keys(totalSessionsPerPath)]);
  return [...allPaths].map(path => {
    const repeats = repeatCounts[path] || 0, bounces = bounceCounts[path] || 0, total = totalSessionsPerPath[path] || 1;
    return { path, repeat_fetch_count: repeats, bounce_count: bounces, total_sessions: total, confusion_score: +((repeats + bounces) / total).toFixed(3) };
  }).sort((a, b) => b.confusion_score - a.confusion_score);
}

async function suggestMissingLinks(env) {
  const windowStart = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const { results: events } = await env.DB.prepare(
    `SELECT session_hash, path, timestamp FROM session_events WHERE timestamp >= ? ORDER BY session_hash, timestamp ASC`
  ).bind(windowStart).all();

  const sessions = {};
  for (const e of events) {
    if (!sessions[e.session_hash]) sessions[e.session_hash] = [];
    sessions[e.session_hash].push(e);
  }

  const pairCounts = {};
  for (const hash in sessions) {
    const evs = sessions[hash];
    for (let i = 0; i < evs.length - 1; i++) {
      const a = evs[i], b = evs[i + 1];
      if (a.path === b.path) continue;
      if ((new Date(b.timestamp) - new Date(a.timestamp)) / 60000 > 5) continue;
      if (await pathLinksTo(env, a.path, b.path)) continue;
      const key = a.path + " -> " + b.path;
      pairCounts[key] = (pairCounts[key] || 0) + 1;
    }
  }

  return Object.entries(pairCounts)
    .filter(([, count]) => count > 1)
    .sort((a, b) => b[1] - a[1])
    .map(([pair, count]) => ({ pair, sessions_observed: count }));
}

function toCSV(rows) {
  if (!rows.length) return "";
  const headers = Object.keys(rows[0]);
  const escape = v => '"' + String(v ?? "").replace(/"/g, '""') + '"';
  return [headers.join(","), ...rows.map(r => headers.map(h => escape(r[h])).join(","))].join("\n");
}

function dashboardHTML(d) {
  const row = (cells) => "<tr>" + cells.map(c => "<td>" + c + "</td>").join("") + "</tr>";
  return "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>useaitree Dashboard</title><style>" +
    ":root{--canvas:#f6f8fa;--card:#ffffff;--border:#d1d9e0;--fg:#1f2328;--fg-muted:#59636e;--accent:#0969da;--accent-bg:#ddf4ff;}" +
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
    "<div class='topbar'><span class='mark'></span><strong>useaitree</strong><a href='/admin/logout' style='margin-left:auto;color:#fff;font-size:0.8rem;text-decoration:none;'>Sign out</a></div>" +
    "<main><h1>Dashboard</h1>" +
    "<div class='stat'><b>" + d.totalVisits + "</b>Total logged visits</div>" +
    "<div class='stat'><b>" + d.uniqueBots + "</b>Distinct AI bots seen</div>" +
    "<div class='stat'><b>" + d.docCount + "</b>Published docs</div>" +
    "<div class='stat'><b>" + d.last7 + " / " + d.prev7 + "</b>Visits: last 7 days / previous 7 days</div>" +
    "<div class='stat'><b>" + d.returningSessions + "</b>Sessions returning on a later day</div>" +
    "<div class='stat'><b>" + d.avgMs + "ms</b>Avg response time (agent traffic)</div>" +
    "<div class='stat'><b>" + d.avgBytes + " bytes</b>Avg response size (agent traffic)</div>" +
    "<h2>Visits by AI bot</h2><table><tr><th>Bot</th><th>Visits</th></tr>" +
    d.botBreakdown.map(r => row([r.matched_bot || "(non-bot / unclassified)", r.count])).join("") + "</table>" +
    "<a class='download' href='/export/logs.csv'>Download full raw log (CSV)</a>" +
    "<h2>Most recent visits</h2><table><tr><th>Time</th><th>Path</th><th>Bot</th><th>Country</th><th>Org (ASN)</th></tr>" +
    d.recentVisits.map(r => row([r.timestamp, r.path, r.matched_bot || "-", r.country, r.as_organization || "-"])).join("") + "</table>" +
    "<h2>Missing / broken links (404s)</h2><table><tr><th>Path</th><th>Times hit</th></tr>" +
    d.missed.map(r => row([r.path, r.count])).join("") + "</table>" +
    "<a class='download' href='/export/missed.csv'>Download missed-links (CSV)</a>" +
    "<h2>Confusion scores</h2><p style='font-size:0.85rem;color:#555;'>Only trust scores with 10+ sessions.</p>" +
    "<table><tr><th>Path</th><th>Repeats</th><th>Bounces</th><th>Sessions</th><th>Score</th></tr>" +
    d.confusion.map(r => row([r.path, r.repeat_fetch_count, r.bounce_count, r.total_sessions, r.confusion_score])).join("") + "</table>" +
    "<h2>Suggested missing cross-links</h2><table><tr><th>Pattern</th><th>Times observed</th></tr>" +
    d.missingLinks.map(r => row([r.pair, r.sessions_observed])).join("") + "</table>" +
    "<h2>Most-chosen paths from the site map</h2><p style='font-size:0.85rem;color:#555;'>Which doc agents picked right after reading llms.txt/manifest.json.</p>" +
    "<table><tr><th>Path</th><th>Times chosen</th></tr>" +
    d.mapSelections.map(r => row([r.selected_path, r.count])).join("") + "</table>" +
    "<h2>Skill files chosen</h2><p style='font-size:0.85rem;color:#555;'>Which skill file agents picked after reading /skills/index.md -- tells you if skill-triage is working.</p>" +
    "<table><tr><th>Skill</th><th>Times chosen</th></tr>" +
    d.skillSelections.map(r => row([r.selected_skill, r.count])).join("") + "</table>" +
    "<h2>Admin login attempts</h2><p style='font-size:0.85rem;color:#555;'>Security log -- watch for repeated failed attempts.</p>" +
    "<table><tr><th>Time</th><th>Email attempted</th><th>Result</th><th>IP</th></tr>" +
    d.recentLoginAttempts.map(r => row([r.timestamp, r.email_attempted, r.success ? "✅ success" : "❌ failed", r.ip])).join("") + "</table>" +
    "</main></body></html>";
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const ua = request.headers.get("user-agent") || "unknown";
  const referrer = request.headers.get("referer") || "";
  const acceptLanguage = request.headers.get("accept-language") || "";
  const acceptHeader = request.headers.get("accept") || "";
  const originHeader = request.headers.get("origin") || "";
  const secFetchSite = request.headers.get("sec-fetch-site") || "";
  const rayId = request.headers.get("cf-ray") || "";
  const cf = request.cf || {};
  const country = cf.country || "unknown";
  const continent = cf.continent || "unknown";
  const city = cf.city || "unknown";
  const region = cf.region || "unknown";
  const postalCode = cf.postalCode || "unknown";
  const timezone = cf.timezone || "unknown";
  const latitude = cf.latitude || "";
  const longitude = cf.longitude || "";
  const asn = cf.asn ? String(cf.asn) : "unknown";
  const asOrg = cf.asOrganization || "unknown";
  const httpProtocol = cf.httpProtocol || "unknown";
  const tlsVersion = cf.tlsVersion || "unknown";
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const timestamp = new Date().toISOString();
  const startTime = Date.now();

  const knownBots = ["ClaudeBot", "Claude-Web", "GPTBot", "OAI-SearchBot", "PerplexityBot", "Google-Extended", "Bytespider", "CCBot"];
  const matchedBot = knownBots.find(b => ua.includes(b)) || null;

  // --- Admin login page ---
  if (url.pathname === "/admin" && request.method === "GET") {
    if (await isAuthenticated(env, request)) {
      return Response.redirect(url.origin + "/dashboard", 302);
    }
    return new Response(loginPageHTML(null), { headers: { "content-type": "text/html" } });
  }

  // --- Admin login submission ---
  if (url.pathname === "/admin/login" && request.method === "POST") {
    const form = await request.formData();
    const email = (form.get("email") || "").toString().trim();
    const password = (form.get("password") || "").toString();
    const success = email === env.ADMIN_EMAIL && password === env.ADMIN_PASSWORD;

    context.waitUntil(
      env.DB.prepare(
        "INSERT INTO admin_login_attempts (timestamp, email_attempted, success, ip) VALUES (?, ?, ?, ?)"
      ).bind(timestamp, email, success ? 1 : 0, ip).run().catch(() => {})
    );

    if (!success) {
      return new Response(loginPageHTML("Incorrect email or password."), {
        status: 401, headers: { "content-type": "text/html" }
      });
    }

    const token = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    await env.DB.prepare(
      "INSERT INTO admin_sessions (token, created_at, expires_at) VALUES (?, ?, ?)"
    ).bind(token, timestamp, expiresAt).run();

    return new Response(null, {
      status: 302,
      headers: {
        "Location": url.origin + "/dashboard",
        "Set-Cookie": `admin_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`
      }
    });
  }

  // --- Admin logout ---
  if (url.pathname === "/admin/logout") {
    const cookies = parseCookies(request);
    if (cookies["admin_session"]) {
      context.waitUntil(
        env.DB.prepare("DELETE FROM admin_sessions WHERE token = ?").bind(cookies["admin_session"]).run().catch(() => {})
      );
    }
    return new Response(null, {
      status: 302,
      headers: { "Location": url.origin + "/admin", "Set-Cookie": "admin_session=; Path=/; Max-Age=0" }
    });
  }

  // --- Everything under /dashboard and /export/* requires login ---
  if (url.pathname === "/dashboard" || url.pathname.startsWith("/export/")) {
    if (!(await isAuthenticated(env, request))) {
      return Response.redirect(url.origin + "/admin", 302);
    }
  }

  if (url.pathname === "/dashboard") {
    const [{ results: totalRows }, { results: botBreakdown }, { results: recentVisits }, { results: missed },
           { results: last7Rows }, { results: prev7Rows }] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) as c FROM request_logs").all(),
      env.DB.prepare("SELECT matched_bot, COUNT(*) as count FROM request_logs GROUP BY matched_bot ORDER BY count DESC").all(),
      env.DB.prepare("SELECT timestamp, path, matched_bot, country, as_organization FROM request_logs ORDER BY timestamp DESC LIMIT 25").all(),
      env.DB.prepare("SELECT path, COUNT(*) as count FROM missed_requests GROUP BY path ORDER BY count DESC LIMIT 25").all(),
      env.DB.prepare("SELECT COUNT(*) as c FROM request_logs WHERE timestamp >= ?").bind(new Date(Date.now() - 7*24*60*60*1000).toISOString()).all(),
      env.DB.prepare("SELECT COUNT(*) as c FROM request_logs WHERE timestamp >= ? AND timestamp < ?")
        .bind(new Date(Date.now() - 14*24*60*60*1000).toISOString(), new Date(Date.now() - 7*24*60*60*1000).toISOString()).all()
    ]);
    const confusion = await computeConfusionScores(env);
    const missingLinks = await suggestMissingLinks(env);
    const { results: mapSelections } = await env.DB.prepare(
      "SELECT selected_path, COUNT(*) as count FROM map_selections GROUP BY selected_path ORDER BY count DESC LIMIT 25"
    ).all();
    const { results: returningRows } = await env.DB.prepare(
      `SELECT COUNT(*) as returning FROM (
         SELECT session_hash FROM session_events GROUP BY session_hash HAVING COUNT(DISTINCT date(timestamp)) > 1
       )`
    ).all().catch(() => ({ results: [{ returning: 0 }] }));
    const { results: perfRows } = await env.DB.prepare(
      "SELECT AVG(duration_ms) as avg_ms, AVG(response_bytes) as avg_bytes FROM request_logs WHERE matched_bot IS NOT NULL"
    ).all();
    const { results: skillSelections } = await env.DB.prepare(
      "SELECT selected_skill, COUNT(*) as count FROM skill_selections GROUP BY selected_skill ORDER BY count DESC LIMIT 25"
    ).all().catch(() => ({ results: [] }));
    const { results: recentLoginAttempts } = await env.DB.prepare(
      "SELECT timestamp, email_attempted, success, ip FROM admin_login_attempts ORDER BY timestamp DESC LIMIT 20"
    ).all().catch(() => ({ results: [] }));

    let docCount = "n/a";
    try {
      const manifestRes = await env.ASSETS.fetch(new Request("https://internal/manifest.json"));
      if (manifestRes.ok) docCount = (await manifestRes.json()).docs.length;
    } catch {}

    const uniqueBots = botBreakdown.filter(r => r.matched_bot).length;

    const html = dashboardHTML({
      totalVisits: totalRows[0]?.c || 0,
      uniqueBots, docCount,
      last7: last7Rows[0]?.c || 0, prev7: prev7Rows[0]?.c || 0,
      returningSessions: returningRows[0]?.returning || 0,
      avgMs: perfRows[0]?.avg_ms ? Math.round(perfRows[0].avg_ms) : 0,
      avgBytes: perfRows[0]?.avg_bytes ? Math.round(perfRows[0].avg_bytes) : 0,
      botBreakdown, recentVisits, missed,
      confusion: confusion.slice(0, 25),
      missingLinks: missingLinks.slice(0, 25),
      mapSelections,
      skillSelections,
      recentLoginAttempts
    });
    return new Response(html, { headers: { "content-type": "text/html" } });
  }

  if (url.pathname === "/export/logs.csv") {
    const { results } = await env.DB.prepare("SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT 5000").all();
    return new Response(toCSV(results), { headers: { "content-type": "text/csv", "content-disposition": "attachment; filename=useaitree-logs.csv" } });
  }

  if (url.pathname === "/export/missed.csv") {
    const { results } = await env.DB.prepare("SELECT * FROM missed_requests ORDER BY timestamp DESC LIMIT 5000").all();
    return new Response(toCSV(results), { headers: { "content-type": "text/csv", "content-disposition": "attachment; filename=useaitree-missed-links.csv" } });
  }

  // --- Normal request path: serve the file, then log everything ---
  const response = await next();
  const durationMs = Date.now() - startTime;
  const responseBytes = response.headers.get("content-length");
  const cacheStatus = response.headers.get("cf-cache-status") || "unknown";

  context.waitUntil(
    env.DB.prepare(
      `INSERT INTO request_logs
        (timestamp, path, query_string, user_agent, matched_bot, referrer, country, continent,
         city, region, postal_code, timezone, latitude, longitude, ip,
         asn, as_organization, http_protocol, tls_version, accept_language, accept_header,
         origin_header, sec_fetch_site, cache_status, ray_id, method, response_bytes, duration_ms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      timestamp, url.pathname, url.search, ua, matchedBot, referrer, country, continent,
      city, region, postalCode, timezone, String(latitude), String(longitude), ip,
      asn, asOrg, httpProtocol, tlsVersion, acceptLanguage, acceptHeader,
      originHeader, secFetchSite, cacheStatus, rayId, request.method,
      responseBytes ? parseInt(responseBytes) : null, durationMs
    ).run().catch(() => {})
  );

  const isTrackablePath = url.pathname.endsWith(".md") || url.pathname === "/" ||
    url.pathname === "/llms.txt" || url.pathname === "/manifest.json";

  if (matchedBot && isTrackablePath) {
    context.waitUntil((async () => {
      const hash = await sessionHash(ip, ua);
      await env.DB.prepare(
        "INSERT INTO session_events (session_hash, path, timestamp, matched_bot) VALUES (?, ?, ?, ?)"
      ).bind(hash, url.pathname, timestamp, matchedBot).run().catch(() => {});

      const isMapPath = url.pathname === "/llms.txt" || url.pathname === "/manifest.json";
      if (!isMapPath) {
        const recentMapFetch = await env.DB.prepare(
          `SELECT 1 FROM session_events
           WHERE session_hash = ? AND (path = '/llms.txt' OR path = '/manifest.json')
             AND timestamp >= ?
           LIMIT 1`
        ).bind(hash, new Date(Date.now() - 3 * 60 * 1000).toISOString()).first().catch(() => null);

        if (recentMapFetch) {
          await env.DB.prepare(
            "INSERT INTO map_selections (session_hash, selected_path, timestamp, matched_bot) VALUES (?, ?, ?, ?)"
          ).bind(hash, url.pathname, timestamp, matchedBot).run().catch(() => {});
        }
      }

      // Skill-selection tracking: if this session read /skills/index.md
      // and then fetched a specific skill file shortly after, log which
      // one -- tells us whether the skill-triage design is working.
      const isSkillFile = url.pathname.startsWith("/skills/") && url.pathname !== "/skills/index.md";
      if (isSkillFile) {
        const recentIndexFetch = await env.DB.prepare(
          `SELECT 1 FROM session_events WHERE session_hash = ? AND path = '/skills/index.md' AND timestamp >= ? LIMIT 1`
        ).bind(hash, new Date(Date.now() - 3 * 60 * 1000).toISOString()).first().catch(() => null);
        if (recentIndexFetch) {
          await env.DB.prepare(
            "INSERT INTO skill_selections (session_hash, selected_skill, timestamp, matched_bot) VALUES (?, ?, ?, ?)"
          ).bind(hash, url.pathname, timestamp, matchedBot).run().catch(() => {});
        }
      }
    })());
  }

  if (response.status === 404) {
    context.waitUntil(
      env.DB.prepare("INSERT INTO missed_requests (timestamp, path, user_agent) VALUES (?, ?, ?)")
        .bind(timestamp, url.pathname, ua).run().catch(() => {})
    );
  }

  return response;
}
