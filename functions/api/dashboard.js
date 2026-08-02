// functions/api/dashboard.js

import { jsonResponse, errorResponse, isReviewer } from './_utils';

export async function onRequest(context) {
  const { env } = context;

  if (context.request.method.toUpperCase() !== 'GET') {
    return errorResponse('Method not allowed', 405);
  }

  const reviewer = isReviewer(context.data?.user);

  try {
    const metricsRow = await env.DB.prepare(
      `SELECT
         COUNT(*) AS total_requests,
         COALESCE(SUM(resp_bytes), 0) AS total_bytes,
         COALESCE(AVG(ttfb_ms), 0) AS avg_ttfb,
         SUM(CASE WHEN cache_status = 'HIT' THEN 1 ELSE 0 END) AS cache_hits,
         SUM(CASE WHEN bot_category != 'Human' THEN 1 ELSE 0 END) AS bot_requests,
         SUM(CASE WHEN status = 404 THEN 1 ELSE 0 END) AS error_count
       FROM request_events
       WHERE ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-24 hours')`
    ).first();

    const totalRequests = metricsRow?.total_requests || 0;
    const totalBytes = metricsRow?.total_bytes || 0;
    const avgTtfb = metricsRow?.avg_ttfb || 0;
    const cacheHits = metricsRow?.cache_hits || 0;
    const botRequests = metricsRow?.bot_requests || 0;
    const errorCount = metricsRow?.error_count || 0;

    const status = totalRequests < 50 ? 'SIMULATION' : 'LIVE';

    let regionalDemand = [];
    if (reviewer) {
      const { results } = await env.DB.prepare(
        `SELECT
           country, city, path, bot_category,
           COUNT(*) AS hits,
           COALESCE(SUM(resp_bytes), 0) AS bytes,
           COALESCE(AVG(ttfb_ms), 0) AS avg_ttfb
         FROM request_events
         WHERE ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-7 days')
         GROUP BY country, city, path, bot_category
         ORDER BY hits DESC
         LIMIT 200`
      ).all();
      regionalDemand = results || [];
    }

    const bots = (await env.DB.prepare(`
      SELECT bot_category, COUNT(*) AS requests
      FROM request_events
      WHERE ts > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-24 hours')
      GROUP BY bot_category
      ORDER BY requests DESC
    `).all()).results || [];

    // Audit log only for reviewers (admin/maintainer) — everyone else gets an empty list
    let logs = [];
    if (reviewer) {
      logs = (await env.DB.prepare(
        'SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 50'
      ).all()).results || [];
    }

    return jsonResponse({
      status,
      measured: [
        { name: 'Total Requests', value: totalRequests, unit: '', formula: 'COUNT(*)' },
        { name: 'Bytes Served', value: (totalBytes / 1024).toFixed(1), unit: 'KB', formula: 'SUM(resp_bytes)/1024' },
        { name: 'Avg TTFB', value: avgTtfb.toFixed(1), unit: 'ms', formula: 'AVG(ttfb_ms)' },
      ],
      derived: [
        { name: 'Cache Hit Rate', value: totalRequests > 0 ? ((cacheHits / totalRequests) * 100).toFixed(1) : 0, unit: '%', formula: "SUM(HIT)/COUNT(*)×100" },
        { name: 'Bot Share', value: totalRequests > 0 ? ((botRequests / totalRequests) * 100).toFixed(1) : 0, unit: '%', formula: "SUM(bot!=Human)/COUNT(*)×100" },
        { name: 'Error Rate', value: totalRequests > 0 ? ((errorCount / totalRequests) * 100).toFixed(1) : 0, unit: '%', formula: "SUM(status=404)/COUNT(*)×100" },
      ],
      modeled: [
        { name: 'Tokens Served', value: Math.round(totalBytes / 4), unit: 'Est', formula: 'bytes÷4', disclosure: 'Standardized 4-byte approx.' },
        { name: 'CO₂ Per Answer', value: totalRequests > 0 ? (((totalBytes / totalRequests) * 0.0000000015 * 490)).toFixed(4) : 0, unit: 'gCO₂', formula: 'avg_bytes×energy×grid', disclosure: 'IEA modeled estimate.' },
      ],
      regional: regionalDemand.map(r => ({
        country: r.country,
        city: r.city,
        path: r.path,
        bot_category: r.bot_category,
        requests: r.hits,
        bytes: r.bytes,
      })),
      bots,
      logs,
    });
  } catch (err) {
    return errorResponse('Dashboard query failed: ' + err.message, 500);
  }
}
