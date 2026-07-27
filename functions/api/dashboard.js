export async function onRequest(context) {
  const logs = (await context.env.DB.prepare(`SELECT * FROM audit_log ORDER BY id DESC LIMIT 50`).all()).results;
  const rawMetrics = (await context.env.DB.prepare(`SELECT endpoint_group, SUM(req_count) as req_count, SUM(sum_bytes) as sum_bytes, SUM(sum_ttfb_ms) as sum_ttfb, SUM(cache_hits) as cache_hits, SUM(cache_misses) as cache_misses, SUM(bot_hits) as bot_hits FROM telemetry_windows GROUP BY endpoint_group`).all()).results;

  const totalRequests = rawMetrics.reduce((s, m) => s + m.req_count, 0);
  const totalBytes = rawMetrics.reduce((s, m) => s + m.sum_bytes, 0);
  const totalTtfb = rawMetrics.reduce((s, m) => s + m.sum_ttfb, 0);
  const totalCacheHits = rawMetrics.reduce((s, m) => s + m.cache_hits, 0);
  const totalBotHits = rawMetrics.reduce((s, m) => s + m.bot_hits, 0);
  const isLive = totalRequests > 100;

  const metrics = {
    status: isLive ? 'LIVE' : 'SIMULATION — SCHEMA PREVIEW',
    measured: [
      { name: 'Total Requests', value: totalRequests, unit: '', formula: 'COUNT(requests)' },
      { name: 'Bytes Served', value: (totalBytes / 1024).toFixed(2), unit: 'KB', formula: 'SUM(response_bytes)' },
      { name: 'Avg TTFB', value: totalRequests > 0 ? (totalTtfb / totalRequests).toFixed(1) : 0, unit: 'ms', formula: 'AVG(response_start - request_start)' }
    ],
    derived: [
      { name: 'Cache Hit Rate', value: totalRequests > 0 ? ((totalCacheHits / totalRequests) * 100).toFixed(2) : 0, unit: '%', formula: "COUNT(cache_status='HIT') / COUNT(*) * 100" },
      { name: 'Bot Share', value: totalRequests > 0 ? ((totalBotHits / totalRequests) * 100).toFixed(2) : 0, unit: '%', formula: 'COUNT(matched_bot) / COUNT(*) * 100' }
    ],
    modeled: [
      { name: 'Tokens Served', value: Math.round(totalBytes / 4), unit: 'Est', formula: 'Bytes / 4', disclosure: 'Standardized approximation.' },
      { name: 'CO₂ Per Answer', value: (totalBytes * 0.0000000015 * 490).toFixed(4), unit: 'gCO₂', formula: 'Bytes × Energy coeff × Grid carbon', disclosure: 'IEA global average estimate.' }
    ]
  };
  return new Response(JSON.stringify({ logs, metrics }), { headers: { 'Content-Type': 'application/json' } });
}
