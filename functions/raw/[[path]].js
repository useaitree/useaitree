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
    if (chain[i].is_full_snapshot) {
      content = chain[i].content;
    } else {
      const patches = dmp.patch_fromText(chain[i].patch);
      content = dmp.patch_apply(patches, content)[0];
    }
  }
  return content;
}

export async function onRequest(context) {
  const filePath = '/' + context.params.path.join('/');
  
  if (filePath.includes('..') || !/^[a-zA-Z0-9\-_\/\.]+$/.test(filePath)) return new Response('Bad Request', { status: 400 });

  const cache = caches.default;
  const cacheKey = new Request(context.request.url, context.request);
  let response = await cache.match(cacheKey);
  if (response) return response;

  const file = await context.env.DB.prepare(`SELECT * FROM files WHERE path = ? AND status = 'approved'`).bind(filePath).first();
  if (!file || !file.active_version_id) return new Response('Not found', { status: 404 });

  try {
    const content = await reconstructContent(context.env, file.active_version_id);

    response = new Response(content, {
      headers: { 'Content-Type': 'text/markdown; charset=utf-8', 'Cache-Control': 'public, max-age=3600' }
    });

    context.waitUntil(cache.put(cacheKey, response.clone()));
    return response;
  } catch (e) {
    return new Response('Reconstruction Error', { status: 500 });
  }
}
