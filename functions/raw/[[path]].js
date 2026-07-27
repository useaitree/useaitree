import DiffMatchPatch from 'diff-match-patch';
const dmp = new DiffMatchPatch();

const PRIVACY_MD = `# Privacy Policy (DPDP Act, 2023 Compliant)

**Effective Date:** July 28, 2026
**Administrator:** Kumar Aryan Das (useaitreelabs@gmail.com | +91 8249597632)

## 1.1 Zero PII Architecture
useaitree is engineered to collect zero Personally Identifiable Information (PII). This is a technical constraint, not merely a policy choice.
- No Cookies: We do not set tracking, analytics, or session cookies for visitors or bots.
- No Accounts Required: Reading content, fetching /llms.txt, or browsing the public site requires no login.
- No Third-Party Trackers: We load zero external scripts, fonts, or analytics pixels.

## 1.2 What We Actually Collect (Telemetry)
When you or an AI agent visits useaitree, our edge middleware captures only aggregate network metadata:
- IP Address: Immediately hashed using SHA-256 + truncated. The raw IP is never written to any database.
- Session Identity: A non-reversible hash. This cannot be reversed to identify an individual.
- Network Metadata: Country, City, ASN (Cloudflare headers).
- Request Data: Path fetched, response size, cache status, bot classification.

## 1.3 Data Retention
- Analytics Telemetry: Automatically deleted after 90 days.
- Audit Logs: Retained for 24 months for security.
- Passwords: Stored as PBKDF2-HMAC-SHA256 hashes.

## 1.4 Your Rights
Since we store no PII, there is no personal data to access or delete. If you have a contributor account, contact the administrator for deletion.`;

const TERMS_MD = `# Terms of Usage

## 2.1 Content Licensing
- All published markdown content on useaitree is licensed under the MIT License.
- The platform codebase is also MIT Licensed.
- Trademarks: The name "useaitree" remains the property of Kumar Aryan Das.

## 2.2 Contributor Submissions
By submitting any markdown file to useaitree:
1. You grant useaitree an exclusive, irrevocable right to use, modify, publish, or delete the content.
2. You warrant that you have the legal right to submit the content.
3. You acknowledge the Administration reserves the exclusive right to delete or alter content to maintain AI knowledge base integrity.
4. All accepted submissions are automatically licensed under MIT.

## 2.3 Acceptable Use
You agree not to:
- Reverse-engineer session hashes.
- Submit malicious markdown (XSS, phishing).
- Impersonate AI bots to manipulate analytics.
- Overload infrastructure with automated scraping.

## 2.4 Disclaimer
useaitree is provided "AS IS". We make no guarantees about the completeness or reliability of content.

## 2.5 Grievance Redressal
Contact: Kumar Aryan Das (useaitreelabs@gmail.com | +91 8249597632). We commit to acknowledging grievances within 72 hours.`;

export async function onRequest(context) {
  const filePath = '/' + context.params.path.join('/');
  
  // Serve legal docs directly from code to avoid DB bloat
  if (filePath === '/legal/privacy.md') return new Response(PRIVACY_MD, { headers: { 'Content-Type': 'text/markdown; charset=utf-8' } });
  if (filePath === '/legal/terms.md') return new Response(TERMS_MD, { headers: { 'Content-Type': 'text/markdown; charset=utf-8' } });
  
  if (filePath.includes('..') || !/^[a-zA-Z0-9\-_\/\.]+$/.test(filePath)) return new Response('Bad Request', { status: 400 });

  const cache = caches.default;
  const cacheKey = new Request(context.request.url, context.request);
  let response = await cache.match(cacheKey);
  if (response) return response;

  const file = await context.env.DB.prepare(`SELECT * FROM files WHERE path = ? AND status = 'approved'`).bind(filePath).first();
  if (!file || !file.active_version_id) return new Response('Not found', { status: 404 });

  try {
    let currentVersion = await context.env.DB.prepare(`SELECT * FROM file_versions WHERE id = ?`).bind(file.active_version_id).first();
    const chain = [currentVersion];
    while (currentVersion && !currentVersion.is_full_snapshot) {
      currentVersion = await context.env.DB.prepare(`SELECT * FROM file_versions WHERE id = ?`).bind(currentVersion.base_version_id).first();
      if (!currentVersion) throw new Error('Missing snapshot');
      chain.push(currentVersion);
    }
    chain.reverse();
    let content = chain[0].content;
    for (let i = 1; i < chain.length; i++) {
      if (chain[i].is_full_snapshot) content = chain[i].content;
      else {
        const patches = dmp.patch_fromText(chain[i].patch);
        content = dmp.patch_apply(patches, content)[0];
      }
    }

    response = new Response(content, { headers: { 'Content-Type': 'text/markdown; charset=utf-8', 'Cache-Control': 'public, max-age=3600' } });
    context.waitUntil(cache.put(cacheKey, response.clone()));
    return response;
  } catch (e) { return new Response('Reconstruction Error', { status: 500 }); }
}
