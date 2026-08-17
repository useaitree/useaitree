// functions/api/auth/github-callback.js
import { buildRedirectUri, createSessionCookie, upsertOAuthUser } from '../_utils';

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const cookieState = (request.headers.get('cookie') || '').match(/(?:^|;\s*)oauth_state=([^;]+)/)?.[1];

  if (!code || !state || state !== cookieState) {
    return Response.redirect(buildRedirectUri(request, '/work?auth_error=state_mismatch'), 302);
  }

  const redirectUri = buildRedirectUri(request, '/api/auth/github-callback');

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      code,
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      redirect_uri: redirectUri
    })
  });
  if (!tokenRes.ok) {
    return Response.redirect(buildRedirectUri(request, '/work?auth_error=token_exchange_failed'), 302);
  }
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) {
    return Response.redirect(buildRedirectUri(request, '/work?auth_error=no_access_token'), 302);
  }

  const headers = {
    Authorization: `Bearer ${tokenData.access_token}`,
    'User-Agent': 'useaitree-app',
    Accept: 'application/vnd.github+json'
  };

  const userRes = await fetch('https://api.github.com/user', { headers });
  if (!userRes.ok) {
    return Response.redirect(buildRedirectUri(request, '/work?auth_error=userinfo_failed'), 302);
  }
  const profile = await userRes.json();

  // GitHub only returns a public email if one is set; fetch the verified primary email explicitly.
  let email = profile.email;
  if (!email) {
    const emailsRes = await fetch('https://api.github.com/user/emails', { headers });
    if (emailsRes.ok) {
      const emails = await emailsRes.json();
      const primary = emails.find(e => e.primary && e.verified) || emails.find(e => e.verified);
      email = primary?.email || null;
    }
  }
  if (!email) {
    return Response.redirect(buildRedirectUri(request, '/work?auth_error=no_email'), 302);
  }

  const user = await upsertOAuthUser(env, {
    provider: 'github',
    providerId: String(profile.id),
    email: email.toLowerCase()
  });

  const cookie = await createSessionCookie(env, user.id);
  const clearState = 'oauth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';

  return new Response(null, {
    status: 302,
    headers: {
      Location: buildRedirectUri(request, '/work'),
      'Set-Cookie': cookie
    }
  });
}
