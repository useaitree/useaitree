// functions/api/auth/google-callback.js
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

  const redirectUri = buildRedirectUri(request, '/api/auth/google-callback');

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    })
  });
  if (!tokenRes.ok) {
    return Response.redirect(buildRedirectUri(request, '/work?auth_error=token_exchange_failed'), 302);
  }
  const tokenData = await tokenRes.json();

  const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${tokenData.access_token}` }
  });
  if (!userRes.ok) {
    return Response.redirect(buildRedirectUri(request, '/work?auth_error=userinfo_failed'), 302);
  }
  const profile = await userRes.json();
  if (!profile.email) {
    return Response.redirect(buildRedirectUri(request, '/work?auth_error=no_email'), 302);
  }

  const user = await upsertOAuthUser(env, {
    provider: 'google',
    providerId: profile.sub,
    email: profile.email.toLowerCase()
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
