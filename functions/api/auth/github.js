// functions/api/auth/github.js
import { generateOAuthState, buildRedirectUri } from '../_utils';

export async function onRequest(context) {
  const { request, env } = context;
  const state = generateOAuthState();
  const redirectUri = buildRedirectUri(request, '/api/auth/github-callback');

  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', 'read:user user:email');
  url.searchParams.set('state', state);

  const cookie = [
    `oauth_state=${state}`, 'HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/', 'Max-Age=600'
  ].join('; ');

  return new Response(null, {
    status: 302,
    headers: { Location: url.toString(), 'Set-Cookie': cookie }
  });
}
