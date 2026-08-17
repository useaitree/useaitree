// functions/api/auth/google.js
import { generateOAuthState, buildRedirectUri } from '../_utils';

export async function onRequest(context) {
  const { request, env } = context;
  const state = generateOAuthState();
  const redirectUri = buildRedirectUri(request, '/api/auth/google-callback');

  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid email');
  url.searchParams.set('state', state);
  url.searchParams.set('prompt', 'select_account');

  const cookie = [
    `oauth_state=${state}`, 'HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/', 'Max-Age=600'
  ].join('; ');

  return new Response(null, {
    status: 302,
    headers: { Location: url.toString(), 'Set-Cookie': cookie }
  });
}
