// ============================================================
// Puente Discord -> Firebase Auth (Cloudflare Workers, plan gratis)
// Repo referencia: scainetprr/Portafolio (admin: scainetprr)
// ============================================================
// COMO DESPLEGAR (5 min, sin tarjeta):
// 1. Crea app en https://discord.com/developers/applications -> New Application
//    -> OAuth2 -> Redirects -> Add Redirect: https://TU-WORKER.workers.dev/callback
//    -> copia CLIENT ID y CLIENT SECRET (Reset Secret).
// 2. workers.cloudflare.com -> Create Worker -> pega este archivo -> Deploy.
// 3. Worker -> Settings -> Variables -> añade Secrets:
//      DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET,
//      FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, FIREBASE_PROJECT_ID
//    (los 3 de Firebase salen de: console.firebase.google.com -> Project Settings
//     -> Service accounts -> Generate new private key)
// 4. Worker -> Settings -> Variables (texto normal):
//      SITE_URL = https://scainetprr.github.io/Portafolio/
// 5. Pasa la URL del worker al admin del portafolio para activar el boton.
// ============================================================
const DISCORD_API = 'https://discord.com/api/v10';

function b64url(bytes) {
  let s = '';
  const b = new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlStr(str) {
  return b64url(new TextEncoder().encode(str));
}
async function importKey(pem) {
  const raw = pem.replace(/-----BEGIN PRIVATE KEY-----/g, '').replace(/-----END PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  const bin = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
  return crypto.subtle.importKey('pkcs8', bin, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
}
async function mintCustomToken(env, uid, name) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64urlStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = b64urlStr(JSON.stringify({
    iss: env.FIREBASE_CLIENT_EMAIL,
    sub: env.FIREBASE_CLIENT_EMAIL,
    aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: now, exp: now + 3600, uid: uid,
    claims: { name: name, provider: 'Discord' }
  }));
  const key = await importKey(env.FIREBASE_PRIVATE_KEY);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(header + '.' + payload));
  return header + '.' + payload + '.' + b64url(sig);
}
function rand(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return Array.from(a, x => x.toString(16).padStart(2, '0')).join('');
}
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const base = url.origin;
    if (url.pathname === '/authorize') {
      const st = rand(16);
      const authUrl = DISCORD_API + '/oauth2/authorize?client_id=' + encodeURIComponent(env.DISCORD_CLIENT_ID)
        + '&redirect_uri=' + encodeURIComponent(base + '/callback')
        + '&response_type=code&scope=' + encodeURIComponent('identify email')
        + '&state=' + st;
      return new Response(null, {
        status: 302,
        headers: { Location: authUrl, 'Set-Cookie': 'dstate=' + st + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=300' }
      });
    }
    if (url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state') || '';
      const cookies = req.headers.get('Cookie') || '';
      const m = cookies.match(/dstate=([a-f0-9]+)/);
      const site = (env.SITE_URL || 'https://scainetprr.github.io/Portafolio/').replace(/\/?$/, '/');
      if (!code || !m || m[1] !== state) {
        return Response.redirect(site + '#fberr=oauth', 302);
      }
      const tk = await fetch(DISCORD_API + '/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: env.DISCORD_CLIENT_ID,
          client_secret: env.DISCORD_CLIENT_SECRET,
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: base + '/callback'
        })
      });
      if (!tk.ok) return Response.redirect(site + '#fberr=token', 302);
      const tj = await tk.json();
      const me = await fetch(DISCORD_API + '/users/@me', {
        headers: { Authorization: 'Bearer ' + tj.access_token }
      });
      if (!me.ok) return Response.redirect(site + '#fberr=profile', 302);
      const user = await me.json();
      const name = (user.global_name || user.username || 'Usuario').slice(0, 30);
      const token = await mintCustomToken(env, 'discord:' + user.id, name);
      const clear = 'dstate=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
      return new Response(null, {
        status: 302,
        headers: { Location: site + '#fbtoken=' + token, 'Set-Cookie': clear }
      });
    }
    return new Response('OK: usa /authorize para iniciar login con Discord', { status: 200 });
  }
};
