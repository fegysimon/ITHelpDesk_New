/* IT Help Desk - shared auth + data layer (client-side demo) */
const IDLE_MS = 15 * 60 * 1000, MAX_FAILS = 5, LOCK_MS = 60 * 1000;
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const load = (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } };
const save = (k, v) => localStorage.setItem(k, JSON.stringify(v));

async function hash(pw, salt) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + pw));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
const newSalt = () => [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, '0')).join('');

/* Built-in users (salted SHA-256 hashes). Merged into storage on every page load. */
const PRESET_USERS = [
  { username: 'john', name: 'John Sunder', role: 'user', salt: '1c3342d9559bda2672019193dfc88ed5', hash: 'bfeac46f9619f2357c9823961d7fe04d193ec1c96fe0e1569a4e0df6ec05da88' },
  { username: 'kumar', name: 'Kumar Sanjeevi', role: 'user', salt: '4bb4342f9223840069a12ea6eadcd88d', hash: 'fb1933eedbf9a5763ff28aaff2d0cde6ef130ea3973a4aa92e125596ba88c340' },
  { username: 'stalin', name: 'Stalin Singh', role: 'user', salt: '447d645db5c8ba15a1ddb1c1a5d3a827', hash: '433927acf02454de6f65a44cf1694ca3de0babdda31201838545fb3b17cc52bf' },
  { username: 'jayaraman', name: 'Jayaraman Krish', role: 'user', salt: 'd75424bebab029dca7e467f17c7fbd1b', hash: 'f6ef43b12011702c257383dd5d49ab0cc625bb900185bba71a86b6501f8fe6a9' },
  { username: 'fegy', name: 'Fegy Simon', role: 'user', salt: '631f191a9769a51dce818dc389ee9184', hash: 'a7cbf0e1b8e01744448abfd6c1fbf240d655e8cd114844c1f354160003eec848' }
];
function mergePresets() {
  const a = load('hd_users', []);
  PRESET_USERS.forEach(p => { if (!a.some(u => u.username === p.username)) a.push({ ...p }); });
  save('hd_users', a);
}

async function seed() {
  if (load('hd_users', null)) return mergePresets();
  const mk = async (username, name, role, pw) => { const salt = newSalt(); return { username, name, role, salt, hash: await hash(pw, salt) }; };
  save('hd_users', [
    await mk('admin', 'Help Desk Admin', 'admin', 'Admin#2026'),
    await mk('user', 'Demo Employee', 'user', 'User#2026')
  ]);
  save('hd_tickets', [
    { id: 1001, owner: 'user', title: 'VPN disconnects every 10 minutes', category: 'Network', priority: 'High', desc: 'Drops on home Wi-Fi.', status: 'In-Progress', created: Date.now() - 864e5 * 2 },
    { id: 1002, owner: 'user', title: 'Need Visio license', category: 'Software', priority: 'Low', desc: 'For network diagrams.', status: 'Open', created: Date.now() - 864e5 }
  ]);
  mergePresets();
}

/* ---- session ---- */
const session = () => {
  try {
    const s = JSON.parse(sessionStorage.getItem('hd_session'));
    if (!s) return null;
    if (Date.now() > s.exp) { sessionStorage.removeItem('hd_session'); return null; }
    return s;
  } catch { return null; }
};
function startSession(u) {
  sessionStorage.setItem('hd_session', JSON.stringify({ username: u.username, name: u.name, role: u.role, exp: Date.now() + IDLE_MS }));
}
const touch = () => { const s = session(); if (s) { s.exp = Date.now() + IDLE_MS; sessionStorage.setItem('hd_session', JSON.stringify(s)); } };
/* ---- Okta (OIDC) sign-in ---- */
/* Identity provider settings (Auth0). Name kept as OKTA so the rest of the code is unchanged. */
const AUTH0_DOMAIN = 'dev-tbmjt7lcunawq407.us.auth0.com';   // <-- paste your Auth0 Domain (no https://)
const OKTA = {
  issuer: 'https://' + AUTH0_DOMAIN + '/',          // must match "issuer" in the discovery document (note trailing slash)
  clientId: '9jEonav3V4Dix7TEh0G5BSj4Arrnkhg2',                // <-- paste your Auth0 Client ID
  authorizeUrl: 'https://' + AUTH0_DOMAIN + '/authorize',
  logoutUrl: (idt, back) => 'https://' + AUTH0_DOMAIN + '/v2/logout?client_id=' + encodeURIComponent(OKTA.clientId) + '&returnTo=' + encodeURIComponent(back),
  codeScope: 'openid profile email',                // add ' offline_access' only if your Genesys setup needs refresh tokens
  admins: ['fegy.simon@genesys.com']                // emails that get the admin role
};
const pageUrl = f => new URL(f, location.href).href;
const rand = () => crypto.randomUUID();
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const jwtClaims = t => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))));

/* kind 'id_token' = identify the user for this website; kind 'code' = get an auth code for Genesys Messenger */
async function oktaAuthorize(kind, opts = {}) {
  const state = rand(), nonce = rand();
  const p = { kind, nonce, prompt: opts.prompt || '', returnTo: opts.returnTo || 'dashboard.html' };
  const q = new URLSearchParams({ client_id: OKTA.clientId, redirect_uri: pageUrl('callback.html'), state, nonce,
    scope: kind === 'code' ? OKTA.codeScope : 'openid profile email' });
  if (kind === 'code') {
    const v = b64url(crypto.getRandomValues(new Uint8Array(32)));
    p.verifier = v;
    q.set('response_type', 'code'); q.set('code_challenge_method', 'S256');
    q.set('code_challenge', b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))));
  } else { q.set('response_type', 'id_token'); q.set('response_mode', 'fragment'); }
  if (opts.prompt) q.set('prompt', opts.prompt);
  sessionStorage.setItem('hd_oauth_' + state, JSON.stringify(p));
  location.assign(OKTA.authorizeUrl + '?' + q);
}

async function logout(reason) {
  try { if (window.Genesys) await Promise.race([new Promise(r => Genesys('command', 'Auth.logout', {}, r, r)), new Promise(r => setTimeout(r, 1500))]); } catch { }
  const idt = sessionStorage.getItem('hd_idtoken');
  ['hd_session', 'hd_idtoken', 'hd_pending_code', 'hd_last_silent'].forEach(k => sessionStorage.removeItem(k));
  if (!reason && idt) location.replace(OKTA.logoutUrl(idt, pageUrl('index.html')));
  else location.replace('index.html' + (reason ? '?r=' + reason : ''));
}

async function login(username, pw) {
  await seed();
  const lock = load('hd_lock', {});
  const L = lock[username.toLowerCase()] || { n: 0, until: 0 };
  if (Date.now() < L.until) return { ok: false, err: `Account locked. Try again in ${Math.ceil((L.until - Date.now()) / 1000)}s.` };
  const u = load('hd_users', []).find(x => x.username === username.toLowerCase());
  const good = u && (await hash(pw, u.salt)) === u.hash;
  if (!good) {
    L.n++; if (L.n >= MAX_FAILS) { L.until = Date.now() + LOCK_MS; L.n = 0; }
    lock[username.toLowerCase()] = L; save('hd_lock', lock);
    return { ok: false, err: 'Invalid username or password.' };
  }
  delete lock[username.toLowerCase()]; save('hd_lock', lock);
  startSession(u);
  return { ok: true };
}

/* ---- Genesys Web Messenger ---- */
/* Fill these in from Admin > Message > Messenger Deployments > your deployment > "Install snippet" */
const GENESYS = {
  environment: 'prod-aps1',   // e.g. 'prod-usw2', 'prod-euw1'
  deploymentId: 'e35ff7ce-18d1-40aa-aa2c-061281b7d52c'   // your deployment GUID
};
/* On-page status box so you can see Messenger/auth progress without DevTools. Set to false to hide. */
const SHOW_DEBUG = true;
function dbg(msg) {
  console.info('[HD] ' + msg);
  if (!SHOW_DEBUG) return;
  let b = document.getElementById('hd-dbg');
  if (!b) {
    b = document.createElement('div'); b.id = 'hd-dbg';
    b.style.cssText = 'position:fixed;left:8px;bottom:8px;max-width:340px;background:#14213d;color:#cfe;font:12px/1.4 monospace;padding:8px 10px;border-radius:6px;z-index:99999;opacity:.92';
    document.body.appendChild(b);
  }
  b.innerHTML += esc(new Date().toLocaleTimeString() + '  ' + msg) + '<br>';
}
function initMessenger(s) {
  dbg('Signed in as ' + s.username + ' (' + s.name + ')');
  if (!GENESYS.environment || !GENESYS.deploymentId) { console.warn('Genesys Messenger not configured (see GENESYS in js/app.js)'); return; }
  if (window.Genesys) return;
  (function (g, e, n, es, ys) {
    g['_genesysJs'] = e;
    g[e] = g[e] || function () { (g[e].q = g[e].q || []).push(arguments); };
    g[e].t = 1 * new Date(); g[e].c = es;
    ys = document.createElement('script'); ys.async = 1; ys.src = n; ys.charset = 'utf-8';
    ys.onload = () => dbg('Genesys script loaded'); ys.onerror = () => dbg('ERROR: Genesys script failed to load (check environment / network)');
    document.head.appendChild(ys);
  })(window, 'Genesys', 'https://apps.' + ({ 'prod-usw2': 'usw2.pure.cloud', 'prod-euw1': 'mypurecloud.ie', 'prod-aps1': 'aps1.pure.cloud', 'prod-apse2': 'mypurecloud.com.au', 'prod-apne1': 'mypurecloud.jp', 'prod-cac1': 'cac1.pure.cloud', 'prod-euw2': 'euw2.pure.cloud', 'prod-euc1': 'mypurecloud.de' }[GENESYS.environment] || 'mypurecloud.com') + '/genesys-bootstrap/genesys.min.js',
    { environment: GENESYS.environment, deploymentId: GENESYS.deploymentId });
  // Report the authentication setting Genesys is currently serving for this deployment
  fetch('https://api-cdn.' + ({ 'prod-usw2': 'usw2.pure.cloud', 'prod-euw1': 'mypurecloud.ie', 'prod-aps1': 'aps1.pure.cloud', 'prod-apse2': 'mypurecloud.com.au', 'prod-apne1': 'mypurecloud.jp', 'prod-cac1': 'cac1.pure.cloud', 'prod-euw2': 'euw2.pure.cloud', 'prod-euc1': 'mypurecloud.de' }[GENESYS.environment] || 'mypurecloud.com') + '/webdeployments/v1/deployments/' + GENESYS.deploymentId + '/config.json', { cache: 'no-store' })
    .then(r => r.json()).then(j => dbg('Genesys deployment auth setting: ' + JSON.stringify(j.auth || 'none (authentication OFF)')))
    .catch(err => dbg('Could not read deployment config: ' + err.message));
  // Authenticated messaging: hand Messenger an Okta authorization code when it asks for one
  Genesys('registerPlugin', 'AuthProvider', AuthProvider => {
    // Returns the stored auth code if it is still fresh (codes are single-use and short-lived), else null
    const takeCode = () => {
      const raw = sessionStorage.getItem('hd_pending_code');
      sessionStorage.removeItem('hd_pending_code');
      if (!raw) return null;
      const d = JSON.parse(raw);
      if (d.t && Date.now() - d.t > 20000) { dbg('Stored auth code is too old, fetching a new one'); return null; }
      const out = { authCode: d.authCode, redirectUri: d.redirectUri, nonce: d.nonce, codeVerifier: d.codeVerifier };
      if (d.iss) out.iss = d.iss;
      return out;
    };
    // No usable code: go back to Auth0 for a fresh one (guard against redirect loops)
    const fetchNewCode = e => {
      const last = +sessionStorage.getItem('hd_last_silent') || 0;
      if (Date.now() - last < 8000) { dbg('ERROR: could not obtain an authorization code'); return e.reject('Could not obtain an authorization code'); }
      sessionStorage.setItem('hd_last_silent', Date.now());
      dbg('Getting a fresh authorization code...');
      oktaAuthorize('code', { prompt: 'none', returnTo: location.pathname.split('/').pop() || 'dashboard.html' });
    };
    AuthProvider.registerCommand('getAuthCode', e => {
      const out = takeCode();
      dbg('Messenger asked for an auth code (getAuthCode). Code ready: ' + !!out);
      if (out) return e.resolve(out);
      fetchNewCode(e);
    });
    // Used when "session upgrade / step-up" is enabled: the visitor starts anonymous and Messenger asks us to sign in
    AuthProvider.registerCommand('signIn', e => {
      const out = takeCode();
      dbg('Messenger asked to sign in (signIn). Code ready: ' + !!out);
      if (out) { AuthProvider.publish('signedIn', out); return e.resolve(out); }
      fetchNewCode(e);
    });
    AuthProvider.registerCommand('reAuthenticate', e => {
      oktaAuthorize('code', { returnTo: location.pathname.split('/').pop() || 'dashboard.html' });
      e.resolve();
    });
    AuthProvider.subscribe('Auth.authError', err => dbg('Genesys Auth ERROR: ' + JSON.stringify(err)));
    AuthProvider.ready();
    dbg('AuthProvider plugin registered');
  });
}

/* ---- page guard + nav ---- */
function guard(page, adminOnly = false) {
  const s = session();
  if (!s) return logout('expired');
  if (adminOnly && s.role !== 'admin') return location.replace('dashboard.html');
  const links = [['dashboard.html', 'Dashboard'], ['tickets.html', 'Tickets'], ['kb.html', 'Knowledge Base'], ['profile.html', s.role === 'admin' ? 'Profile / Admin' : 'Profile']];
  document.body.insertAdjacentHTML('afterbegin',
    `<header><div class="brand">IT Help Desk</div><nav>${links.map(([h, t]) => `<a href="${h}" class="${h === page ? 'active' : ''}">${t}</a>`).join('')}</nav>
     <div class="who">${esc(s.name)} (${esc(s.role)}) <button class="ghost" id="lo">Sign out</button></div></header>`);
  $('#lo').onclick = () => logout();
  initMessenger(s);
  ['click', 'keydown', 'mousemove'].forEach(e => document.addEventListener(e, touch, { passive: true }));
  setInterval(() => { if (!session()) logout('expired'); }, 15000);
  return s;
}

/* ---- tickets ---- */
const tickets = () => load('hd_tickets', []);
const fmt = t => new Date(t).toLocaleDateString();
