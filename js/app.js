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
function logout(reason) { sessionStorage.removeItem('hd_session'); location.replace('index.html' + (reason ? '?r=' + reason : '')); }

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
  ['click', 'keydown', 'mousemove'].forEach(e => document.addEventListener(e, touch, { passive: true }));
  setInterval(() => { if (!session()) logout('expired'); }, 15000);
  return s;
}

/* ---- tickets ---- */
const tickets = () => load('hd_tickets', []);
const fmt = t => new Date(t).toLocaleDateString();
