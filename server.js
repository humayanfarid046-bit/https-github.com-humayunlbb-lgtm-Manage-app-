/**
 * College Management - Single-file server (Express + JSON store)
 * Updated: refresh tokens, chat, payment mock, role management
 *
 * Usage:
 * 1) npm init -y
 * 2) npm i express bcrypt jsonwebtoken uuid cors body-parser fs-extra
 * 3) node server.js
 *
 * Env:
 * - PORT (default 4000)
 * - JWT_SECRET (default 'change_this_secret')
 * - OPENAI_API_KEY (optional)
 */
const express = require('express');
const fs = require('fs-extra');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

let OpenAI = null;
try {
  if (process.env.OPENAI_API_KEY) OpenAI = require('openai');
} catch (e) {
  // optional
}

const PORT = Number(process.env.PORT || 4000);
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const REFRESH_SECRET = JWT_SECRET + '_refresh';

const DATA_FILE = path.join(__dirname, 'data.json');
const BACKUP_DIR = path.join(__dirname, 'backups');

async function loadData() {
  try {
    await fs.ensureFile(DATA_FILE);
    const txt = await fs.readFile(DATA_FILE, 'utf8');
    if (!txt) {
      const init = {
        users: [],
        students: [],
        attendances: [],
        notices: [],
        payments: [],
        results: [],
        refreshTokens: [],
        chatMessages: []
      };
      await fs.writeJson(DATA_FILE, init, { spaces: 2 });
      return init;
    }
    return JSON.parse(txt);
  } catch (err) {
    console.error('Failed to load data:', err);
    const init = {
      users: [],
      students: [],
      attendances: [],
      notices: [],
      payments: [],
      results: [],
      refreshTokens: [],
      chatMessages: []
    };
    await fs.writeJson(DATA_FILE, init, { spaces: 2 });
    return init;
  }
}

async function saveData(data) {
  await fs.writeJson(DATA_FILE, data, { spaces: 2 });
}

function signAccessToken(payload, expiresIn = '1h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}
function signRefreshToken(payload, expiresIn = '7d') {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn });
}
function verifyAccessToken(token) {
  return jwt.verify(token, JWT_SECRET);
}
function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_SECRET);
}

async function ensureAdminSeed() {
  const data = await loadData();
  if (!data.users.find(u => u.email === 'admin@college.test')) {
    const hash = await bcrypt.hash('password123', 10);
    const admin = {
      id: uuidv4(),
      email: 'admin@college.test',
      name: 'Admin User',
      password: hash,
      role: 'ADMIN',
      createdAt: new Date().toISOString(),
    };
    data.users.push(admin);
    await saveData(data);
    console.log('Seeded admin: admin@college.test / password123');
  }
}

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static frontend file (frontend.html should be in same folder)
app.get('/', async (req, res) => {
  const file = path.join(__dirname, 'frontend.html');
  if (await fs.pathExists(file)) {
    res.sendFile(file);
  } else {
    res.send('<h3>No frontend.html found. Put the provided frontend file in the same directory.</h3>');
  }
});

/** Middleware: auth */
async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: 'No authorization header' });
  const parts = header.split(' ');
  const token = parts.length === 2 ? parts[1] : parts[0];
  try {
    const payload = verifyAccessToken(token);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ message: 'Unauthenticated' });
    if (req.user.role === 'ADMIN' || req.user.role === role) return next();
    return res.status(403).json({ message: 'Forbidden' });
  };
}

/** Auth routes */
// register returns access + refresh
app.post('/api/register', async (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'email & password required' });
  const data = await loadData();
  if (data.users.find(u => u.email === email)) return res.status(400).json({ message: 'Email already exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), email, name: name || email.split('@')[0], password: hash, role: role || 'STUDENT', createdAt: new Date().toISOString() };
  data.users.push(user);
  if (user.role === 'STUDENT') {
    data.students.push({
      id: uuidv4(),
      userId: user.id,
      rollNumber: `R-${Math.floor(Math.random() * 9000) + 1000}`,
      batch: '2025',
      department: 'General',
      createdAt: new Date().toISOString(),
    });
  }
  const access = signAccessToken({ id: user.id, email: user.email, role: user.role, name: user.name }, '1h');
  const refresh = signRefreshToken({ id: user.id }, '7d');
  data.refreshTokens.push({ token: refresh, userId: user.id, expiresAt: new Date(Date.now() + 7*24*3600*1000).toISOString() });
  await saveData(data);
  res.json({ access, refresh, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
});

// login returns access + refresh
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const data = await loadData();
  const user = data.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
  const access = signAccessToken({ id: user.id, email: user.email, role: user.role, name: user.name }, '1h');
  const refresh = signRefreshToken({ id: user.id }, '7d');
  data.refreshTokens.push({ token: refresh, userId: user.id, expiresAt: new Date(Date.now() + 7*24*3600*1000).toISOString() });
  await saveData(data);
  res.json({ access, refresh, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
});

// refresh endpoint
app.post('/api/refresh', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: 'token required' });
  const data = await loadData();
  const stored = data.refreshTokens.find(rt => rt.token === token);
  if (!stored) return res.status(401).json({ message: 'Invalid refresh token' });
  try {
    const payload = verifyRefreshToken(token);
    const userId = payload.id;
    const user = data.users.find(u => u.id === userId);
    if (!user) return res.status(401).json({ message: 'User not found' });
    const access = signAccessToken({ id: user.id, email: user.email, role: user.role, name: user.name }, '1h');
    res.json({ access });
  } catch (err) {
    return res.status(401).json({ message: 'Invalid refresh token' });
  }
});

// logout (invalidate refresh)
app.post('/api/logout', requireAuth, async (req, res) => {
  const { refresh } = req.body;
  const data = await loadData();
  if (refresh) {
    data.refreshTokens = data.refreshTokens.filter(rt => rt.token !== refresh);
    await saveData(data);
  }
  res.json({ ok: true });
});

/** Student endpoints */
app.get('/api/students/me', requireAuth, async (req, res) => {
  const data = await loadData();
  const userId = req.user.id;
  const user = data.users.find(u => u.id === userId);
  const student = data.students.find(s => s.userId === userId);
  res.json({ user, student });
});
app.put('/api/students/me', requireAuth, async (req, res) => {
  const data = await loadData();
  const userId = req.user.id;
  const user = data.users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ message: 'User not found' });
  const { name } = req.body;
  if (name) user.name = name;
  await saveData(data);
  res.json({ user });
});

/** Attendance */
app.post('/api/attendance/mark', requireAuth, requireRole('TEACHER'), async (req, res) => {
  const { studentId, classId, status, date } = req.body;
  if (!studentId || !status) return res.status(400).json({ message: 'Missing studentId or status' });
  const data = await loadData();
  const rec = { id: uuidv4(), studentId, classId: classId || null, status, date: date || new Date().toISOString(), markedBy: req.user.id };
  data.attendances.push(rec);
  await saveData(data);
  res.json({ attendance: rec });
});
app.get('/api/attendance', requireAuth, async (req, res) => {
  const data = await loadData();
  if (req.user.role === 'STUDENT') {
    const student = data.students.find(s => s.userId === req.user.id);
    if (!student) return res.json({ attendances: [] });
    return res.json({ attendances: data.attendances.filter(a => a.studentId === student.id) });
  }
  res.json({ attendances: data.attendances });
});

/** Notices */
app.post('/api/notices', requireAuth, requireRole('STAFF'), async (req, res) => {
  const { title, content, pinned } = req.body;
  if (!title || !content) return res.status(400).json({ message: 'title & content required' });
  const data = await loadData();
  const n = { id: uuidv4(), title, content, authorId: req.user.id, pinned: !!pinned, createdAt: new Date().toISOString() };
  data.notices.unshift(n);
  await saveData(data);
  res.json({ notice: n });
});
app.get('/api/notices', async (req, res) => {
  const data = await loadData();
  res.json({ notices: data.notices.slice(0, 50) });
});

/** Result generator */
app.post('/api/results/generate', requireAuth, requireRole('TEACHER'), async (req, res) => {
  const { studentId, term, marks } = req.body;
  if (!studentId || !term || !marks) return res.status(400).json({ message: 'studentId, term, marks required' });
  const data = await loadData();
  const total = Object.values(marks).reduce((s, v) => s + Number(v || 0), 0);
  const maxTotal = Object.values(marks).length * 100;
  const percent = (total / maxTotal) * 100;
  let grade = 'F';
  if (percent >= 85) grade = 'A+';
  else if (percent >= 75) grade = 'A';
  else if (percent >= 65) grade = 'B';
  else if (percent >= 50) grade = 'C';
  else grade = 'F';
  const r = { id: uuidv4(), studentId, term, marks, total, grade, createdAt: new Date().toISOString() };
  data.results.push(r);
  await saveData(data);
  res.json({ result: r });
});
app.get('/api/results/:studentId', requireAuth, async (req, res) => {
  const { studentId } = req.params;
  const data = await loadData();
  if (req.user.role === 'STUDENT') {
    const student = data.students.find(s => s.userId === req.user.id);
    if (!student || student.id !== studentId) return res.status(403).json({ message: 'Forbidden' });
  }
  const results = data.results.filter(r => r.studentId === studentId);
  res.json({ results });
});

/** Chat / Helpdesk */
app.post('/api/chat/send', requireAuth, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: 'text required' });
  const data = await loadData();
  const msg = { id: uuidv4(), userId: req.user.id, name: req.user.name || req.user.email, text, createdAt: new Date().toISOString() };
  data.chatMessages.push(msg);
  // keep last 1000
  if (data.chatMessages.length > 1000) data.chatMessages = data.chatMessages.slice(-1000);
  await saveData(data);
  res.json({ message: msg });
});
app.get('/api/chat/messages', requireAuth, async (req, res) => {
  const data = await loadData();
  const last = data.chatMessages.slice(-200);
  res.json({ messages: last });
});

/** Payments (mock) */
app.post('/api/payments/create', requireAuth, async (req, res) => {
  const { studentId, amount, method } = req.body;
  if (!studentId || !amount) return res.status(400).json({ message: 'studentId & amount required' });
  const data = await loadData();
  const p = { id: uuidv4(), studentId, amount: Number(amount), method: method || 'card', status: 'pending', createdAt: new Date().toISOString() };
  data.payments.push(p);
  await saveData(data);
  // Return mock client secret
  res.json({ payment: p, client_secret: 'mock_client_secret_' + p.id });
});
app.post('/api/payments/confirm', requireAuth, async (req, res) => {
  const { paymentId } = req.body;
  if (!paymentId) return res.status(400).json({ message: 'paymentId required' });
  const data = await loadData();
  const pay = data.payments.find(p => p.id === paymentId);
  if (!pay) return res.status(404).json({ message: 'Payment not found' });
  pay.status = 'completed';
  await saveData(data);
  res.json({ payment: pay });
});
app.get('/api/payments', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const data = await loadData();
  res.json({ payments: data.payments });
});

/** Export CSV */
function toCSV(rows, headers) {
  const esc = (v) => {
    if (v === null || v === undefined) return '';
    const s = String(typeof v === 'object' ? JSON.stringify(v) : v);
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };
  const out = [headers.join(',')];
  for (const r of rows) {
    out.push(headers.map(h => esc(r[h])).join(','));
  }
  return out.join('\n');
}
app.get('/api/export', requireAuth, async (req, res) => {
  const { type } = req.query; // students | attendance | results
  const data = await loadData();
  if (type === 'students') {
    const rows = data.students.map(s => ({
      id: s.id,
      userId: s.userId,
      rollNumber: s.rollNumber,
      batch: s.batch,
      department: s.department,
      createdAt: s.createdAt
    }));
    const csv = toCSV(rows, ['id', 'userId', 'rollNumber', 'batch', 'department', 'createdAt']);
    res.setHeader('Content-Disposition', 'attachment; filename=students.csv');
    res.setHeader('Content-Type', 'text/csv');
    return res.send(csv);
  }
  if (type === 'attendance') {
    const rows = data.attendances.map(a => ({
      id: a.id, studentId: a.studentId, classId: a.classId, status: a.status, date: a.date, markedBy: a.markedBy
    }));
    const csv = toCSV(rows, ['id', 'studentId', 'classId', 'status', 'date', 'markedBy']);
    res.setHeader('Content-Disposition', 'attachment; filename=attendance.csv');
    res.setHeader('Content-Type', 'text/csv');
    return res.send(csv);
  }
  if (type === 'results') {
    const rows = data.results.map(r => ({ id: r.id, studentId: r.studentId, term: r.term, total: r.total, grade: r.grade, createdAt: r.createdAt, marks: JSON.stringify(r.marks) }));
    const csv = toCSV(rows, ['id', 'studentId', 'term', 'total', 'grade', 'createdAt', 'marks']);
    res.setHeader('Content-Disposition', 'attachment; filename=results.csv');
    res.setHeader('Content-Type', 'text/csv');
    return res.send(csv);
  }
  res.status(400).json({ message: 'invalid type' });
});

/** Backup */
app.post('/api/backup', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const data = await loadData();
  await fs.ensureDir(BACKUP_DIR);
  const filename = `data-${Date.now()}.json`;
  await fs.writeJson(path.join(BACKUP_DIR, filename), data, { spaces: 2 });
  res.json({ ok: true, path: `/backups/${filename}` });
});
app.get('/backups/:file', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const f = req.params.file;
  const p = path.join(BACKUP_DIR, f);
  if (!(await fs.pathExists(p))) return res.status(404).json({ message: 'Not found' });
  res.download(p);
});

/** Admin: list users & change role */
app.get('/api/users', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const data = await loadData();
  const users = data.users.map(u => ({ id: u.id, email: u.email, name: u.name, role: u.role, createdAt: u.createdAt }));
  res.json({ users });
});
app.put('/api/users/:id/role', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const id = req.params.id;
  const { role } = req.body;
  if (!role) return res.status(400).json({ message: 'role required' });
  const data = await loadData();
  const user = data.users.find(u => u.id === id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  user.role = role;
  await saveData(data);
  res.json({ user });
});

/** AI Assistant (optional) */
app.post('/api/assistant', requireAuth, async (req, res) => {
  const { prompt } = req.body;
  if (!prompt) return res.status(400).json({ message: 'prompt required' });
  if (!process.env.OPENAI_API_KEY) {
    return res.json({ answer: `AI not configured. Received: ${prompt}` });
  }
  if (!OpenAI) return res.status(500).json({ message: 'OpenAI package not available' });
  try {
    const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const response = await client.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.2,
      max_tokens: 400
    });
    const message = response.choices?.[0]?.message?.content || 'No response';
    res.json({ answer: message });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'AI error', error: String(err) });
  }
});<!doctype html>
<html lang="bn">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>College Management - Mini UI (Cookie refresh)</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 min-h-screen">
  <div class="max-w-5xl mx-auto p-4">
    <header class="flex items-center justify-between py-4">
      <h1 class="text-xl font-bold">College Management (Mini)</h1>
      <div id="user-area"></div>
    </header>

    <main id="app">
      <section id="login-section" class="bg-white p-6 rounded shadow max-w-md mx-auto">
        <h2 class="text-lg font-semibold mb-3">লগইন / রেজিস্টার</h2>
        <form id="login-form" class="space-y-2">
          <input id="email" class="w-full p-2 border rounded" placeholder="ইমেইল" />
          <input id="password" type="password" class="w-full p-2 border rounded" placeholder="পাসওয়ার্ড" />
          <div class="flex gap-2">
            <button id="login-btn" type="button" class="px-4 py-2 bg-indigo-600 text-white rounded">Login</button>
            <button id="register-btn" type="button" class="px-4 py-2 bg-emerald-600 text-white rounded">Register</button>
          </div>
        </form>
        <p class="mt-3 text-sm text-slate-500">Seeded admin: admin@college.test / password123</p>
      </section>

      <section id="dashboard" class="hidden mt-6">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="p-4 bg-white rounded shadow">
            <h3 class="font-semibold">Quick Actions</h3>
            <div class="mt-3 space-y-2">
              <button id="quick-att" class="w-full py-2 bg-indigo-500 text-white rounded">Daily Attendance</button>
              <button id="new-notice" class="w-full py-2 bg-sky-500 text-white rounded">Add Notice</button>
              <button id="export-students" class="w-full py-2 bg-green-600 text-white rounded">Export Students CSV</button>
              <button id="open-chat" class="w-full py-2 bg-gray-700 text-white rounded">Open Support Chat</button>
              <button id="pay-sim" class="w-full py-2 bg-yellow-500 text-black rounded">Simulate Payment</button>
            </div>
          </div>
          <div class="p-4 bg-white rounded shadow col-span-2">
            <h3 class="font-semibold">Dashboard Content</h3>
            <div id="content-area" class="mt-3 space-y-4">
              <div id="notices" class="bg-slate-50 p-3 rounded"></div>
              <div id="attendance-list" class="bg-slate-50 p-3 rounded"></div>
              <div id="result-area" class="bg-slate-50 p-3 rounded"></div>
              <div id="chat-area" class="bg-slate-50 p-3 rounded hidden">
                <h4 class="font-semibold">Support Chat</h4>
                <div id="chat-messages" class="max-h-64 overflow-auto mt-2 space-y-2"></div>
                <div class="flex gap-2 mt-2">
                  <input id="chat-input" class="flex-1 p-2 border rounded" placeholder="Type your message..." />
                  <button id="chat-send" class="px-4 py-2 bg-indigo-600 text-white rounded">Send</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </main>

    <footer class="mt-6 text-sm text-slate-500">Mini demo UI — cookie-based refresh for safer tokens.</footer>
  </div>

<script>
const API_BASE = '/api';

function setUserArea(user) {
  const ua = document.getElementById('user-area');
  if (!user) {
    ua.innerHTML = '';
    return;
  }
  ua.innerHTML = \`<div class="flex gap-3 items-center">
    <div>\${user.name} (\${user.role})</div>
    <button id="logout-btn" class="px-3 py-1 bg-red-500 text-white rounded">Logout</button>
  </div>\`;
  document.getElementById('logout-btn').onclick = async () => {
    try {
      await fetch(API_BASE + '/logout', { method: 'POST', credentials: 'same-origin', headers: {'Content-Type':'application/json', 'Authorization': 'Bearer ' + localStorage.getItem('access')}});
    } catch (e) {}
    localStorage.removeItem('access');
    localStorage.removeItem('user');
    location.reload();
  };
}

async function apiFetch(path, opts = {}) {
  const headers = opts.headers || {};
  const token = localStorage.getItem('access');
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const fetchOpts = { ...opts, headers: { 'Content-Type': 'application/json', ...headers }, credentials: 'same-origin' };
  const res = await fetch(API_BASE + path, fetchOpts);
  if (res.status === 401) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      return apiFetch(path, opts); // retry
    } else {
      localStorage.removeItem('access');
      localStorage.removeItem('user');
      alert('Session expired. Please login again.');
      location.reload();
      throw new Error('Unauthorized');
    }
  }
  return res.json();
}

async function tryRefresh() {
  try {
    const r = await fetch(API_BASE + '/refresh', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }});
    const j = await r.json();
    if (r.ok && j.access) {
      localStorage.setItem('access', j.access);
      return true;
    }
    return false;
  } catch (e) { return false; }
}

document.getElementById('login-btn').addEventListener('click', async () => {
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  try {
    const res = await fetch(API_BASE + '/login', { method: 'POST', credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ email, password })});
    const data = await res.json();
    if (!res.ok) { alert(data.message || 'Login failed'); return; }
    // server sets httpOnly cookie for refresh; we store only access and user
    localStorage.setItem('access', data.access);
    localStorage.setItem('user', JSON.stringify(data.user));
    loadDashboard();
  } catch (e) { alert('Network error'); }
});

document.getElementById('register-btn').addEventListener('click', async () => {
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  try {
    const res = await fetch(API_BASE + '/register', { method: 'POST', credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ email, password })});
    const data = await res.json();
    if (!res.ok) { alert(data.message || 'Register failed'); return; }
    localStorage.setItem('access', data.access);
    localStorage.setItem('user', JSON.stringify(data.user));
    loadDashboard();
  } catch (e) { alert('Network error'); }
});

async function loadDashboard() {
  const user = JSON.parse(localStorage.getItem('user') || 'null');
  if (!user) return;
  setUserArea(user);
  document.getElementById('login-section').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
  // load notices
  const noticesResp = await apiFetch('/notices');
  const notices = noticesResp.notices || [];
  document.getElementById('notices').innerHTML = '<h4 class="font-semibold">Notices</h4>' + (notices.length ? notices.map(n => \`<div class="p-2 border rounded mt-2"><b>\${n.title}</b><div class="text-sm mt-1">\${n.content}</div><div class="text-xs text-slate-500 mt-1">By: \${n.authorId} at \${new Date(n.createdAt).toLocaleString()}</div></div>\`).join('') : '<div class="mt-2 text-slate-500">No notices</div>');
  // attendance list
  const attResp = await apiFetch('/attendance');
  const attends = attResp.attendances || [];
  document.getElementById('attendance-list').innerHTML = '<h4 class="font-semibold">Attendance</h4>' + (attends.length ? '<ul class="mt-2 space-y-1">' + attends.map(a=>\`<li class="text-sm">\${a.studentId} — \${a.status} — \${new Date(a.date).toLocaleString()}</li>\`).join('') + '</ul>' : '<div class="mt-2 text-slate-500">No records</div>');
  // result area: simple generator for teachers
  if (user.role === 'TEACHER' || user.role === 'ADMIN') {
    document.getElementById('result-area').innerHTML = \`<h4 class="font-semibold">Generate Result</h4>
      <div class="mt-2 space-y-2">
        <input id="res-student" class="p-2 border rounded w-full" placeholder="studentId" />
        <input id="res-term" class="p-2 border rounded w-full" placeholder="Term (e.g., Mid-Term)" />
        <textarea id="res-marks" class="p-2 border rounded w-full" placeholder='Marks JSON: { "Math": 80, "Eng": 70 }'></textarea>
        <button id="gen-res" class="px-4 py-2 bg-indigo-600 text-white rounded">Generate</button>
      </div>\`;
    document.getElementById('gen-res').onclick = async () => {
      try {
        const studentId = document.getElementById('res-student').value;
        const term = document.getElementById('res-term').value;
        const marks = JSON.parse(document.getElementById('res-marks').value || '{}');
        const r = await apiFetch('/results/generate', { method: 'POST', body: JSON.stringify({ studentId, term, marks }) });
        alert('Result generated: ' + JSON.stringify(r.result || r));
      } catch (e) { alert('Error or invalid marks JSON'); }
    };
  } else {
    document.getElementById('result-area').innerHTML = '<h4 class="font-semibold">Results</h4><div class="mt-2 text-slate-500">Teachers can generate results.</div>';
  }
}

// Quick actions
document.getElementById('quick-att').onclick = async () => {
  const studentId = prompt('Student ID to mark present (enter studentId):');
  if (!studentId) return;
  try {
    const res = await apiFetch('/attendance/mark', { method: 'POST', body: JSON.stringify({ studentId, status: 'present' }) });
    alert('Marked: ' + JSON.stringify(res.attendance || res));
    loadDashboard();
  } catch (e) { alert('Failed: ' + e.message); }
};
document.getElementById('new-notice').onclick = async () => {
  const title = prompt('Title:');
  const content = prompt('Content:');
  if (!title || !content) return;
  try {
    const r = await apiFetch('/notices', { method: 'POST', body: JSON.stringify({ title, content }) });
    alert('Notice posted');
    loadDashboard();
  } catch (e) { alert('Failed: ' + e.message); }
};
document.getElementById('export-students').onclick = () => {
  window.open('/api/export?type=students', '_blank');
};
document.getElementById('open-chat').onclick = async () => {
  document.getElementById('chat-area').classList.toggle('hidden');
  if (!document.getElementById('chat-area').classList.contains('hidden')) {
    const m = await apiFetch('/chat/messages');
    const msgs = m.messages || [];
    const el = document.getElementById('chat-messages');
    el.innerHTML = msgs.map(msg => \`<div class="p-2 bg-white rounded"><b>\${msg.name}</b><div class="text-sm">\${msg.text}</div><div class="text-xs text-slate-400">\${new Date(msg.createdAt).toLocaleString()}</div></div>\`).join('');
    document.getElementById('chat-send').onclick = async () => {
      const text = document.getElementById('chat-input').value;
      if (!text) return;
      await apiFetch('/chat/send', { method: 'POST', body: JSON.stringify({ text }) });
      document.getElementById('chat-input').value = '';
      const m2 = await apiFetch('/chat/messages');
      const msgs2 = m2.messages || [];
      el.innerHTML = msgs2.map(msg => \`<div class="p-2 bg-white rounded"><b>\${msg.name}</b><div class="text-sm">\${msg.text}</div><div class="text-xs text-slate-400">\${new Date(msg.createdAt).toLocaleString()}</div></div>\`).join('');
    };
  }
};

// On load, if token exists, show dashboard
window.addEventListener('load', () => {
  const token = localStorage.getItem('access');
  const user = JSON.parse(localStorage.getItem('user') || 'null');
  if (token && user) {
    loadDashboard();
  }
});
</script>
</body>
</html>

/** Health */
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

/** Start server */
(async () => {
  await ensureAdminSeed();
  await fs.ensureDir(BACKUP_DIR);
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
})();


