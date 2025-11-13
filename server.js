/**
 * College Management - Single-file server (Express + JSON store)
 *
 * Features:
 * - Auth (register/login) with bcrypt + JWT
 * - Role-based middleware (ADMIN, TEACHER, STUDENT)
 * - Student profile endpoints
 * - Attendance mark/list
 * - Notices (create/list)
 * - Result generator (marks JSON -> total + grade)
 * - CSV export endpoints
 * - Backup endpoint (saves ./backups/data-<ts>.json)
 * - Optional OpenAI assistant endpoint (set OPENAI_API_KEY)
 *
 * Usage:
 * 1) npm init -y
 * 2) npm i express bcrypt jsonwebtoken uuid cors body-parser fs-extra openai
 * 3) node server.js
 * 4) Open http://localhost:4000
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
if (process.env.OPENAI_API_KEY) {
  try {
    OpenAI = require('openai');
  } catch (e) {
    console.warn('openai package not installed or failed to load. AI endpoint will error if used.');
  }
}

const PORT = Number(process.env.PORT || 4000);
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

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
    };
    await fs.writeJson(DATA_FILE, init, { spaces: 2 });
    return init;
  }
}

async function saveData(data) {
  await fs.writeJson(DATA_FILE, data, { spaces: 2 });
}

function signToken(payload, expiresIn = '12h') {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
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
    const payload = verifyToken(token);
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
  await saveData(data);
  const token = signToken({ id: user.id, email: user.email, role: user.role, name: user.name });
  res.json({ access: token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const data = await loadData();
  const user = data.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ message: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
  const token = signToken({ id: user.id, email: user.email, role: user.role, name: user.name });
  res.json({ access: token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
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
  // Admin/Teacher: get all, Student: only self
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
  data.notices.unshift(n); // newest first
  await saveData(data);
  res.json({ notice: n });
});
app.get('/api/notices', async (req, res) => {
  const data = await loadData();
  res.json({ notices: data.notices.slice(0, 50) });
});

/** Result generator */
app.post('/api/results/generate', requireAuth, requireRole('TEACHER'), async (req, res) => {
  /**
   * Body:
   * { studentId: string, term: string, marks: { subject: mark, ... } }
   */
  const { studentId, term, marks } = req.body;
  if (!studentId || !term || !marks) return res.status(400).json({ message: 'studentId, term, marks required' });
  const data = await loadData();
  const total = Object.values(marks).reduce((s, v) => s + Number(v || 0), 0);
  const maxTotal = Object.values(marks).length * 100; // assume each subject max 100
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

/** Export CSV */
function toCSV(rows, headers) {
  const esc = (v) => {
    if (v === null || v === undefined) return '';
    const s = String(v);
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
    const rows = data.results.map(r => ({ id: r.id, studentId: r.studentId, term: r.term, total: r.total, grade: r.grade, createdAt: r.createdAt }));
    const csv = toCSV(rows, ['id', 'studentId', 'term', 'total', 'grade', 'createdAt']);
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
});

/** Health */
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

/** Simple admin endpoints to view users (protected) */
app.get('/api/users', requireAuth, requireRole('ADMIN'), async (req, res) => {
  const data = await loadData();
  const users = data.users.map(u => ({ id: u.id, email: u.email, name: u.name, role: u.role, createdAt: u.createdAt }));
  res.json({ users });
});

/** Start server */
(async () => {
  await ensureAdminSeed();
  await fs.ensureDir(BACKUP_DIR);
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
})();
