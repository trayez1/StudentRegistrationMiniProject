const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const db = new Database(process.env.DB_PATH || 'data.sqlite');
db.exec(`
CREATE TABLE IF NOT EXISTS students(
  id INTEGER PRIMARY KEY, role TEXT DEFAULT 'student', name TEXT, student_id TEXT UNIQUE,
  email TEXT UNIQUE, phone TEXT, dob TEXT, gender TEXT, course TEXT, semester TEXT,
  address TEXT, password TEXT, registered_on TEXT);
CREATE TABLE IF NOT EXISTS invoices(
  id INTEGER PRIMARY KEY, student_id INTEGER, description TEXT, amount REAL,
  due_date TEXT, status TEXT DEFAULT 'Unpaid');
CREATE TABLE IF NOT EXISTS payments(
  id INTEGER PRIMARY KEY, invoice_id INTEGER, student_id INTEGER, amount REAL,
  method TEXT, receipt_no TEXT, paid_on TEXT);`);

// Sample fee per semester (RM)
const FEES = {
  'Diploma in Cyber Security': 3800, 'Diploma in Computer Science': 3500,
  'Diploma in Information Technology': 3200, 'Diploma in Software Engineering': 3600 };
const METHODS = ['Online Banking (FPX)', 'Credit/Debit Card', 'Bank Transfer'];

if (!db.prepare("SELECT 1 FROM students WHERE role='admin'").get())
  db.prepare("INSERT INTO students(role,name,email,password,registered_on) VALUES('admin','Administrator','admin@gmi.edu.my',?,date('now'))")
    .run(bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10));

const app = express();
app.use(express.json());
app.set('trust proxy', 1);
app.use(session({
  secret: process.env.SESSION_SECRET || 'demo-secret-change-me',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 864e5 }
}));
app.use(express.static('public'));

const auth = (req, res, next) => req.session.uid ? next() : res.status(401).json({ error: 'Please login.' });
const admin = (req, res, next) => req.session.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only.' });
const today = () => new Date().toISOString().slice(0, 10);
const clean = s => (s || '').toString().trim();

function view(uid) {
  const s = db.prepare('SELECT id,role,name,student_id,email,phone,dob,gender,course,semester,address,registered_on FROM students WHERE id=?').get(uid);
  if (!s) return null;
  const invoices = db.prepare('SELECT * FROM invoices WHERE student_id=?').all(uid)
    .map(i => ({ ...i, status: i.status === 'Unpaid' && i.due_date < today() ? 'Overdue' : i.status }));
  const payments = db.prepare('SELECT * FROM payments WHERE student_id=? ORDER BY id DESC').all(uid);
  return { ...s, invoices, payments };
}

app.post('/api/register', (req, res) => {
  const b = req.body, d = {};
  ['name','studentId','email','phone','dob','gender','course','semester','address'].forEach(k => d[k] = clean(b[k]));
  if (Object.values(d).some(v => !v) || !b.password) return res.status(400).json({ error: 'Please complete every field.' });
  if (!/^[A-Za-z]{2,5}\d{3,8}$/.test(d.studentId)) return res.status(400).json({ error: 'Student ID format is invalid (e.g. GMI12345).' });
  if (!/^\+?\d{9,13}$/.test(d.phone.replace(/[\s-]/g, ''))) return res.status(400).json({ error: 'Phone number is invalid.' });
  if (!/^\S+@\S+\.\S+$/.test(d.email)) return res.status(400).json({ error: 'Email is invalid.' });
  if (new Date(d.dob) > new Date()) return res.status(400).json({ error: 'Date of birth is invalid.' });
  if (!FEES[d.course]) return res.status(400).json({ error: 'Unknown course.' });
  if (b.password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  d.email = d.email.toLowerCase(); d.studentId = d.studentId.toUpperCase();
  if (db.prepare('SELECT 1 FROM students WHERE email=?').get(d.email)) return res.status(409).json({ error: 'An account already exists for this email.' });
  if (db.prepare('SELECT 1 FROM students WHERE student_id=?').get(d.studentId)) return res.status(409).json({ error: 'This Student ID is already registered.' });

  const r = db.prepare(`INSERT INTO students(name,student_id,email,phone,dob,gender,course,semester,address,password,registered_on)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(d.name, d.studentId, d.email, d.phone, d.dob, d.gender, d.course, d.semester, d.address, bcrypt.hashSync(b.password, 10), today());
  const due = new Date(Date.now() + 30 * 864e5).toISOString().slice(0, 10);
  db.prepare('INSERT INTO invoices(student_id,description,amount,due_date) VALUES(?,?,?,?)')
    .run(r.lastInsertRowid, `Tuition Fee - ${d.semester}`, FEES[d.course], due);
  req.session.uid = r.lastInsertRowid; req.session.role = 'student';
  res.json(view(r.lastInsertRowid));
});

app.post('/api/login', (req, res) => {
  const u = db.prepare('SELECT * FROM students WHERE email=?').get(clean(req.body.email).toLowerCase());
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password))
    return res.status(401).json({ error: 'No matching account found for that email and password.' });
  req.session.uid = u.id; req.session.role = u.role;
  res.json(view(u.id));
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', (req, res) => res.json(req.session.uid ? view(req.session.uid) : null));

// Course & semester are locked: only these fields can be edited
app.put('/api/me', auth, (req, res) => {
  const b = req.body, name = clean(b.name), phone = clean(b.phone), dob = clean(b.dob), gender = clean(b.gender), address = clean(b.address);
  if (!name || !phone || !dob || !gender || !address) return res.status(400).json({ error: 'Please complete every field.' });
  db.prepare('UPDATE students SET name=?,phone=?,dob=?,gender=?,address=? WHERE id=?').run(name, phone, dob, gender, address, req.session.uid);
  res.json(view(req.session.uid));
});

// Simulated gateway: the SERVER confirms payment, the browser cannot fake it
app.post('/api/pay', auth, (req, res) => {
  const inv = db.prepare('SELECT * FROM invoices WHERE id=? AND student_id=?').get(req.body.invoiceId, req.session.uid);
  if (!inv) return res.status(404).json({ error: 'Invoice not found.' });
  if (inv.status === 'Paid') return res.status(400).json({ error: 'Invoice is already paid.' });
  if (!METHODS.includes(req.body.method)) return res.status(400).json({ error: 'Choose a payment method.' });
  const receipt = 'RCP-' + Date.now().toString().slice(-8);
  db.prepare("UPDATE invoices SET status='Paid' WHERE id=?").run(inv.id);
  db.prepare('INSERT INTO payments(invoice_id,student_id,amount,method,receipt_no,paid_on) VALUES(?,?,?,?,?,?)')
    .run(inv.id, inv.student_id, inv.amount, req.body.method, receipt, new Date().toISOString().slice(0, 16).replace('T', ' '));
  res.json(view(req.session.uid));
});

app.get('/api/admin/students', auth, admin, (req, res) => {
  const rows = db.prepare(`SELECT s.name,s.student_id,s.email,s.course,s.semester,s.registered_on,
    i.amount,i.due_date,i.status FROM students s LEFT JOIN invoices i ON i.student_id=s.id
    WHERE s.role='student' ORDER BY s.id DESC`).all()
    .map(r => ({ ...r, status: r.status === 'Unpaid' && r.due_date < today() ? 'Overdue' : r.status }));
  const paid = rows.filter(r => r.status === 'Paid');
  res.json({ rows, summary: { total: rows.length, paid: paid.length, unpaid: rows.length - paid.length,
    collected: paid.reduce((a, r) => a + r.amount, 0) } });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Running on port ' + PORT));
