const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const { v4: uuidv4 } = require('uuid');
const expressLayouts = require('express-ejs-layouts');

const app = express();
const PORT = 3333;

app.set('view engine', 'ejs');
app.use(expressLayouts);
app.set('layout', 'layout');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'forms-secret',
  resave: false,
  saveUninitialized: false
}));

let db;
(async () => {
  db = await open({
    filename: './database.db',
    driver: sqlite3.Database
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT
    );

    CREATE TABLE IF NOT EXISTS forms (
      id TEXT PRIMARY KEY,
      title TEXT,
      user_id INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS fields (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      form_id TEXT,
      label TEXT NOT NULL,
      type TEXT NOT NULL,
      choices TEXT,
      max_responses INTEGER,
      FOREIGN KEY(form_id) REFERENCES forms(id)
    );

    CREATE TABLE IF NOT EXISTS answers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      form_id TEXT,
      field_id INTEGER,
      value TEXT,
      submission_id TEXT,  -- New column
      FOREIGN KEY(form_id) REFERENCES forms(id),
      FOREIGN KEY(field_id) REFERENCES fields(id)
    );
  `);
})();

try {
  await db.exec('ALTER TABLE answers ADD COLUMN user_id INTEGER');
} catch (e) {
}

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.redirect('/login');
});

// Register
app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    await db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash]);
    res.redirect('/login');
  } catch {
    res.render('register', { error: 'Username or email already in use' });
  }
});

// Login
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const user = await db.get('SELECT * FROM users WHERE username = ?', req.body.username);
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.render('login', { error: 'Invalid credentials' });
  }
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Dashboard
app.get('/dashboard', requireLogin, async (req, res) => {
  const forms = await db.all('SELECT * FROM forms WHERE user_id = ?', req.session.userId);
  res.render('dashboard', { forms });
});

app.post('/delete/:id', requireLogin, async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId]);
  if (!form) return res.status(403).send('Forbidden');
  await db.run('DELETE FROM answers WHERE form_id = ?', req.params.id);
  await db.run('DELETE FROM fields WHERE form_id = ?', req.params.id);
  await db.run('DELETE FROM forms WHERE id = ?', req.params.id);
  res.redirect('/dashboard');
});

// Create Form
app.get('/create', requireLogin, (req, res) => res.render('create'));

app.post('/create', requireLogin, async (req, res) => {
  const { title, fieldsJSON } = req.body;
  const fields = JSON.parse(fieldsJSON);
  const formId = uuidv4();

  await db.run(`INSERT INTO forms (id, title, user_id) VALUES (?, ?, ?)`, [formId, title, req.session.userId]);

  const insert = await db.prepare('INSERT INTO fields (form_id, label, type, choices, max_responses) VALUES (?, ?, ?, ?, ?)');
  for (let field of fields) {
    const choices = field.choices?.length ? JSON.stringify(field.choices) : null;
    const limit = field.maxResponses || null;
    await insert.run(formId, field.label, field.type, choices, limit);
  }
  await insert.finalize();
  res.redirect('/dashboard');
});

// Display public form
app.get('/form/:id', async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ?', req.params.id);
  if (!form) return res.status(404).send('Form not found');

  const fields = await db.all(`
    SELECT f.*, COUNT(a.id) as usage
    FROM fields f LEFT JOIN answers a ON a.field_id = f.id
    WHERE f.form_id = ? GROUP BY f.id
  `, [req.params.id]);

  res.render('form', { form, fields, success: req.query.success });
});

// Submit public form
app.post('/form/:id', async (req, res) => {
  const fields = await db.all(`
    SELECT f.*, COUNT(a.id) as usage
    FROM fields f LEFT JOIN answers a ON a.field_id = f.id
    WHERE f.form_id = ? GROUP BY f.id
  `, [req.params.id]);

  const userId = req.session.userId || null;
  const submissionId = uuidv4();

  for (const field of fields) {
    if (field.max_responses && field.usage >= field.max_responses) continue;
    const key = `field_${field.id}`;
    const val = req.body[key];
    if (!val) continue;

    const values = Array.isArray(val) ? val : [val];
    for (const v of values) {
      await db.run(
        `INSERT INTO answers (form_id, field_id, value, submission_id, user_id)
        VALUES (?, ?, ?, ?, ?)`,
        [req.params.id, field.id, v, submissionId, userId]
      );
    }
  }

  res.redirect(`/form/${req.params.id}?success=1`);
});

// Panel
app.get('/panel/:id', requireLogin, async (req, res) => {
  const raw = await db.all(`
    SELECT a.submission_id, a.user_id, f.label, a.value, u.email
    FROM answers a
    JOIN fields f ON f.id = a.field_id
    LEFT JOIN users u ON u.id = a.user_id
    WHERE a.form_id = ?
    ORDER BY a.id ASC
  `, [req.params.id]);
  
  // Group by submission_id
  const grouped = {};
  raw.forEach(row => {
    if (!grouped[row.submission_id]) {
      grouped[row.submission_id] = { email: row.email || 'Anonymous', fields: [] };
    }
    grouped[row.submission_id].fields.push({ label: row.label, value: row.value });
  });
  
  const submissions = Object.values(grouped).reverse();

  const fieldGroups = Object.values(submissions).reverse(); // newest first
  res.render('panel', { form, responses: fieldGroups });
});

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));