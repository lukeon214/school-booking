const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const bcrypt = require('bcrypt');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = 3333;

app.set('view engine', 'ejs');
app.set('layout', 'layout'); // default layout
app.use(expressLayouts);
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
      password TEXT
    );

    CREATE TABLE IF NOT EXISTS forms (
      id TEXT PRIMARY KEY,
      title TEXT,
      user_id INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS responses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      form_id TEXT,
      name TEXT,
      choice TEXT,
      FOREIGN KEY(form_id) REFERENCES forms(id)
    );

    CREATE TABLE IF NOT EXISTS fields (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      form_id TEXT,
      label TEXT NOT NULL,
      type TEXT NOT NULL,       -- 'text' or 'choice'
      choices TEXT,             -- JSON array: ["A", "B", "C"] or NULL
      FOREIGN KEY(form_id) REFERENCES forms(id)
    );
  `);
})();

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.redirect('/login');
});

// Registration
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    await db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed]);
    res.redirect('/login');
  } catch {
    res.render('register', { error: "User exists." });
  }
});

// Login
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE username = ?', username);
  if (!user) return res.render('login', { error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.render('login', { error: 'Invalid credentials' });

  req.session.userId = user.id;
  res.redirect('/dashboard');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Dashboard
app.get('/dashboard', requireLogin, async (req, res) => {
  const forms = await db.all('SELECT * FROM forms WHERE user_id = ?', req.session.userId);
  res.render('dashboard', { forms });
});

// Delete
app.post('/delete/:id', requireLogin, async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId]);
  if (!form) return res.status(403).send('Unauthorized');

  await db.run('DELETE FROM responses WHERE form_id = ?', req.params.id);
  await db.run('DELETE FROM forms WHERE id = ?', req.params.id);

  res.redirect('/dashboard');
});

// Create form
app.get('/create', requireLogin, (req, res) => {
  res.render('create');
});

app.post('/create', requireLogin, async (req, res) => {
  const { title, fieldsJSON } = req.body;

  const id = uuidv4();
  const fields = JSON.parse(fieldsJSON);

  await db.run('INSERT INTO forms (id, title, user_id) VALUES (?, ?, ?)', [id, title, req.session.userId]);

  const insertField = await db.prepare('INSERT INTO fields (form_id, label, type, choices) VALUES (?, ?, ?, ?)');
  for (const f of fields) {
    const choices = (f.type === 'choice') ? JSON.stringify(f.choices) : null;
    await insertField.run(id, f.label, f.type, choices);
  }
  await insertField.finalize();

  res.redirect('/dashboard');
});

// View panel
app.get('/panel/:id', requireLogin, async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId]);
  if (!form) return res.status(403).send('Not authorized');
  const responses = await db.all('SELECT * FROM responses WHERE form_id = ?', req.params.id);
  res.render('panel', { form, responses });
});

// Public form view
app.get('/form/:id', async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ?', req.params.id);
  if (!form) return res.status(404).send('Form not found');
  const fields = await db.all('SELECT * FROM fields WHERE form_id = ?', req.params.id);

  res.render('form', { form, fields, success: req.query.success });
});

// Submit response
app.post('/form/:id', async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ?', req.params.id);
  const fields = await db.all('SELECT * FROM fields WHERE form_id = ?', req.params.id);
  if (!form || !fields.length) return res.status(400).send('Invalid form');

  const result = [];
  for (const field of fields) {
    const key = `field_${field.id}`;
    const val = req.body[key];
    if (!val) return res.status(400).send('Missing response');
    result.push(`${field.label}: ${val}`);
  }

  const formatted = result.join('; ');
  await db.run('INSERT INTO responses (form_id, name, choice) VALUES (?, ?, ?)', [req.params.id, `Anonymous`, formatted]);
  res.redirect(`/form/${req.params.id}?success=1`);
});

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));