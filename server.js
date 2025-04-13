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

app.use((req, res, next) => {
  res.locals.user = req.session.userId || null;
  next();
});

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
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS forms (
      id TEXT PRIMARY KEY,
      title TEXT,
      user_id INTEGER,
      private INTEGER DEFAULT 0
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS fields (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      form_id TEXT,
      label TEXT NOT NULL,
      type TEXT NOT NULL,
      choices TEXT,
      max_responses INTEGER,
      FOREIGN KEY(form_id) REFERENCES forms(id)
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS answers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      form_id TEXT,
      field_id INTEGER,
      value TEXT,
      submission_id TEXT,
      user_id INTEGER,
      FOREIGN KEY(form_id) REFERENCES forms(id),
      FOREIGN KEY(field_id) REFERENCES fields(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  // OPTIONAL auto-migrate
  try {
    await db.exec(`ALTER TABLE forms ADD COLUMN private INTEGER DEFAULT 0`);
  } catch (e) { /* already exists */ }

  try {
    await db.exec(`ALTER TABLE answers ADD COLUMN user_id INTEGER`);
  } catch (e) { /* already exists */ }

})();

function requireLogin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

app.get('/', (req, res) => {
  res.render('index', { noSidebar: true });
});

// Register
app.get('/register', (req, res) => {
  const redirectTo = req.query.redirect || '/dashboard';
  res.render('register', {
    redirectTo,
    noSidebar: true,
    layout: false // ✅ needed to avoid layout.ejs
  });
});

app.post('/register', async (req, res) => {
  const { username, email, password, redirectTo } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    await db.run(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hash]
    );

    // Auto-login
    const user = await db.get('SELECT * FROM users WHERE username = ?', username);
    req.session.userId = user.id;

    res.redirect(redirectTo || '/dashboard');
  } catch {
    res.render('register', { error: 'Username or email already in use', redirectTo });
  }
});

// Login
app.get('/login', (req, res) => {
  const redirectTo = req.query.redirect || '/dashboard';
  res.render('login', { redirectTo, noSidebar: true, layout: false });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE username = ?', username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.render('login', { error: 'Invalid credentials', redirectTo: req.body.redirectTo || '/dashboard' });
  }

  req.session.userId = user.id;
  res.redirect(req.body.redirectTo || '/dashboard');
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
app.get('/create', requireLogin, (req, res) => {
  res.render('create');
});

app.post('/create', requireLogin, async (req, res) => {
  const { title, fieldsJSON } = req.body;
  const isPrivate = parseInt(req.body.private) === 1 ? 1 : 0;

  const fields = JSON.parse(fieldsJSON);
  const formId = uuidv4();

  // Insert form
  await db.run(
    'INSERT INTO forms (id, title, user_id, private) VALUES (?, ?, ?, ?)',
    [formId, title, req.session.userId, isPrivate]
  );

  // Insert fields
  const insert = await db.prepare('INSERT INTO fields (form_id, label, type, choices, max_responses) VALUES (?, ?, ?, ?, ?)');
  for (const f of fields) {
    const choices = f.choices?.length ? JSON.stringify(f.choices) : null;
    const max = f.maxResponses || null;
    await insert.run(formId, f.label, f.type, choices, max);
  }
  await insert.finalize();

  res.redirect('/dashboard');
});

// Display public form
app.get('/form/:id', async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ?', req.params.id);
  if (!form) return res.status(404).send('Form not found');

  if (form.private && !req.session.userId) {
    return res.redirect(`/login?redirect=/form/${form.id}`);
  }

  // Get fields and current usage per field
  const fields = await db.all(`
    SELECT f.*, COUNT(a.id) AS usage
    FROM fields f
    LEFT JOIN answers a ON a.field_id = f.id
    WHERE f.form_id = ?
    GROUP BY f.id
  `, [req.params.id]);

  res.render('form', {
    form,
    fields,
    success: req.query.success,
    layout: false
  });
});

// Submit public form
app.post('/form/:id', async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ?', req.params.id);
  if (!form) return res.status(404).send('Form not found');

  if (form.private && !req.session.userId) {
    return res.status(403).send('Login required for this form.');
  }

  const userId = form.private ? req.session.userId : null;
  const submissionId = uuidv4();

  // Get fields + usage
  const fields = await db.all(`
    SELECT f.*, COUNT(a.id) as usage
    FROM fields f LEFT JOIN answers a ON a.field_id = f.id
    WHERE f.form_id = ? GROUP BY f.id
  `, [req.params.id]);

  for (const field of fields) {
    if (field.max_responses && field.usage >= field.max_responses) continue;
    
    const key = `field_${field.id}`;
    const val = req.body[key];
    if (!val) continue;

    const values = Array.isArray(val) ? val : [val];

    for (const v of values) {
      await db.run(
        'INSERT INTO answers (form_id, field_id, value, submission_id, user_id) VALUES (?, ?, ?, ?, ?)',
        [req.params.id, field.id, v, submissionId, userId]
      );
    }
  }

  res.redirect(`/form/${req.params.id}/submitted`);
});

app.get('/form/:id/submitted', async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ?', req.params.id);
  if (!form) return res.status(404).send('Form not found');

  res.render('success', {
    formId: form.id,
    userId: req.session.userId || null
  });
});

// Panel
app.get('/panel/:id', requireLogin, async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId]);
  if (!form) return res.status(403).send('Forbidden');

  const raw = await db.all(`
    SELECT a.submission_id, a.user_id, f.label, a.value, u.email
    FROM answers a
    JOIN fields f ON f.id = a.field_id
    LEFT JOIN users u ON u.id = a.user_id
    WHERE a.form_id = ?
    ORDER BY a.id ASC
  `, [req.params.id]);

  const grouped = {};
  raw.forEach(row => {
    if (!grouped[row.submission_id]) {
      grouped[row.submission_id] = {
        email: row.email || 'Anonymous',
        fields: []
      };
    }
    grouped[row.submission_id].fields.push({
      label: row.label,
      value: row.value
    });
  });

  const responses = Object.values(grouped);
  res.render('panel', { form, responses });
});

app.get('/export/:id', requireLogin, async (req, res) => {
  const form = await db.get('SELECT * FROM forms WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId]);
  if (!form) return res.status(403).send('Forbidden');

  const raw = await db.all(`
    SELECT a.submission_id, a.user_id, f.label, a.value, u.email
    FROM answers a
    JOIN fields f ON f.id = a.field_id
    LEFT JOIN users u ON u.id = a.user_id
    WHERE a.form_id = ?
    ORDER BY a.id ASC
  `, [req.params.id]);

  const rowsBySubmission = {};
  for (const r of raw) {
    if (!rowsBySubmission[r.submission_id]) {
      rowsBySubmission[r.submission_id] = { email: r.email || 'Anonymous' };
    }
    rowsBySubmission[r.submission_id][r.label] = r.value;
  }

  const rows = Object.values(rowsBySubmission);

  if (rows.length === 0) return res.status(400).send('No submissions to export.');

  const fields = Object.keys(rows[0]);

  const csv = [
    fields.join(','),
    ...rows.map(r => fields.map(f => `"${(r[f] || '').replace(/"/g, '""')}"`).join(','))
  ].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="form_${form.id}_responses.csv"`);
  res.send(csv);
});

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));