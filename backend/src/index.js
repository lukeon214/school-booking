const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');
const { Pool } = require('pg');
const authMiddleware = require('./middleware/auth');
require('dotenv').config();

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

app.use(cors({
  origin: ['https://form.databooq.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(cookieParser());

app.get('/hello', authMiddleware, async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ message: 'Hello from backend! DB connected.', user: req.user });
      } catch (error) {
    res.status(500).json({ message: 'DB error', error: error.message });
}})

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ error: 'User exists' });

    const bcrypt = require('bcryptjs');
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, passwordHash },
    });

    const jwt = require('jsonwebtoken');
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, secure: true });  // secure: true for HTTPS
    res.json({ message: 'Registered', user: { id: user.id, email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const bcrypt = require('bcryptjs');
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    const jwt = require('jsonwebtoken');
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, secure: false });
    res.json({ message: 'Logged in', user: { id: user.id, email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: 'User not found' });

    const jwt = require('jsonwebtoken');
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await prisma.user.update({
      where: { id: user.id },
      data: { resetToken: token, resetTokenExpiry: new Date(Date.now() + 3600000) },
    });

    const nodemailer = require('nodemailer');
    var transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: true,  // false for Gmail 587
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      tls: { rejectUnauthorized: false },
    });

    await new Promise((resolve, reject) => {
      transport.verify((error, success) => {
        if (error) {
          console.error('SMTP verify error:', error);
          reject(error);
        } else {
          console.log('SMTP connection OK');
          resolve(success);
        }
      });
    });

    await transport.sendMail({
      from: process.env.SMTP_USER,
      to: email,
      subject: 'Password Reset',
      html: `<p>Click <a href="${process.env.APP_URL}/reset-password/${token}">here</a> to reset your password.</p>`,
    });

    res.json({ message: 'Reset link sent to email' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Error sending email' });
  }
});

app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });

  try {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
    if (!user || user.resetToken !== token || user.resetTokenExpiry < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const bcrypt = require('bcryptjs');
    const passwordHash = await bcrypt.hash(password, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: { passwordHash, resetToken: null, resetTokenExpiry: null },
    });

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    res.status(500).json({ error: 'Error resetting password' });
  }
});

app.get('/me', authMiddleware, async (req, res) => {
  res.json({ user: req.user });
});

app.get('/forms', authMiddleware, async (req, res) => {
  try {
    const forms = await prisma.form.findMany({
      where: { userId: req.user.userId },
      orderBy: { createdAt: 'desc' },
    });
    res.json(forms);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/forms', authMiddleware, async (req, res) => {
  const { title, description } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });

  try {
    const slug = title.toLowerCase().replace(/\s+/g, '-') + '-' + Math.random().toString(36).slice(2, 8); // Simple unique slug
    const form = await prisma.form.create({
      data: {
        userId: req.user.userId,
        title,
        description,
        schemaJson: { questions: [] }, // Empty for now
        slug,
      },
    });
    res.json(form);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/forms/:id', authMiddleware, async (req, res) => {
  try {
    const form = await prisma.form.findUnique({
      where: { id: parseInt(req.params.id) },
    });
    if (!form || form.userId !== req.user.userId) return res.status(404).json({ error: 'Not found' });
    res.json(form);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/forms/:id', authMiddleware, async (req, res) => {
  const { title, description, isPublished, schemaJson } = req.body;
  try {
    const form = await prisma.form.update({
      where: { id: parseInt(req.params.id) },
      data: { title, description, isPublished, schemaJson },
    });
    if (form.userId !== req.user.userId) return res.status(403).json({ error: 'Unauthorized' });
    res.json(form);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/forms/:id', authMiddleware, async (req, res) => {
  try {
    const form = await prisma.form.findUnique({ where: { id: parseInt(req.params.id) } });
    if (!form || form.userId !== req.user.userId) return res.status(404).json({ error: 'Not found' });
    await prisma.form.delete({ where: { id: parseInt(req.params.id) } });
    res.json({ message: 'Deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));