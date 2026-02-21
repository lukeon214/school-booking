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
app.set('trust proxy', 1);

app.use(cors({
  origin: ['https://form.databooq.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(cookieParser());

// ====================== PROTECTED ROUTES ======================

app.get('/hello', authMiddleware, async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ message: 'Hello from backend! DB connected.', user: req.user });
  } catch (error) {
    res.status(500).json({ message: 'DB error', error: error.message });
  }
});

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
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: { id: true, email: true, createdAt: true }
    });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/forms', authMiddleware, async (req, res) => {
  try {
    const forms = await prisma.form.findMany({
      where: { userId: req.user.userId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        publicId: true,
        title: true,
        description: true,
        schemaJson: true,
        isPublished: true,
        createdAt: true,
        _count: {
          select: { submissions: true }
        },
        submissions: {
          orderBy: { submittedAt: 'desc' },
          take: 1,
          select: { submittedAt: true }
        }
      }
    });

    const formatted = forms.map(f => ({
      id:               f.id,
      publicId:         f.publicId,
      title:            f.title,
      description:      f.description,
      schemaJson:       f.schemaJson,
      isPublished:      f.isPublished,
      createdAt:        f.createdAt,
      submissionCount:  f._count.submissions,
      lastSubmittedAt:  f.submissions[0]?.submittedAt ?? null,
    }));

    res.json(formatted);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/forms', authMiddleware, async (req, res) => {
  const { title, description } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });

  try {
    const slug = title.toLowerCase().replace(/\s+/g, '-') + '-' + Math.random().toString(36).slice(2, 8);
    const form = await prisma.form.create({
      data: {
        userId: req.user.userId,
        title,
        description,
        schemaJson: { questions: [] },
        slug,
      },
    });
    res.json(form);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/forms/:publicId', authMiddleware, async (req, res) => {
  try {
    const form = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: {
        id: true,
        publicId: true,
        userId: true,
        title: true,
        description: true,
        schemaJson: true,
        isPublished: true,
        createdAt: true
      }
    });

    if (!form || form.userId !== req.user.userId) {
      return res.status(404).json({ error: 'Not found' });
    }
    res.json(form);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/forms/:publicId', authMiddleware, async (req, res) => {
  const { title, description, isPublished, schemaJson } = req.body;
  try {
    const existingForm = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: { userId: true }
    });

    if (!existingForm || existingForm.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const form = await prisma.form.update({
      where: { publicId: req.params.publicId },
      data: { title, description, isPublished, schemaJson },
    });
    res.json(form);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/forms/:publicId', authMiddleware, async (req, res) => {
  try {
    const form = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: { userId: true }
    });

    if (!form || form.userId !== req.user.userId) {
      return res.status(404).json({ error: 'Not found' });
    }

    await prisma.form.delete({ where: { publicId: req.params.publicId } });
    res.json({ message: 'Deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ====================== STATS  ======================

app.get('/forms/:publicId/submissions', authMiddleware, async (req, res) => {
  try {
    const form = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: {
        id: true,
        publicId: true,
        userId: true,
        title: true,
        description: true,
        schemaJson: true,
        createdAt: true
      }
    });

    if (!form || form.userId !== req.user.userId) {
      return res.status(404).json({ error: 'Form not found or access denied' });
    }

    const submissions = await prisma.submission.findMany({
      where: { formId: form.id },
      orderBy: { submittedAt: 'desc' },
      select: {
        id: true,
        dataJson: true,
        submittedAt: true
      }
    });

    res.json({
      form,
      submissions,
      totalSubmissions: submissions.length
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to load responses' });
  }
});

app.delete('/forms/:publicId/submissions/:id', authMiddleware, async (req, res) => {
  const form = await prisma.form.findUnique({
    where: { publicId: req.params.publicId },
    select: { id: true, userId: true }
  });
  if (!form || form.userId !== req.user.userId)
    return res.status(404).json({ error: 'Not found' });

  await prisma.submission.deleteMany({
    where: { id: parseInt(req.params.id), formId: form.id }
  });
  res.json({ success: true });
});

// ====================== PUBLIC FORM ROUTES ======================

app.get('/f/:publicId', async (req, res) => {
  try {
    const form = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: { 
        publicId: true,
        title: true,
        description: true,
        schemaJson: true,
        isPublished: true 
      }
    });

    if (!form || !form.isPublished) {
      return res.status(404).json({ error: 'Form not found or not published' });
    }

    res.json(form);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/f/:publicId/submit', async (req, res) => {
  const { publicId } = req.params;
  const { data } = req.body;

  if (!data || typeof data !== 'object') {
    return res.status(400).json({ error: 'Invalid submission data' });
  }

  try {
    const form = await prisma.form.findUnique({
      where: { publicId },
      select: { id: true, isPublished: true, schemaJson: true }
    });

    if (!form || !form.isPublished) {
      return res.status(404).json({ error: 'Form not found or not published' });
    }

    // Increment used count for every selected grid cell
    const schemaJson = { ...form.schemaJson };
    Object.keys(data).forEach(qId => {
      const answer = data[qId];
      if (Array.isArray(answer)) { // grid answer
        answer.forEach(cellKey => {
          const q = schemaJson.questions.find(q => q.id === qId);
          if (q && q.type === 'grid' && q.cells[cellKey]) {
            q.cells[cellKey].used = (q.cells[cellKey].used || 0) + 1;
          }
        });
      }
    });

    // Save updated counts
    await prisma.form.update({
      where: { id: form.id },
      data: { schemaJson }
    });

    await prisma.submission.create({
      data: {
        formId: form.id,
        dataJson: data,
        ip: req.ip || req.headers['x-forwarded-for'] || null
      }
    });

    res.json({ success: true, message: 'Thank you!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to save response' });
  }
});

// ====================== START SERVER ======================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));