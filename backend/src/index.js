const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');
const { Pool } = require('pg');
const { Resend } = require('resend');
const authMiddleware = require('./middleware/auth');
require('dotenv').config();

const resend = new Resend(process.env.RESEND_API_KEY);

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });
app.set('trust proxy', 1);

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
const multer = require('multer');

const upload = multer({ storage: multer.memoryStorage() });

app.use(cors({
  origin: ['https://form.databooq.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(cookieParser());

async function getFormStatus(form, prisma) {
  if (!form.isPublished) return 'draft';

  // Check close date
  if (form.closeDate && new Date() > new Date(form.closeDate)) {
    return 'closed';
  }

  // Check max total responses
  if (form.maxTotalResponses > 0) {
    const count = await prisma.submission.count({ where: { formId: form.id } });
    if (count >= form.maxTotalResponses) return 'closed';
  }

  return 'published';
}

// ====================== PROTECTED ROUTES ======================

app.get('/health', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: 'ok' });
  } catch {
    res.status(503).json({ status: 'degraded' });
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
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' });  // secure: true for HTTPS
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
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' });
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
    if (!user) {
      return res.json({ message: 'If that email exists, a reset link has been sent.' });
    }

    const jwt = require('jsonwebtoken');
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetToken: token,
        resetTokenExpiry: new Date(Date.now() + 3600000),
      },
    });

    const resetUrl = `${process.env.APP_URL}/reset-password/${token}`;

    await resend.emails.send({
      from: 'databooq <noreply@form.databooq.com>',
      to: email,
      subject: 'Reset your databooq password',
      html: `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          </head>
          <body style="margin:0;padding:0;background:#f5f7fa;font-family:'Helvetica Neue',Arial,sans-serif;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f7fa;padding:40px 0;">
              <tr>
                <td align="center">
                  <table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;width:100%;">

                    <!-- Logo / header -->
                    <tr>
                      <td align="center" style="padding-bottom:28px;">
                        <span style="font-size:1.6rem;font-weight:800;color:#2c3a75;letter-spacing:-0.5px;">
                          data<span style="color:#4f7fff;">booq</span>
                        </span>
                      </td>
                    </tr>

                    <!-- Card -->
                    <tr>
                      <td style="background:#ffffff;border-radius:18px;padding:40px 48px;border:1px solid #e8edf9;box-shadow:0 4px 24px rgba(80,120,200,0.08);">

                        <h1 style="margin:0 0 12px;font-size:1.5rem;font-weight:700;color:#2c3a75;">Reset your password</h1>
                        <p style="margin:0 0 28px;font-size:0.97rem;color:#778bab;line-height:1.65;">
                          We received a request to reset the password for your databooq account
                          (<strong style="color:#465183;">${email}</strong>).
                          Click the button below to choose a new password.
                        </p>

                        <!-- Button -->
                        <table cellpadding="0" cellspacing="0" style="margin-bottom:28px; display: flex; justify-content: center;">
                          <tr>
                            <td style="background:#4f7fff;border-radius:10px;">
                              <a href="${resetUrl}"
                                style="display:inline-block;padding:14px 32px;font-size:1rem;font-weight:700;color:#ffffff;text-decoration:none;border-radius:10px;">
                                Reset Password
                              </a>
                            </td>
                          </tr>
                        </table>

                        <p style="margin:0 0 8px;font-size:0.85rem;color:#9aabcc;line-height:1.6;">
                          This link expires in <strong>1 hour</strong>.
                          If you didn't request a password reset, you can safely ignore this email —
                          your password won't be changed.
                        </p>

                        <!-- Fallback URL -->
                        <p style="margin:20px 0 0;font-size:0.78rem;color:#b0bdda;">
                          If the button doesn't work, copy and paste this link:<br/>
                          <a href="${resetUrl}" style="color:#4f7fff;word-break:break-all;">${resetUrl}</a>
                        </p>

                      </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                      <td align="center" style="padding-top:24px;">
                        <p style="margin:0;font-size:0.78rem;color:#b0bdda;">
                          © ${new Date().getFullYear()} databooq · You're receiving this because you have an account at
                          <a href="https://form.databooq.com" style="color:#9aabcc;">form.databooq.com</a>
                        </p>
                      </td>
                    </tr>

                  </table>
                </td>
              </tr>
            </table>
          </body>
        </html>
      `,
    });

    res.json({ message: 'If that email exists, a reset link has been sent.' });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Error sending reset email' });
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
      return res.status(400).json({ error: 'Invalid or expired reset link.' });
    }

    const bcrypt = require('bcryptjs');
    const passwordHash = await bcrypt.hash(password, 10);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        resetToken: null,
        resetTokenExpiry: null,
      },
    });

    res.json({ message: 'Password reset successful' });

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
    }
    console.error('Reset password error:', error);
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
        closeDate: true,
        maxTotalResponses: true,
        createdAt: true,
        _count: { select: { submissions: true } },
        submissions: {
          orderBy: { submittedAt: 'desc' },
          take: 1,
          select: { submittedAt: true }
        }
      }
    });

    const formatted = await Promise.all(forms.map(async (f) => {
      const submissionCount = f._count.submissions;

      let status = 'draft';
      if (f.isPublished) {
        if (f.closeDate && new Date() > new Date(f.closeDate)) {
          status = 'closed';
        } else if (f.maxTotalResponses > 0 && submissionCount >= f.maxTotalResponses) {
          status = 'closed';
        } else {
          status = 'published';
        }
      }

      return {
        id:               f.id,
        publicId:         f.publicId,
        title:            f.title,
        description:      f.description,
        schemaJson:       f.schemaJson,
        isPublished:      f.isPublished,
        closeDate:        f.closeDate,
        maxTotalResponses: f.maxTotalResponses,
        createdAt:        f.createdAt,
        submissionCount,
        lastSubmittedAt:  f.submissions[0]?.submittedAt ?? null,
        status,
      };
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
        closeDate: true,
        maxTotalResponses: true,
        createdAt: true,
      }
    });

    if (!form || form.userId !== req.user.userId) {
      return res.status(404).json({ error: 'Form not found' });
    }
    res.json(form);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/forms/:publicId', authMiddleware, async (req, res) => {
  try {
    const { title, description, isPublished, schemaJson, closeDate, maxTotalResponses } = req.body;

    const form = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: { id: true, userId: true }
    });

    if (!form || form.userId !== req.user.userId) {
      return res.status(404).json({ error: 'Form not found or access denied' });
    }

    const updated = await prisma.form.update({
      where: { publicId: req.params.publicId },
      data: {
        ...(title !== undefined        && { title }),
        ...(description !== undefined  && { description }),
        ...(isPublished !== undefined  && { isPublished }),
        ...(schemaJson !== undefined   && { schemaJson }),
        ...(closeDate !== undefined    && { closeDate: closeDate ? new Date(closeDate) : null }),
        ...(maxTotalResponses !== undefined && { maxTotalResponses: parseInt(maxTotalResponses) || 0 }),
      },
    });

    res.json(updated);
  } catch (error) {
    console.error(error);
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

// ====================== qr code =======================
app.post('/forms/:publicId/qr', authMiddleware, async (req, res) => {
  console.log('QR route hit for:', req.params.publicId);
  try {
    const form = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: { id: true, userId: true, title: true }
    });

    if (!form || form.userId !== req.user.userId) {
      return res.status(404).json({ error: 'Form not found or access denied' });
    }

    const shareLink = `https://form.databooq.com/f/${req.params.publicId}`;
    const ecc = (req.body.ecc || 'M').toUpperCase();
    const tempRaw = path.join(__dirname, `qr-temp-${Date.now()}.raw`);
    const qrgenPath = path.join(__dirname, '..', 'qrgen');

    if (!fs.existsSync(qrgenPath)) {
      return res.status(500).json({ error: 'qrgen.exe not found in server directory' });
    }

    const qrProcess = spawn(qrgenPath, [shareLink, ecc, tempRaw], { stdio: 'pipe' });

    let dimData = '';
    qrProcess.stdout.on('data', data => { dimData += data.toString(); });
    qrProcess.stderr.on('data', () => {});

    qrProcess.on('error', err => {
      console.error('QR spawn error:', err.message);
      res.status(500).json({ error: `QR process failed: ${err.message}` });
    });

    qrProcess.on('close', async (code) => {
      console.log('QR process exited with code:', code);
      console.log('DIM output:', dimData.trim());
      if (code !== 0) {
        console.error('QR non-zero exit');
        return res.status(500).json({ error: 'QR generation failed' });
      }

      const match = dimData.trim().match(/^DIM (\d+)$/);
      if (!match) {
        return res.status(500).json({ error: 'Failed to parse QR dimensions' });
      }

      const size = parseInt(match[1]);

      if (!fs.existsSync(tempRaw)) {
        return res.status(500).json({ error: 'Raw file not generated' });
      }

      const rawBuffer = fs.readFileSync(tempRaw);
      fs.unlinkSync(tempRaw);

      try {
        const pngBuffer = await sharp(rawBuffer, {
          raw: { width: size, height: size, channels: 3 }
        })
          .png()
          .toBuffer();

        const base64 = pngBuffer.toString('base64');
        res.json({ image: `data:image/png;base64,${base64}` });
      } catch (err) {
        res.status(500).json({ error: `Image conversion failed: ${err.message}` });
      }
    });

  } catch(err) {
    console.error('Sharp error:', err);
    res.status(500).json({ error: err.message });
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
app.get('/f/:publicId/grid-counts', async (req, res) => {
  try {
    const form = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: {
        id: true,
        isPublished: true,
        schemaJson: true,
      }
    });

    if (!form || !form.isPublished) {
      return res.status(404).json({ error: 'Form not found' });
    }

    // Find all grid question IDs in this form
    const gridQuestions = (form.schemaJson.questions || [])
      .filter(q => q.type === 'grid')
      .map(q => q.id);

    if (gridQuestions.length === 0) {
      return res.json({});
    }

    // Fetch all submissions for this form
    const submissions = await prisma.submission.findMany({
      where: { formId: form.id },
      select: { dataJson: true },
    });

    // Count cell selections per grid question
    // Each submission's dataJson is the answers object: { [qId]: string | string[] | ... }
    const counts = {};

    for (const qId of gridQuestions) {
      counts[qId] = {};
    }

    for (const sub of submissions) {
      const data = sub.dataJson;
      if (!data || typeof data !== 'object') continue;

      for (const qId of gridQuestions) {
        const selection = data[qId];
        if (!Array.isArray(selection)) continue;

        for (const cellKey of selection) {
          if (typeof cellKey !== 'string') continue;
          counts[qId][cellKey] = (counts[qId][cellKey] || 0) + 1;
        }
      }
    }

    res.json(counts);

  } catch (error) {
    console.error('grid-counts error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/f/:publicId', async (req, res) => {
  try {
    const form = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: {
        id: true,
        publicId: true,
        title: true,
        description: true,
        schemaJson: true,
        isPublished: true,
        closeDate: true,
        maxTotalResponses: true,
      }
    });

    if (!form || !form.isPublished) {
      return res.status(404).json({ error: 'Form not found or not published.' });
    }

    let status = 'published';
    if (form.closeDate && new Date() > new Date(form.closeDate)) {
      status = 'closed';
    } else if (form.maxTotalResponses > 0) {
      const count = await prisma.submission.count({ where: { formId: form.id } });
      if (count >= form.maxTotalResponses) status = 'closed';
    }

    res.json({ ...form, status });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/f/:publicId', async (req, res) => {
  try {
    const form = await prisma.form.findUnique({
      where: { publicId: req.params.publicId },
      select: {
        id: true,
        isPublished: true,
        closeDate: true,
        maxTotalResponses: true,
        schemaJson: true,
      }
    });

    if (!form) {
      return res.status(404).json({ error: 'Form not found.' });
    }

    if (!form.isPublished) {
      return res.status(403).json({ error: 'This form is not published.' });
    }

    // ── Close date check ──
    if (form.closeDate && new Date() > new Date(form.closeDate)) {
      return res.status(403).json({
        error: 'This form is closed and no longer accepting responses.',
        reason: 'closeDate',
        closedAt: form.closeDate,
      });
    }

    // ── Max total responses check ──
    if (form.maxTotalResponses > 0) {
      const count = await prisma.submission.count({ where: { formId: form.id } });
      if (count >= form.maxTotalResponses) {
        return res.status(403).json({
          error: 'This form has reached its maximum number of responses.',
          reason: 'maxResponses',
        });
      }
    }

    // ── Save submission ──
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || null;

    const submission = await prisma.submission.create({
      data: {
        formId: form.id,
        dataJson: req.body,
        ip,
      }
    });

    res.json({ success: true, submissionId: submission.id });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// ====================== START SERVER ======================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));