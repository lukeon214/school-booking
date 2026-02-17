const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { PrismaClient } = require('@prisma/client');
const { PrismaPg } = require('@prisma/adapter-pg');
const { Pool } = require('pg');
const authRouter = require('./routes/auth');
const authMiddleware = require('./middleware/auth');
require('dotenv').config();

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

app.use(cors({ credentials: true, origin: 'http://localhost:4173' })); // Allow frontend
app.use(express.json());
app.use(cookieParser());

// Routes
app.use('/auth', authRouter);

// Test protected
app.get('/hello', authMiddleware, async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ message: 'Hello from backend! DB connected.', user: req.user });
  } catch (error) {
    res.status(500).json({ message: 'DB error', error: error.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));