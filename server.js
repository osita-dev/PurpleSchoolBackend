// backend/server.js
dotenv.config();
import dotenv from 'dotenv';

import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
const app = express();


// Middleware
app.use(cors({
  origin: 'http://localhost:5173', // your frontend
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// --- Mongoose / User model (single-file) ---
const { Schema } = mongoose;

const UserSchema = new Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  full_name: { type: String },
  school_name: { type: String },
  class_level: { type: String },
  state: { type: String },
  is_verified: { type: Boolean, default: false },
}, { timestamps: true });

UserSchema.methods.toPublic = function () {
  const obj = this.toObject();
  delete obj.passwordHash;
  delete obj.__v;
  return obj;
};

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- Helpers ---
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// --- Routes ---
// Health
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Register
app.post('/api/auth/signup', async (req, res) => {
  try {
    const {
      email,
      password,
      username,
      full_name = '',
      school_name = '',
      class_level = '',
      state = '',
    } = req.body;

    if (!email || !password || !username) {
      return res.status(400).json({ error: 'email, username and password are required' });
    }

    // check duplicates
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(409).json({ error: 'Email or username already in use' });

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
      email,
      passwordHash,
      username,
      full_name,
      school_name,
      class_level,
      state,
      is_verified: true,
    });

    await user.save();

    const token = signToken({ id: user._id });

    return res.status(201).json({ user: user.toPublic(), token });
  } catch (err) {
    console.error('Register error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ id: user._id });
    return res.json({ user: user.toPublic(), token });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Me (protected)
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({ user: user.toPublic() });
  } catch (err) {
    console.error('Me error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});
// -- Start server (connect to Mongo first) --
async function start() {
    try {
      
    await mongoose.connect(process.env.MONGO_URI, {
     
    });
    console.log('Mongo connected');
    app.listen(process.env.PORT || 5000, () => {
      console.log(`Server running on port ${process.env.PORT}`);
      console.log(`API endpoints: POST /api/auth/register, POST /api/auth/login, GET /api/auth/me`);
    });
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
}

start();
