// backend/server.js
dotenv.config();
import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { GoogleGenAI } from '@google/genai';
import { buildPrompt, parseModelJson } from './promptUtils.js';
import Room from './models/Room.js';
import Message from './models/Message.js';
import http from 'http';
import path from 'path';

import { Server } from 'socket.io';

const app = express();

const server = http.createServer(app);

app.use(cors({
  origin: 'http://localhost:5174',
  credentials: true,
}));

// Socket.IO CORS
const io = new Server(server, {
  cors: {
    origin: 'http://localhost:5174',
    methods: ['GET', 'POST'],
    credentials: true,
  },
});
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

// Optional: some auth middleware to set req.userId
app.get('/api/user', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user.toPublic());
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});


// Health
app.get('/api/health', (req, res) => res.json({ ok: true }));


const client = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY
});

// Model name
const MODEL_NAME = process.env.GEMINI_MODEL || 'gemini-2.0-flash';

const extractText = (r) => {
  if (!r) return null;

  // 1) if .text() exists and is function
  try {
    if (typeof r.text === 'function') {
      const maybe = r.text();
      if (typeof maybe === 'string' && maybe.trim()) return maybe.trim();
    }
  } catch (e) {
    // ignore
  }

  // 2) direct fields
  if (typeof r.outputText === 'string' && r.outputText.trim()) return r.outputText.trim();
  if (typeof r.text === 'string' && r.text.trim()) return r.text.trim();
  if (typeof r.output === 'string' && r.output.trim()) return r.output.trim();

  // 3) outputs -> content -> text
  if (Array.isArray(r.outputs) && r.outputs[0]) {
    const out0 = r.outputs[0];
    const maybe = out0?.content?.[0]?.text ?? out0?.text ?? out0?.outputText;
    if (typeof maybe === 'string' && maybe.trim()) return maybe.trim();
  }

  // 4) candidates -> content -> text
  if (Array.isArray(r.candidates) && r.candidates[0]) {
    const cand = r.candidates[0];
    const maybe = cand?.content?.[0]?.text ?? cand?.text ?? cand?.content;
    if (typeof maybe === 'string' && maybe.trim()) return maybe.trim();
  }

  // 5) results
  if (Array.isArray(r.results) && r.results[0]) {
    const maybe = r.results[0]?.outputText ?? r.results[0]?.text;
    if (typeof maybe === 'string' && maybe.trim()) return maybe.trim();
  }

  // 6) fallback if response itself is a string
  if (typeof r === 'string' && r.trim()) return r.trim();

  return null;
};

const FORCE_JSON_INSTRUCTION = `Return ONLY a single valid JSON object (no surrounding text). Example:
{"introduction":"...","key_concepts":["..."],"examples":["..."],"applications":["..."],"summary":"..."}
Respond exactly with the JSON object and nothing else.`;

app.post('/api/ai/chat', async (req, res) => {
  try {
    const { message, recent = [], temperature = 0.2 } = req.body;
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'message is required' });
    }

    // Build prompt with your helper (system + few-shot + recent + user)
    const prompt = buildPrompt(recent, message); // ensure promptUtils.js exports this

    // Call the model with the composed prompt
    const response = await client.models.generateContent({
      model: MODEL_NAME,
      contents: prompt,
      temperature,
      maxOutputTokens: 800,
    });

    // Extract text safely
    let text = extractText(response);

    // If extraction failed, try alternative shapes or log
    if (!text) {
      console.warn('Cannot extract text from model response. Dumping truncated shape for debugging.');
      console.warn(JSON.stringify(response).slice(0, 3000));
      return res.status(502).json({ error: 'Invalid model response', raw: response });
    }

    // Try parsing JSON using your helper
    let parsed = parseModelJson(text);

    // If parse failed, retry once instructing the model to return only JSON
    if (!parsed) {
      console.warn('Initial parse failed. Retrying with forced JSON instruction.');
      const retryPrompt = `${prompt}\n\n${FORCE_JSON_INSTRUCTION}\n\nUser: ${message}\nAssistant:`;
      try {
        const retryResp = await client.models.generateContent({
          model: MODEL_NAME,
          contents: retryPrompt,
          temperature,
          maxOutputTokens: 800,
        });
        const retryText = extractText(retryResp);
        parsed = parseModelJson(retryText);
        if (parsed) text = retryText; // replace with final JSON text
      } catch (retryErr) {
        console.warn('Retry parse call errored:', retryErr);
      }
    }

    // Optional: validate parsed shape minimally
    if (parsed) {
      const ok =
        typeof parsed.introduction === 'string' &&
        Array.isArray(parsed.key_concepts) &&
        Array.isArray(parsed.examples) &&
        Array.isArray(parsed.applications) &&
        typeof parsed.summary === 'string';
      if (!ok) {
        console.warn('Parsed JSON missing expected fields. Returning raw text with parsed=null.');
        parsed = null;
      }
    }

    return res.json({
      reply: text,       // raw text returned by model (or forced JSON)
      parsed: parsed || null,
      id: Date.now(),
      ai_source: `Gemini (${MODEL_NAME})`,
    });
  } catch (err) {
    console.error('AI error:', err);
    return res.status(500).json({ error: err?.message || 'Server error' });
  }
});

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

app.post('/api/rooms', async (req, res) => {
  try {
    const { title, subject = '', createdBy, expiresInMinutes } = req.body;
    if (!title || !createdBy) return res.status(400).json({ error: 'title and createdBy required' });

    const room = new Room({ title, subject, createdBy });
    if (expiresInMinutes) {
      room.expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000);
    }
    await room.save();
    return res.status(201).json(room);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server error' });
  }
});

app.get('/api/rooms', async (req, res) => {
  try {
    const rooms = await Room.find().sort({ createdAt: -1 }).lean();
    return res.json(rooms);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server error' });
  }
});

// Join a room (adds member)
app.post('/api/rooms/:roomId/join', async (req, res) => {
  try {
    const roomId = req.params.roomId;
    const { userId, username } = req.body;
    if (!userId || !username) return res.status(400).json({ error: 'userId and username required' });

    const room = await Room.findById(roomId);
    if (!room) return res.status(404).json({ error: 'room not found' });

    const exists = room.members.some(m => m.userId === userId);
    if (!exists) {
      room.members.push({ userId, username });
      await room.save();
    }

    return res.json(room);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server error' });
  }
});

// Get messages for a room (simple pagination)
app.get('/api/rooms/:roomId/messages', async (req, res) => {
  try {
    const { roomId } = req.params;
    const limit = parseInt(req.query.limit || '50', 10);
    const messages = await Message.find({ roomId }).sort({ createdAt: -1 }).limit(limit).lean();
    return res.json(messages.reverse()); // return chronological
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server error' });
  }
});

// ----------------- Socket.io events -----------------
io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  // join room
  socket.on('join-room', async ({ roomId, userId, username }) => {
    if (!roomId) return;
    socket.join(roomId);
    console.log(`socket ${socket.id} joined room ${roomId}`);

    // notify others
    socket.to(roomId).emit('user-joined', { userId, username, socketId: socket.id });

    // (optional) add to room members if not present
    try {
      const room = await Room.findById(roomId);
      if (room) {
        const exists = room.members.some(m => m.userId === userId);
        if (!exists) {
          room.members.push({ userId, username });
          await room.save();
          io.to(roomId).emit('room-updated', room);
        }
      }
    } catch (err) {
      console.error('error adding member to room', err);
    }
  });

  // handle text message
  socket.on('message', async (payload) => {
    // payload should be { roomId, userId, username, text }
    const { roomId, userId, username, text } = payload || {};
    if (!roomId || !userId || !text) return;

    try {
      const msg = new Message({
        roomId,
        userId,
        username,
        type: 'text',
        content: text,
        moderation: { status: 'pending' }
      });
      await msg.save();

      // run moderation asynchronously
      moderateMessage(msg).then(async (modResult) => {
        msg.moderation = modResult;
        await msg.save();
        io.to(roomId).emit('message-moderation', { messageId: msg._id, moderation: modResult });
      }).catch(err => {
        console.error('moderation error', err);
      });

      // broadcast message immediately (optimistic UI)
      io.to(roomId).emit('message', formatMessageForClient(msg));
    } catch (err) {
      console.error('error saving message', err);
    }
  });

  // WebRTC signaling: offer, answer, ice-candidate
  socket.on('webrtc-offer', ({ toSocketId, from, sdp }) => {
    if (!toSocketId) return;
    io.to(toSocketId).emit('webrtc-offer', { fromSocketId: socket.id, from, sdp });
  });

  socket.on('webrtc-answer', ({ toSocketId, sdp }) => {
    if (!toSocketId) return;
    io.to(toSocketId).emit('webrtc-answer', { fromSocketId: socket.id, sdp });
  });

  socket.on('webrtc-ice-candidate', ({ toSocketId, candidate }) => {
    if (!toSocketId) return;
    io.to(toSocketId).emit('webrtc-ice-candidate', { fromSocketId: socket.id, candidate });
  });

  // handle leaving room
  socket.on('leave-room', ({ roomId, userId, username }) => {
    socket.leave(roomId);
    socket.to(roomId).emit('user-left', { userId, username, socketId: socket.id });
  });

  // disconnect
  socket.on('disconnect', () => {
    console.log('socket disconnected', socket.id);
    // optional: broadcast presence updates if you track socket->user mapping
  });
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


const blacklistedTokens = new Set();

app.post('/api/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(400).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  if (token) blacklistedTokens.add(token);

  return res.json({ success: true, message: 'Logged out' });
});

// update authMiddleware to check blacklist
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Invalid token' });

  if (blacklistedTokens.has(token)) {
    return res.status(401).json({ error: 'Token has been logged out' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}


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
