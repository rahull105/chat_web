import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';

import bcrypt from 'bcryptjs';
import cors from 'cors';
import express from 'express';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { Server } from 'socket.io';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.resolve(process.env.DATA_DIR ?? path.join(__dirname, 'data'));
const DB_PATH = path.join(DATA_DIR, 'db.json');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const FRONTEND_DIST_DIR = path.join(__dirname, '..', 'dist');

const PORT = Number(process.env.PORT ?? 3001);
const NODE_ENV = process.env.NODE_ENV ?? 'development';
const DEFAULT_JWT_SECRET = 'change-me-in-production';
const configuredJwtSecret = String(process.env.JWT_SECRET ?? '').trim();
const missingStrongJwtSecret =
  !configuredJwtSecret || configuredJwtSecret === DEFAULT_JWT_SECRET;
const JWT_SECRET =
  NODE_ENV === 'production' && missingStrongJwtSecret
    ? crypto.randomBytes(48).toString('hex')
    : configuredJwtSecret || DEFAULT_JWT_SECRET;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN ?? '*';
const ORIGIN_ALLOWLIST = CLIENT_ORIGIN.split(',')
  .map((entry) => entry.trim())
  .filter(Boolean);
const ALLOW_ALL_ORIGINS = ORIGIN_ALLOWLIST.includes('*');

if (NODE_ENV === 'production' && missingStrongJwtSecret) {
  console.warn(
    '[security] JWT_SECRET is not set. Using a temporary runtime secret; existing tokens will be invalid after restart. Configure JWT_SECRET in environment variables.',
  );
}

const DEFAULT_DB = {
  users: [],
  chats: [],
  messages: [],
  statuses: [],
};

const STATUS_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_NAME_LENGTH = 30;
const MAX_EMAIL_LENGTH = 160;
const MAX_ABOUT_LENGTH = 120;
const MAX_PASSWORD_LENGTH = 72;
const MAX_MESSAGE_LENGTH = 4000;

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const STRONG_PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[ !"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]).{8,72}$/;

const ALLOWED_UPLOAD_MIME_TYPES = new Set([
  'application/pdf',
  'application/zip',
  'application/x-zip-compressed',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'text/plain',
]);

const BLOCKED_UPLOAD_EXTENSIONS = new Set([
  '.bat',
  '.cmd',
  '.com',
  '.cpl',
  '.exe',
  '.jar',
  '.js',
  '.msi',
  '.ps1',
  '.scr',
  '.sh',
]);

const avatarPalette = [
  '#0f9d58',
  '#f4b400',
  '#4285f4',
  '#db4437',
  '#7a4cff',
  '#00a0dc',
  '#f57c00',
  '#00897b',
  '#6d4c41',
  '#5c6bc0',
  '#d81b60',
  '#43a047',
];

function ensureStorage() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });

  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(DEFAULT_DB, null, 2), 'utf-8');
  }
}

function readDb() {
  try {
    const content = fs.readFileSync(DB_PATH, 'utf-8');
    const parsed = JSON.parse(content);
    return {
      users: (parsed.users ?? []).map((user) => ({
        ...user,
        avatarUrl: user.avatarUrl ?? null,
      })),
      chats: (parsed.chats ?? []).map((chat) => ({
        ...chat,
        avatarUrl: chat.avatarUrl ?? null,
      })),
      messages: (parsed.messages ?? []).map((message) => ({
        ...message,
        attachments: Array.isArray(message.attachments) ? message.attachments : [],
        seenBy: Array.isArray(message.seenBy) ? message.seenBy : [],
        reactions: Array.isArray(message.reactions) ? message.reactions : [],
        pinnedBy: Array.isArray(message.pinnedBy) ? message.pinnedBy : [],
        pinnedAt: message.pinnedAt ?? null,
        encryption: message.encryption ?? null,
      })),
      statuses: (parsed.statuses ?? []).map((status) => ({
        ...status,
        viewers: Array.isArray(status.viewers) ? status.viewers : [],
      })),
    };
  } catch {
    return structuredClone(DEFAULT_DB);
  }
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf-8');
}

function colorFromSeed(seed) {
  let hash = 0;
  for (const char of seed) {
    hash = (hash << 5) - hash + char.charCodeAt(0);
    hash |= 0;
  }
  return avatarPalette[Math.abs(hash) % avatarPalette.length];
}

function sanitizeUser(user) {
  const { passwordHash, ...safeUser } = user;
  return safeUser;
}

function createToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

function findUser(db, userId) {
  return db.users.find((entry) => entry.id === userId);
}

function findUserByEmail(db, email) {
  return db.users.find((entry) => entry.email === email.toLowerCase().trim());
}

function findChat(db, chatId) {
  return db.chats.find((entry) => entry.id === chatId);
}

function isChatMember(chat, userId) {
  return chat.members.includes(userId);
}

function getLastMessage(db, chatId) {
  const messages = db.messages
    .filter((message) => message.chatId === chatId)
    .sort((a, b) => +new Date(a.createdAt) - +new Date(b.createdAt));
  return messages.at(-1) ?? null;
}

function shapeMessage(db, message) {
  const sender = findUser(db, message.senderId);
  const replySource = message.replyTo
    ? db.messages.find((entry) => entry.id === message.replyTo)
    : null;
  const replySender = replySource ? findUser(db, replySource.senderId) : null;

  return {
    ...message,
    reactions: message.reactions ?? [],
    pinnedAt: message.pinnedAt ?? null,
    pinnedBy: message.pinnedBy ?? [],
    encryption: message.encryption ?? null,
    sender: sender ? sanitizeUser(sender) : null,
    replyToMessage: replySource
      ? {
          id: replySource.id,
          text: replySource.isDeleted
            ? 'This message was deleted'
            : replySource.encryption
              ? 'Encrypted message'
              : replySource.text,
          senderId: replySource.senderId,
          senderName: replySender?.name ?? replySender?.email ?? 'Unknown',
        }
      : null,
  };
}

function shapeChatForUser(db, chat, userId) {
  const members = chat.members
    .map((memberId) => findUser(db, memberId))
    .filter(Boolean)
    .map(sanitizeUser);

  const directPeer =
    chat.type === 'direct' ? members.find((member) => member.id !== userId) ?? null : null;

  const lastMessage = getLastMessage(db, chat.id);
  const pinnedCount = db.messages.filter((message) => message.chatId === chat.id && message.pinnedAt).length;

  const unreadCount = db.messages.reduce((count, message) => {
    if (message.chatId !== chat.id) {
      return count;
    }
    if (message.senderId === userId || message.isDeleted) {
      return count;
    }
    const alreadySeen = message.seenBy.some((seenEntry) => seenEntry.userId === userId);
    return alreadySeen ? count : count + 1;
  }, 0);

  const title = chat.type === 'group' ? chat.name : directPeer?.name ?? directPeer?.email ?? 'New chat';
  const subtitle = chat.type === 'group' ? chat.description : directPeer?.about ?? '';

  return {
    ...chat,
    title,
    subtitle,
    avatarColor: chat.type === 'group' ? chat.avatarColor : directPeer?.avatarColor ?? chat.avatarColor,
    avatarUrl: chat.type === 'group' ? chat.avatarUrl ?? null : directPeer?.avatarUrl ?? chat.avatarUrl ?? null,
    directPeer,
    members,
    unreadCount,
    pinnedCount,
    lastMessage: lastMessage ? shapeMessage(db, lastMessage) : null,
  };
}

function markChatAsRead(db, chatId, userId) {
  const seenAt = new Date().toISOString();
  const updatedIds = [];

  for (const message of db.messages) {
    if (message.chatId !== chatId || message.senderId === userId || message.isDeleted) {
      continue;
    }

    const alreadySeen = message.seenBy.some((entry) => entry.userId === userId);
    if (!alreadySeen) {
      message.seenBy.push({ userId, at: seenAt });
      updatedIds.push(message.id);
    }
  }

  return { seenAt, updatedIds };
}

function createMessageRecord({ chatId, senderId, text, attachments, replyTo }) {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(),
    chatId,
    senderId,
    text,
    attachments,
    replyTo: replyTo || null,
    createdAt: now,
    editedAt: null,
    isDeleted: false,
    seenBy: [{ userId: senderId, at: now }],
    reactions: [],
    pinnedBy: [],
    pinnedAt: null,
    encryption: null,
  };
}

function emitChatListUpdate(io, memberIds) {
  for (const memberId of memberIds) {
    io.to(`user:${memberId}`).emit('chat:list:update');
  }
}

function emitPresence(io, onlineUsers) {
  io.emit('presence:update', { userIds: [...onlineUsers.keys()] });
}

function messagePreview(message) {
  if (!message || message.isDeleted) {
    return 'Message deleted';
  }

  if (message.encryption) {
    return 'Encrypted message';
  }

  if (message.attachments.length > 0 && !message.text) {
    return message.attachments.length === 1 ? 'Attachment' : `${message.attachments.length} attachments`;
  }

  if (message.attachments.length > 0 && message.text) {
    return `${message.text} (${message.attachments.length} files)`;
  }

  return message.text;
}

function asErrorMessage(error) {
  if (typeof error === 'string') {
    return error;
  }
  return error instanceof Error ? error.message : 'Request failed';
}

function getChatOrThrow(db, chatId) {
  const chat = findChat(db, chatId);
  if (!chat) {
    throw new Error('Chat not found.');
  }
  return chat;
}

function findMessage(db, messageId) {
  return db.messages.find((entry) => entry.id === messageId);
}

function cleanupStatuses(db) {
  const now = Date.now();
  db.statuses = db.statuses.filter((status) => new Date(status.expiresAt).getTime() > now);
}

function shapeStatus(db, status, viewerId) {
  const owner = findUser(db, status.userId);
  return {
    ...status,
    user: owner ? sanitizeUser(owner) : null,
    seen: status.viewers.includes(viewerId),
  };
}

function removeUploadFileIfExists(fileUrl) {
  if (!fileUrl || typeof fileUrl !== 'string' || !fileUrl.startsWith('/uploads/')) {
    return;
  }

  const filename = path.basename(fileUrl);
  const targetPath = path.join(UPLOAD_DIR, filename);
  if (fs.existsSync(targetPath)) {
    fs.unlinkSync(targetPath);
  }
}

function isOriginAllowed(origin) {
  if (!origin) {
    return true;
  }

  if (ALLOW_ALL_ORIGINS) {
    return true;
  }

  return ORIGIN_ALLOWLIST.includes(origin);
}

function normalizeText(value, maxLength) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim()
    .slice(0, maxLength);
}

function normalizeEmail(value) {
  return normalizeText(value, MAX_EMAIL_LENGTH).toLowerCase();
}

function normalizeMessage(value) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .trim();
}

function isStrongPassword(password) {
  return STRONG_PASSWORD_REGEX.test(password);
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress ?? 'unknown';
}

const rateLimitBuckets = new Map();

function createRateLimiter({ windowMs, max, keyPrefix, message }) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${keyPrefix}:${getClientIp(req)}`;
    const current = rateLimitBuckets.get(key);

    if (!current || current.resetAt <= now) {
      rateLimitBuckets.set(key, {
        count: 1,
        resetAt: now + windowMs,
      });
      return next();
    }

    if (current.count >= max) {
      const retryAfterSeconds = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({ message });
    }

    current.count += 1;
    rateLimitBuckets.set(key, current);
    return next();
  };
}

const registerLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  keyPrefix: 'register',
  message: 'Too many registration attempts. Please try again later.',
});

const loginLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 12,
  keyPrefix: 'login',
  message: 'Too many login attempts. Please try again later.',
});

const messageLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 60,
  keyPrefix: 'message',
  message: 'Too many messages in a short time. Please slow down.',
});

ensureStorage();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=()');

  const contentSecurityPolicy = [
    "default-src 'self'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https:",
    "media-src 'self' data: blob:",
    "connect-src 'self' https: ws: wss:",
    "form-action 'self'",
  ].join('; ');

  res.setHeader('Content-Security-Policy', contentSecurityPolicy);

  const forwardedProto = req.headers['x-forwarded-proto'];
  if (req.secure || forwardedProto === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }

  next();
});

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: (origin, callback) => {
      if (isOriginAllowed(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error('Origin not allowed by CORS'));
    },
  },
});

app.use(
  cors({
    origin: (origin, callback) => {
      if (isOriginAllowed(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error('Origin not allowed by CORS'));
    },
    credentials: true,
  }),
);
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));

const upload = multer({
  storage: multer.diskStorage({
    destination(_req, _file, callback) {
      callback(null, UPLOAD_DIR);
    },
    filename(_req, file, callback) {
      const extension = path.extname(file.originalname || '');
      callback(null, `${Date.now()}-${crypto.randomUUID()}${extension}`);
    },
  }),
  limits: {
    files: 5,
    fileSize: 15 * 1024 * 1024,
  },
  fileFilter(_req, file, callback) {
    const extension = path.extname(file.originalname ?? '').toLowerCase();
    const mimeType = String(file.mimetype ?? '').toLowerCase();

    if (BLOCKED_UPLOAD_EXTENSIONS.has(extension)) {
      callback(new Error('Unsupported file type.'));
      return;
    }

    if (
      mimeType.startsWith('image/') ||
      mimeType.startsWith('video/') ||
      mimeType.startsWith('audio/') ||
      ALLOWED_UPLOAD_MIME_TYPES.has(mimeType)
    ) {
      callback(null, true);
      return;
    }

    callback(new Error('Unsupported file type.'));
  },
});

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';

  if (!token) {
    return res.status(401).json({ message: 'Authentication required.' });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const db = readDb();
    const user = findUser(db, payload.userId);

    if (!user) {
      return res.status(401).json({ message: 'Invalid token.' });
    }

    req.userId = user.id;
    req.user = sanitizeUser(user);
    return next();
  } catch {
    return res.status(401).json({ message: 'Invalid token.' });
  }
}

function buildChatIfMissing(db, userAId, userBId) {
  const existing = db.chats.find((chat) => {
    if (chat.type !== 'direct') {
      return false;
    }
    const members = [...chat.members].sort();
    const pair = [userAId, userBId].sort();
    return members.length === 2 && members[0] === pair[0] && members[1] === pair[1];
  });

  if (existing) {
    return existing;
  }

  const now = new Date().toISOString();
  const chat = {
    id: crypto.randomUUID(),
    type: 'direct',
    name: null,
    description: '',
    members: [userAId, userBId],
    admins: [userAId],
    createdBy: userAId,
    createdAt: now,
    updatedAt: now,
    lastMessageAt: now,
    avatarColor: colorFromSeed(`${userAId}-${userBId}`),
    avatarUrl: null,
  };

  db.chats.push(chat);
  return chat;
}

function createAndBroadcastMessage({
  chatId,
  senderId,
  text,
  attachments,
  replyTo,
  encryption,
}) {
  const db = readDb();
  const chat = findChat(db, chatId);

  if (!chat) {
    throw new Error('Chat not found.');
  }

  if (!isChatMember(chat, senderId)) {
    throw new Error('You are not a member of this chat.');
  }

  const cleanText = normalizeMessage(text);
  if (cleanText.length > MAX_MESSAGE_LENGTH) {
    throw new Error('Message is too long.');
  }

  if (!cleanText && attachments.length === 0) {
    throw new Error('Message cannot be empty.');
  }

  if (replyTo) {
    const replyMessage = db.messages.find((message) => message.id === replyTo);
    if (!replyMessage || replyMessage.chatId !== chatId) {
      throw new Error('Reply target does not exist in this chat.');
    }
  }

  const message = createMessageRecord({
    chatId,
    senderId,
    text: cleanText,
    attachments,
    replyTo,
  });
  message.encryption = encryption ?? null;

  db.messages.push(message);

  const now = new Date().toISOString();
  chat.updatedAt = now;
  chat.lastMessageAt = now;

  writeDb(db);

  const shapedMessage = shapeMessage(db, message);

  io.to(`chat:${chatId}`).emit('message:new', {
    chatId,
    message: shapedMessage,
    preview: messagePreview(message),
  });

  emitChatListUpdate(io, chat.members);

  return shapedMessage;
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.post('/api/auth/register', registerLimiter, async (req, res) => {
  try {
    const name = normalizeText(req.body?.name, MAX_NAME_LENGTH);
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password ?? '');

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Name, email and password are required.' });
    }

    if (name.length < 2) {
      return res.status(400).json({ message: 'Username must be at least 2 characters.' });
    }

    if (!EMAIL_REGEX.test(email)) {
      return res.status(400).json({ message: 'Enter a valid email address.' });
    }

    if (password.length > MAX_PASSWORD_LENGTH) {
      return res.status(400).json({ message: 'Password is too long.' });
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json({
        message:
          'Password must be 8-72 chars and include uppercase, lowercase, number and symbol.',
      });
    }

    const db = readDb();

    if (findUserByEmail(db, email)) {
      return res.status(409).json({ message: 'This email is already registered.' });
    }

    const now = new Date().toISOString();
    const user = {
      id: crypto.randomUUID(),
      name,
      email,
      passwordHash: await bcrypt.hash(password, 10),
      about: 'Hey there! I am using chatrix.',
      avatarColor: colorFromSeed(email),
      avatarUrl: null,
      createdAt: now,
      lastSeen: null,
    };

    db.users.push(user);
    writeDb(db);

    const token = createToken(user.id);
    return res.status(201).json({ token, user: sanitizeUser(user) });
  } catch (error) {
    return res.status(500).json({ message: asErrorMessage(error) });
  }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password ?? '');

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    if (password.length > MAX_PASSWORD_LENGTH) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }

    const db = readDb();
    const user = findUserByEmail(db, email);

    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    user.lastSeen = new Date().toISOString();
    writeDb(db);

    const token = createToken(user.id);
    return res.json({ token, user: sanitizeUser(user) });
  } catch (error) {
    return res.status(500).json({ message: asErrorMessage(error) });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  return res.json({ user: req.user });
});

app.patch('/api/auth/me', requireAuth, (req, res) => {
  try {
    const name = normalizeText(req.body?.name, MAX_NAME_LENGTH);
    const about = normalizeText(req.body?.about, MAX_ABOUT_LENGTH);

    if (!name) {
      return res.status(400).json({ message: 'Name cannot be empty.' });
    }

    if (name.length < 2) {
      return res.status(400).json({ message: 'Name must be at least 2 characters.' });
    }

    const db = readDb();
    const user = findUser(db, req.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    user.name = name;
    user.about = about;

    writeDb(db);

    io.to(`user:${user.id}`).emit('profile:updated', { user: sanitizeUser(user) });

    return res.json({ user: sanitizeUser(user) });
  } catch (error) {
    return res.status(500).json({ message: asErrorMessage(error) });
  }
});

app.patch('/api/auth/me/avatar', requireAuth, upload.single('avatar'), (req, res) => {
  try {
    const file = req.file;
    if (!file) {
      return res.status(400).json({ message: 'Avatar image is required.' });
    }

    if (!String(file.mimetype ?? '').toLowerCase().startsWith('image/')) {
      removeUploadFileIfExists(`/uploads/${file.filename}`);
      return res.status(400).json({ message: 'Avatar must be an image file.' });
    }

    const db = readDb();
    const user = findUser(db, req.userId);
    if (!user) {
      removeUploadFileIfExists(`/uploads/${file.filename}`);
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.avatarUrl) {
      removeUploadFileIfExists(user.avatarUrl);
    }

    user.avatarUrl = `/uploads/${file.filename}`;
    writeDb(db);

    io.to(`user:${user.id}`).emit('profile:updated', { user: sanitizeUser(user) });
    return res.json({ user: sanitizeUser(user) });
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.delete('/api/auth/me/avatar', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const user = findUser(db, req.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.avatarUrl) {
      removeUploadFileIfExists(user.avatarUrl);
    }
    user.avatarUrl = null;
    writeDb(db);

    io.to(`user:${user.id}`).emit('profile:updated', { user: sanitizeUser(user) });
    return res.json({ user: sanitizeUser(user) });
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.get('/api/users/search', requireAuth, (req, res) => {
  const query = String(req.query.query ?? '').toLowerCase().trim();
  const db = readDb();

  const users = db.users
    .filter((user) => user.id !== req.userId)
    .filter((user) => {
      if (!query) {
        return true;
      }
      return user.email.includes(query) || user.name.toLowerCase().includes(query);
    })
    .slice(0, 25)
    .map(sanitizeUser);

  return res.json({ users });
});

app.get('/api/statuses', requireAuth, (req, res) => {
  const db = readDb();
  cleanupStatuses(db);
  writeDb(db);

  const statuses = db.statuses
    .sort((a, b) => +new Date(b.createdAt) - +new Date(a.createdAt))
    .map((status) => shapeStatus(db, status, req.userId));

  return res.json({ statuses });
});

app.post('/api/statuses', requireAuth, upload.single('file'), (req, res) => {
  try {
    const db = readDb();
    cleanupStatuses(db);

    const text = String(req.body?.text ?? '').trim().slice(0, 220);
    const file = req.file ?? null;

    if (!text && !file) {
      return res.status(400).json({ message: 'Status must include text or an image/video.' });
    }

    const now = Date.now();
    const status = {
      id: crypto.randomUUID(),
      userId: req.userId,
      text,
      attachment: file
        ? {
            id: crypto.randomUUID(),
            name: file.originalname,
            mimeType: file.mimetype,
            size: file.size,
            url: `/uploads/${file.filename}`,
          }
        : null,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + STATUS_TTL_MS).toISOString(),
      viewers: [req.userId],
    };

    db.statuses.push(status);
    writeDb(db);

    io.emit('status:new', { status: shapeStatus(db, status, req.userId) });

    return res.status(201).json({ status: shapeStatus(db, status, req.userId) });
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.post('/api/statuses/:statusId/view', requireAuth, (req, res) => {
  const db = readDb();
  cleanupStatuses(db);
  const status = db.statuses.find((entry) => entry.id === req.params.statusId);

  if (!status) {
    return res.status(404).json({ message: 'Status not found.' });
  }

  if (!status.viewers.includes(req.userId)) {
    status.viewers.push(req.userId);
    writeDb(db);
  } else {
    writeDb(db);
  }

  return res.json({ ok: true });
});

app.get('/api/chats', requireAuth, (req, res) => {
  const db = readDb();
  const chats = db.chats
    .filter((chat) => isChatMember(chat, req.userId))
    .sort((a, b) => +new Date(b.lastMessageAt ?? b.updatedAt) - +new Date(a.lastMessageAt ?? a.updatedAt))
    .map((chat) => shapeChatForUser(db, chat, req.userId));

  return res.json({ chats });
});

app.post('/api/chats/direct', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const rawEmail = String(req.body?.email ?? '').toLowerCase().trim();
    const rawUserId = String(req.body?.userId ?? '').trim();

    const targetUser = rawUserId
      ? findUser(db, rawUserId)
      : rawEmail
        ? findUserByEmail(db, rawEmail)
        : null;

    if (!targetUser) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (targetUser.id === req.userId) {
      return res.status(400).json({ message: 'Cannot create a direct chat with yourself.' });
    }

    const chat = buildChatIfMissing(db, req.userId, targetUser.id);
    writeDb(db);

    for (const memberId of chat.members) {
      io.in(`user:${memberId}`).socketsJoin(`chat:${chat.id}`);
    }

    emitChatListUpdate(io, chat.members);

    return res.status(201).json({ chat: shapeChatForUser(db, chat, req.userId) });
  } catch (error) {
    return res.status(500).json({ message: asErrorMessage(error) });
  }
});

app.post('/api/chats/group', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const name = String(req.body?.name ?? '').trim();
    const description = String(req.body?.description ?? '').trim();
    const memberIds = Array.isArray(req.body?.memberIds)
      ? req.body.memberIds.map((entry) => String(entry).trim())
      : [];

    if (name.length < 2) {
      return res.status(400).json({ message: 'Group name should be at least 2 characters.' });
    }

    const uniqueMembers = [...new Set([req.userId, ...memberIds])];

    const validMembers = uniqueMembers.filter((id) => findUser(db, id));

    if (validMembers.length < 2) {
      return res.status(400).json({ message: 'Choose at least one member for your group.' });
    }

    const now = new Date().toISOString();
    const chat = {
      id: crypto.randomUUID(),
      type: 'group',
      name: name.slice(0, 60),
      description: description.slice(0, 120),
      members: validMembers,
      admins: [req.userId],
      createdBy: req.userId,
      createdAt: now,
      updatedAt: now,
      lastMessageAt: now,
      avatarColor: colorFromSeed(name + req.userId),
      avatarUrl: null,
    };

    db.chats.push(chat);
    writeDb(db);

    for (const memberId of chat.members) {
      io.in(`user:${memberId}`).socketsJoin(`chat:${chat.id}`);
    }

    emitChatListUpdate(io, chat.members);

    return res.status(201).json({ chat: shapeChatForUser(db, chat, req.userId) });
  } catch (error) {
    return res.status(500).json({ message: asErrorMessage(error) });
  }
});

app.patch('/api/chats/:chatId', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const chat = findChat(db, req.params.chatId);

    if (!chat) {
      return res.status(404).json({ message: 'Chat not found.' });
    }

    if (!isChatMember(chat, req.userId)) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    if (chat.type !== 'group') {
      return res.status(400).json({ message: 'Only groups can be updated.' });
    }

    if (!chat.admins.includes(req.userId)) {
      return res.status(403).json({ message: 'Only group admins can update group details.' });
    }

    const name = String(req.body?.name ?? '').trim();
    const description = String(req.body?.description ?? '').trim();

    if (name) {
      chat.name = name.slice(0, 60);
    }
    chat.description = description.slice(0, 120);
    chat.updatedAt = new Date().toISOString();

    writeDb(db);

    io.to(`chat:${chat.id}`).emit('chat:updated', {
      chat: shapeChatForUser(db, chat, req.userId),
    });

    emitChatListUpdate(io, chat.members);

    return res.json({ chat: shapeChatForUser(db, chat, req.userId) });
  } catch (error) {
    return res.status(500).json({ message: asErrorMessage(error) });
  }
});

app.get('/api/chats/:chatId/messages', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const chat = findChat(db, req.params.chatId);

    if (!chat) {
      return res.status(404).json({ message: 'Chat not found.' });
    }

    if (!isChatMember(chat, req.userId)) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    const limit = Math.min(Math.max(Number(req.query.limit ?? 50), 1), 100);
    const before = String(req.query.before ?? '').trim();

    let messages = db.messages
      .filter((message) => message.chatId === chat.id)
      .sort((a, b) => +new Date(a.createdAt) - +new Date(b.createdAt));

    if (before) {
      messages = messages.filter((message) => message.createdAt < before);
    }

    const startIndex = Math.max(messages.length - limit, 0);
    const page = messages.slice(startIndex);
    const nextCursor = startIndex > 0 ? messages[startIndex - 1]?.createdAt ?? null : null;

    return res.json({
      messages: page.map((message) => shapeMessage(db, message)),
      nextCursor,
    });
  } catch (error) {
    return res.status(500).json({ message: asErrorMessage(error) });
  }
});

app.get('/api/chats/:chatId/pins', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const chat = findChat(db, req.params.chatId);

    if (!chat) {
      return res.status(404).json({ message: 'Chat not found.' });
    }

    if (!isChatMember(chat, req.userId)) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    const messages = db.messages
      .filter((message) => message.chatId === chat.id && message.pinnedAt)
      .sort((a, b) => +new Date(b.pinnedAt) - +new Date(a.pinnedAt))
      .map((message) => shapeMessage(db, message));

    return res.json({ messages });
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.post('/api/chats/:chatId/messages', requireAuth, messageLimiter, upload.array('files', 5), (req, res) => {
  try {
    const db = readDb();
    const chat = findChat(db, req.params.chatId);

    if (!chat) {
      return res.status(404).json({ message: 'Chat not found.' });
    }

    if (!isChatMember(chat, req.userId)) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    const text = normalizeMessage(req.body?.text);
    const replyTo = String(req.body?.replyTo ?? '').trim() || null;
    const encrypted = String(req.body?.encrypted ?? '').toLowerCase() === 'true';
    const iv = normalizeText(req.body?.iv, 200);
    if (encrypted && !iv) {
      return res.status(400).json({ message: 'Missing encryption IV.' });
    }
    const files = Array.isArray(req.files) ? req.files : [];

    const attachments = files.map((file) => ({
      id: crypto.randomUUID(),
      name: file.originalname,
      mimeType: file.mimetype,
      size: file.size,
      url: `/uploads/${file.filename}`,
    }));

    const message = createAndBroadcastMessage({
      chatId: chat.id,
      senderId: req.userId,
      text,
      attachments,
      replyTo,
      encryption: encrypted
        ? {
            algorithm: 'AES-GCM',
            iv,
          }
        : null,
    });

    return res.status(201).json({ message });
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.patch('/api/messages/:messageId', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const message = db.messages.find((entry) => entry.id === req.params.messageId);

    if (!message) {
      return res.status(404).json({ message: 'Message not found.' });
    }

    if (message.senderId !== req.userId) {
      return res.status(403).json({ message: 'You can edit only your own messages.' });
    }

    const chat = findChat(db, message.chatId);
    if (!chat || !isChatMember(chat, req.userId)) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    const text = normalizeMessage(req.body?.text);
    const encrypted = String(req.body?.encrypted ?? '').toLowerCase() === 'true';
    const iv = normalizeText(req.body?.iv, 200);
    if (encrypted && !iv) {
      return res.status(400).json({ message: 'Missing encryption IV.' });
    }

    if (!text) {
      return res.status(400).json({ message: 'Edited message cannot be empty.' });
    }

    message.text = text;
    message.editedAt = new Date().toISOString();
    message.encryption = encrypted
      ? {
          algorithm: 'AES-GCM',
          iv,
        }
      : null;

    writeDb(db);

    const payload = shapeMessage(db, message);

    io.to(`chat:${message.chatId}`).emit('message:updated', {
      chatId: message.chatId,
      message: payload,
      preview: messagePreview(message),
    });

    emitChatListUpdate(io, chat.members);

    return res.json({ message: payload });
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.delete('/api/messages/:messageId', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const message = db.messages.find((entry) => entry.id === req.params.messageId);

    if (!message) {
      return res.status(404).json({ message: 'Message not found.' });
    }

    if (message.senderId !== req.userId) {
      return res.status(403).json({ message: 'You can delete only your own messages.' });
    }

    const chat = findChat(db, message.chatId);
    if (!chat || !isChatMember(chat, req.userId)) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    message.text = '';
    message.editedAt = new Date().toISOString();
    message.isDeleted = true;
    message.attachments = [];
    message.reactions = [];
    message.pinnedAt = null;
    message.pinnedBy = [];
    message.encryption = null;

    writeDb(db);

    io.to(`chat:${message.chatId}`).emit('message:deleted', {
      chatId: message.chatId,
      messageId: message.id,
      preview: 'Message deleted',
    });

    emitChatListUpdate(io, chat.members);

    return res.json({ ok: true });
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.post('/api/messages/:messageId/reactions', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const message = findMessage(db, req.params.messageId);

    if (!message) {
      return res.status(404).json({ message: 'Message not found.' });
    }

    const chat = getChatOrThrow(db, message.chatId);
    if (!isChatMember(chat, req.userId)) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    if (message.isDeleted) {
      return res.status(400).json({ message: 'Cannot react to deleted messages.' });
    }

    const emoji = String(req.body?.emoji ?? '').trim();
    if (!emoji || emoji.length > 6) {
      return res.status(400).json({ message: 'Invalid emoji.' });
    }

    const current = message.reactions.find((entry) => entry.emoji === emoji);
    if (!current) {
      message.reactions.push({ emoji, userIds: [req.userId] });
    } else if (current.userIds.includes(req.userId)) {
      current.userIds = current.userIds.filter((id) => id !== req.userId);
      if (current.userIds.length === 0) {
        message.reactions = message.reactions.filter((entry) => entry.emoji !== emoji);
      }
    } else {
      current.userIds.push(req.userId);
    }

    writeDb(db);

    io.to(`chat:${chat.id}`).emit('message:reaction', {
      chatId: chat.id,
      messageId: message.id,
      reactions: message.reactions,
    });

    return res.json({ reactions: message.reactions });
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.post('/api/messages/:messageId/pin', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const message = findMessage(db, req.params.messageId);

    if (!message) {
      return res.status(404).json({ message: 'Message not found.' });
    }

    const chat = getChatOrThrow(db, message.chatId);
    if (!isChatMember(chat, req.userId)) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    const requested = req.body?.pinned;
    const shouldPin = typeof requested === 'boolean' ? requested : !message.pinnedBy.includes(req.userId);

    if (shouldPin) {
      if (!message.pinnedBy.includes(req.userId)) {
        message.pinnedBy.push(req.userId);
      }
      if (!message.pinnedAt) {
        message.pinnedAt = new Date().toISOString();
      }
    } else {
      message.pinnedBy = message.pinnedBy.filter((id) => id !== req.userId);
      if (message.pinnedBy.length === 0) {
        message.pinnedAt = null;
      }
    }

    writeDb(db);

    const payload = {
      chatId: chat.id,
      messageId: message.id,
      pinnedAt: message.pinnedAt,
      pinnedBy: message.pinnedBy,
    };

    io.to(`chat:${chat.id}`).emit('message:pinned', payload);
    emitChatListUpdate(io, chat.members);

    return res.json(payload);
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.post('/api/chats/:chatId/read', requireAuth, (req, res) => {
  try {
    const db = readDb();
    const chat = findChat(db, req.params.chatId);

    if (!chat) {
      return res.status(404).json({ message: 'Chat not found.' });
    }

    if (!isChatMember(chat, req.userId)) {
      return res.status(403).json({ message: 'Access denied.' });
    }

    const { seenAt, updatedIds } = markChatAsRead(db, chat.id, req.userId);

    writeDb(db);

    if (updatedIds.length > 0) {
      io.to(`chat:${chat.id}`).emit('message:seen', {
        chatId: chat.id,
        userId: req.userId,
        messageIds: updatedIds,
        seenAt,
      });
      emitChatListUpdate(io, chat.members);
    }

    return res.json({ updatedIds, seenAt });
  } catch (error) {
    return res.status(400).json({ message: asErrorMessage(error) });
  }
});

app.use((error, _req, res, next) => {
  if (error instanceof multer.MulterError) {
    return res.status(400).json({ message: error.message });
  }

  if (error instanceof Error && error.message === 'Unsupported file type.') {
    return res.status(400).json({ message: error.message });
  }

  return next(error);
});

const onlineUsers = new Map();
const callSessions = new Map();

function emitToUser(ioServer, userId, eventName, payload) {
  ioServer.to(`user:${userId}`).emit(eventName, payload);
}

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;

  if (!token) {
    next(new Error('Authentication required.'));
    return;
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const db = readDb();
    const user = findUser(db, payload.userId);

    if (!user) {
      next(new Error('Invalid token.'));
      return;
    }

    socket.data.userId = user.id;
    next();
  } catch {
    next(new Error('Invalid token.'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.data.userId;

  if (!onlineUsers.has(userId)) {
    onlineUsers.set(userId, new Set());
  }
  onlineUsers.get(userId).add(socket.id);

  socket.join(`user:${userId}`);

  const db = readDb();
  const userChats = db.chats.filter((chat) => isChatMember(chat, userId));
  for (const chat of userChats) {
    socket.join(`chat:${chat.id}`);
  }

  emitPresence(io, onlineUsers);

  socket.on('chat:join', ({ chatId }) => {
    const nextDb = readDb();
    const chat = findChat(nextDb, String(chatId ?? ''));
    if (!chat || !isChatMember(chat, userId)) {
      return;
    }
    socket.join(`chat:${chat.id}`);
  });

  socket.on('typing:start', ({ chatId }) => {
    const nextDb = readDb();
    const chat = findChat(nextDb, String(chatId ?? ''));

    if (!chat || !isChatMember(chat, userId)) {
      return;
    }

    socket.to(`chat:${chat.id}`).emit('typing:update', {
      chatId: chat.id,
      userId,
      isTyping: true,
    });
  });

  socket.on('typing:stop', ({ chatId }) => {
    const nextDb = readDb();
    const chat = findChat(nextDb, String(chatId ?? ''));

    if (!chat || !isChatMember(chat, userId)) {
      return;
    }

    socket.to(`chat:${chat.id}`).emit('typing:update', {
      chatId: chat.id,
      userId,
      isTyping: false,
    });
  });

  socket.on('chat:read', ({ chatId }) => {
    const nextDb = readDb();
    const chat = findChat(nextDb, String(chatId ?? ''));

    if (!chat || !isChatMember(chat, userId)) {
      return;
    }

    const { seenAt, updatedIds } = markChatAsRead(nextDb, chat.id, userId);
    if (updatedIds.length === 0) {
      return;
    }

    writeDb(nextDb);

    io.to(`chat:${chat.id}`).emit('message:seen', {
      chatId: chat.id,
      userId,
      messageIds: updatedIds,
      seenAt,
    });

    emitChatListUpdate(io, chat.members);
  });

  socket.on('call:start', ({ chatId, type }, ack) => {
    try {
      const db = readDb();
      const chat = getChatOrThrow(db, String(chatId ?? ''));
      if (!isChatMember(chat, userId)) {
        throw new Error('Access denied.');
      }

      const mode = type === 'video' ? 'video' : 'audio';
      const callId = crypto.randomUUID();
      const participants = [...chat.members];

      const session = {
        id: callId,
        chatId: chat.id,
        type: mode,
        initiatorId: userId,
        participants,
        acceptedBy: [userId],
        createdAt: new Date().toISOString(),
      };

      callSessions.set(callId, session);

      const initiator = findUser(db, userId);
      for (const participantId of participants) {
        if (participantId === userId) {
          continue;
        }
        emitToUser(io, participantId, 'call:incoming', {
          callId,
          chatId: chat.id,
          type: mode,
          callerId: userId,
          callerName: initiator?.name ?? initiator?.email ?? 'Unknown',
          participants,
        });
      }

      emitToUser(io, userId, 'call:outgoing', {
        callId,
        chatId: chat.id,
        type: mode,
        participants,
      });

      if (typeof ack === 'function') {
        ack({ ok: true, callId });
      }
    } catch (error) {
      if (typeof ack === 'function') {
        ack({ ok: false, message: asErrorMessage(error) });
      }
    }
  });

  socket.on('call:answer', ({ callId, accepted }, ack) => {
    try {
      const session = callSessions.get(String(callId ?? ''));
      if (!session || !session.participants.includes(userId)) {
        throw new Error('Call not found.');
      }

      const acceptedFlag = Boolean(accepted);
      if (acceptedFlag) {
        if (!session.acceptedBy.includes(userId)) {
          session.acceptedBy.push(userId);
        }
        io.to(`chat:${session.chatId}`).emit('call:answered', {
          callId: session.id,
          userId,
          accepted: true,
        });
      } else {
        io.to(`chat:${session.chatId}`).emit('call:ended', {
          callId: session.id,
          reason: 'rejected',
          endedBy: userId,
        });
        callSessions.delete(session.id);
      }

      if (typeof ack === 'function') {
        ack({ ok: true });
      }
    } catch (error) {
      if (typeof ack === 'function') {
        ack({ ok: false, message: asErrorMessage(error) });
      }
    }
  });

  socket.on('webrtc:signal', ({ callId, targetUserId, signal }, ack) => {
    try {
      const session = callSessions.get(String(callId ?? ''));
      const targetId = String(targetUserId ?? '');

      if (!session || !session.participants.includes(userId) || !session.participants.includes(targetId)) {
        throw new Error('Invalid call signal.');
      }

      emitToUser(io, targetId, 'webrtc:signal', {
        callId: session.id,
        fromUserId: userId,
        signal,
      });

      if (typeof ack === 'function') {
        ack({ ok: true });
      }
    } catch (error) {
      if (typeof ack === 'function') {
        ack({ ok: false, message: asErrorMessage(error) });
      }
    }
  });

  socket.on('call:end', ({ callId }, ack) => {
    const session = callSessions.get(String(callId ?? ''));
    if (!session || !session.participants.includes(userId)) {
      if (typeof ack === 'function') {
        ack({ ok: false, message: 'Call not found.' });
      }
      return;
    }

    io.to(`chat:${session.chatId}`).emit('call:ended', {
      callId: session.id,
      reason: 'ended',
      endedBy: userId,
    });
    callSessions.delete(session.id);

    if (typeof ack === 'function') {
      ack({ ok: true });
    }
  });

  socket.on('message:send', ({ chatId, text, replyTo }, ack) => {
    try {
      const message = createAndBroadcastMessage({
        chatId: String(chatId ?? ''),
        senderId: userId,
        text: String(text ?? ''),
        attachments: [],
        replyTo: replyTo ? String(replyTo) : null,
        encryption: null,
      });

      if (typeof ack === 'function') {
        ack({ ok: true, message });
      }
    } catch (error) {
      if (typeof ack === 'function') {
        ack({ ok: false, message: asErrorMessage(error) });
      }
    }
  });

  socket.on('disconnect', () => {
    const sockets = onlineUsers.get(userId);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        onlineUsers.delete(userId);
      }
    }

    const nextDb = readDb();
    const user = findUser(nextDb, userId);
    if (user) {
      user.lastSeen = new Date().toISOString();
      writeDb(nextDb);
    }

    for (const [callId, session] of callSessions.entries()) {
      if (!session.participants.includes(userId)) {
        continue;
      }

      io.to(`chat:${session.chatId}`).emit('call:ended', {
        callId,
        reason: 'left',
        endedBy: userId,
      });
      callSessions.delete(callId);
    }

    emitPresence(io, onlineUsers);
  });
});

if (fs.existsSync(FRONTEND_DIST_DIR)) {
  app.use(express.static(FRONTEND_DIST_DIR));

  // Serve the SPA shell for non-API routes.
  app.get(/^\/(?!api|uploads|socket\.io).*/, (_req, res) => {
    res.sendFile(path.join(FRONTEND_DIST_DIR, 'index.html'));
  });
}

httpServer.listen(PORT, () => {
  console.log(`Chat server running on port ${PORT}`);
});
