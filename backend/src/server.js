import 'dotenv/config';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import zxcvbn from 'zxcvbn';
import { logAudit, pool, query } from './db.js';

const app = express();
const port = Number(process.env.PORT || 4000);
const frontendOrigin = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
const scryptAsync = promisify(scrypt);

// V1 intentionat vulnerabil: sesiunile sunt in memorie si token-ul este usor de reutilizat.
const sessions = new Map();
const PASSWORD_POLICY_MESSAGE = 'Parola nu respecta politica de securitate.';
const MIN_PASSWORD_LENGTH = 10;
const MIN_PASSWORD_SCORE = 3;
const PASSWORD_HASH_PREFIX = 'scrypt';
const PASSWORD_KEY_LENGTH = 64;

app.use(
  cors({
    origin: frontendOrigin,
    credentials: true,
  }),
);
app.use(express.json());
app.use(cookieParser());

function createWeakSession(user) {
  const token = Buffer.from(`${user.id}:${Date.now()}`).toString('base64');
  sessions.set(token, {
    userId: user.id,
    createdAt: Date.now(),
  });
  return token;
}

function createPredictableResetToken(email) {
  return Buffer.from(`${email}:reset`).toString('base64');
}

function validatePasswordPolicy(password, userInputs = []) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    return false;
  }

  const passwordStrength = zxcvbn(password, userInputs);
  return passwordStrength.score >= MIN_PASSWORD_SCORE;
}

async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derivedKey = await scryptAsync(password, salt, PASSWORD_KEY_LENGTH);
  return `${PASSWORD_HASH_PREFIX}$${salt}$${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, storedPassword) {
  const [algorithm, salt, storedHash] = String(storedPassword).split('$');

  if (algorithm !== PASSWORD_HASH_PREFIX || !salt || !storedHash) {
    const validLegacyPassword = storedPassword === password;
    return { valid: validLegacyPassword, needsRehash: validLegacyPassword };
  }

  if (!/^[a-f0-9]+$/i.test(storedHash)) {
    return { valid: false, needsRehash: false };
  }

  const storedKey = Buffer.from(storedHash, 'hex');
  if (storedKey.length === 0) {
    return { valid: false, needsRehash: false };
  }

  const derivedKey = await scryptAsync(password, salt, storedKey.length);

  return {
    valid: timingSafeEqual(storedKey, derivedKey),
    needsRehash: false,
  };
}

async function currentUser(req, _res, next) {
  const authHeader = req.get('authorization') || '';
  const bearerToken = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;
  const token = req.cookies.authx_session || bearerToken;
  const session = token ? sessions.get(token) : null;

  if (!session) {
    req.user = null;
    req.sessionToken = token || null;
    return next();
  }

  const result = await query(
    'SELECT id, email, role, created_at, locked FROM users WHERE id = $1',
    [session.userId],
  );

  req.user = result.rows[0] || null;
  req.sessionToken = token;
  return next();
}

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ message: 'Trebuie sa fii autentificat.' });
  }
  return next();
}

app.use(currentUser);

app.get('/api/health', async (_req, res) => {
  await pool.query('SELECT 1');
  res.json({ status: 'ok', database: 'connected' });
});

app.post('/api/auth/register', async (req, res) => {
  const { email, password, role = 'USER' } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: 'Email si parola sunt obligatorii.' });
  }

  if (!validatePasswordPolicy(password, [email])) {
    return res.status(400).json({ message: PASSWORD_POLICY_MESSAGE });
  }

  const existing = await query('SELECT id FROM users WHERE email = $1', [
    email,
  ]);
  if (existing.rowCount > 0) {
    await logAudit({
      userId: existing.rows[0].id,
      action: 'REGISTER_DUPLICATE',
      resource: 'auth',
      resourceId: email,
      ipAddress: req.ip,
    });
    return res.status(409).json({ message: 'Utilizatorul exista deja.' });
  }

  const passwordHash = await hashPassword(password);
  const result = await query(
    `INSERT INTO users (email, password_hash, role)
     VALUES ($1, $2, $3)
     RETURNING id, email, role, created_at, locked`,
    [email, passwordHash, role],
  );

  await logAudit({
    userId: result.rows[0].id,
    action: 'REGISTER',
    resource: 'auth',
    resourceId: result.rows[0].id,
    ipAddress: req.ip,
  });

  return res.status(201).json({
    message: 'Cont creat.',
    user: result.rows[0],
  });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: 'Email si parola sunt obligatorii.' });
  }

  const result = await query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];

  // V1 vulnerabil: raspuns diferit pentru user inexistent.
  if (!user) {
    await logAudit({
      action: 'LOGIN_UNKNOWN_USER',
      resource: 'auth',
      resourceId: email,
      ipAddress: req.ip,
    });
    return res.status(404).json({ message: 'User inexistent.' });
  }

  const passwordCheck = await verifyPassword(password, user.password_hash);
  if (!passwordCheck.valid) {
    await logAudit({
      userId: user.id,
      action: 'LOGIN_FAILED_PASSWORD',
      resource: 'auth',
      resourceId: user.id,
      ipAddress: req.ip,
    });
    return res.status(401).json({ message: 'Parola gresita.' });
  }

  if (passwordCheck.needsRehash) {
    const upgradedHash = await hashPassword(password);
    await query('UPDATE users SET password_hash = $1 WHERE id = $2', [
      upgradedHash,
      user.id,
    ]);
  }

  const token = createWeakSession(user);

  // V1 vulnerabil: cookie-ul nu are HttpOnly, Secure sau SameSite strict.
  res.cookie('authx_session', token, {
    maxAge: 1000 * 60 * 60 * 24 * 30,
  });

  await logAudit({
    userId: user.id,
    action: 'LOGIN',
    resource: 'auth',
    resourceId: user.id,
    ipAddress: req.ip,
  });

  return res.json({
    message: 'Login reusit.',
    token,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      locked: user.locked,
    },
  });
});

app.post('/api/auth/logout', async (req, res) => {
  if (req.user) {
    await logAudit({
      userId: req.user.id,
      action: 'LOGOUT',
      resource: 'auth',
      resourceId: req.user.id,
      ipAddress: req.ip,
    });
  }

  // V1 vulnerabil: sterge cookie-ul, dar nu invalideaza token-ul din sessions.
  res.clearCookie('authx_session');
  return res.json({
    message:
      'Logout facut doar in browser; token-ul vechi ramane reutilizabil.',
  });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email obligatoriu.' });
  }

  const result = await query('SELECT id, email FROM users WHERE email = $1', [
    email,
  ]);
  const user = result.rows[0];

  // V1 vulnerabil: raspunsul confirma daca un cont exista.
  if (!user) {
    await logAudit({
      action: 'RESET_UNKNOWN_USER',
      resource: 'auth',
      resourceId: email,
      ipAddress: req.ip,
    });
    return res.status(404).json({ message: 'Nu exista cont cu acest email.' });
  }

  const token = createPredictableResetToken(user.email);

  await query('INSERT INTO reset_tokens (user_id, token) VALUES ($1, $2)', [
    user.id,
    token,
  ]);
  await logAudit({
    userId: user.id,
    action: 'RESET_TOKEN_CREATED',
    resource: 'auth',
    resourceId: user.id,
    ipAddress: req.ip,
  });

  return res.json({
    message: 'Token generat. V1 il returneaza direct in raspuns.',
    resetToken: token,
  });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res
      .status(400)
      .json({ message: 'Token si parola noua sunt obligatorii.' });
  }

  if (!validatePasswordPolicy(newPassword)) {
    return res.status(400).json({ message: PASSWORD_POLICY_MESSAGE });
  }

  const result = await query(
    `SELECT rt.id, rt.user_id, u.email
     FROM reset_tokens rt
     JOIN users u ON u.id = rt.user_id
     WHERE rt.token = $1
     ORDER BY rt.created_at DESC
     LIMIT 1`,
    [token],
  );

  const reset = result.rows[0];
  if (!reset) {
    return res.status(400).json({ message: 'Token invalid.' });
  }

  const passwordHash = await hashPassword(newPassword);
  await query('UPDATE users SET password_hash = $1 WHERE id = $2', [
    passwordHash,
    reset.user_id,
  ]);
  await logAudit({
    userId: reset.user_id,
    action: 'PASSWORD_RESET',
    resource: 'auth',
    resourceId: reset.user_id,
    ipAddress: req.ip,
  });

  return res.json({
    message: `Parola pentru ${reset.email} a fost schimbata. Token-ul poate fi reutilizat in V1.`,
  });
});

app.get('/api/me', requireAuth, async (req, res) => {
  return res.json({ user: req.user });
});

app.get('/api/audit-logs', requireAuth, async (_req, res) => {
  // V1 vulnerabil: orice user autentificat vede toate logurile.
  const result = await query(
    `SELECT al.*, u.email, COALESCE(u.email, al.resource_id, 'necunoscut') AS actor
     FROM audit_logs al
     LEFT JOIN users u ON u.id = al.user_id
     ORDER BY al.timestamp DESC
     LIMIT 50`,
  );
  return res.json({ logs: result.rows });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  return res.status(500).json({
    message: 'Eroare interna.',
    detail: process.env.NODE_ENV === 'production' ? undefined : err.message,
  });
});

app.listen(port, () => {
  console.log(`AuthX backend vulnerabil pornit pe http://localhost:${port}`);
});
