const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const OpenAI = require('openai');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';
const jwtSecret = process.env.JWT_SECRET;
const integrationApiKey = process.env.INTEGRATION_API_KEY || null;
const whatsappVerifyToken = process.env.WHATSAPP_VERIFY_TOKEN || null;
const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: isProduction ? { rejectUnauthorized: false } : false }) : null;
const client = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;

const reviewFormats = {
  grammar: 'Return output in this exact format:\n\n1. Corrected version:\n[full corrected text]\n2. Key fixes:\n- [fix 1]\n- [fix 2]\n3. Summary:\n[1-2 sentence summary]',
  code: 'Return output in this exact format:\n\nScore: [0-10]\nStrengths:\n- [strength]\nIssues:\n- [issue]\nImprovements:\n1. [improvement]\n2. [improvement]\nFinal recommendation: [short recommendation]',
  business: 'Return output in this exact format:\n\nScore: [0-10]\nStrengths:\n- [strength]\nWeak points:\n- [weak point]\nOpportunities:\n- [opportunity]\nRisks:\n- [risk]\nImprovement plan:\n1. [step]\n2. [step]\nFinal recommendation: [short recommendation]',
  document: 'Return output in this exact format:\n\nOverall score: [0-10]\nTop issues:\n- [issue]\nSuggested improvements:\n1. [improvement]\n2. [improvement]\nRevised version:\n[short rewritten version or summary]'
};

const modePrompts = {
  general: {
    system: 'You are SILA AI, a friendly and practical assistant. Help with writing, business ideas, creativity, productivity, and English or Swahili communication. Respond in the language the user is using.'
  },
  grammar: {
    system: 'You are a professional grammar and writing editor. Correct grammar, punctuation, clarity, tone, and structure. Preserve the user\'s meaning while improving readability. ' + reviewFormats.grammar
  },
  code: {
    system: 'You are an expert software code reviewer and debugging assistant. Review code for correctness, bugs, performance, readability, and maintainability. Give specific recommendations, root causes, and improvement suggestions. If code is incomplete, explain the likely issue and how to fix it. ' + reviewFormats.code
  },
  business: {
    system: 'You are a business strategy reviewer. Evaluate ideas, plans, value propositions, operations, risks, and opportunities. Use practical, realistic advice and highlight assumptions, weak points, and next steps for a business or startup. ' + reviewFormats.business
  },
  document: {
    system: 'You are a document editor and reviewer. Improve clarity, structure, formatting, tone, and professionalism for reports, proposals, notes, contracts, and other written documents. Keep the original intent while enhancing readability and coherence. ' + reviewFormats.document
  }
};

app.use(express.json({ limit: '20kb' }));
app.use(express.static(__dirname));

async function initDb() {
  if (!pool) return;
  await pool.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS messages (id BIGSERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL CHECK (role IN ('user','assistant')), content TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE INDEX IF NOT EXISTS messages_user_created_idx ON messages(user_id, created_at);`);
}

function tokenFor(user) { return jwt.sign({ id: user.id, email: user.email }, jwtSecret, { expiresIn: '30d' }); }
function setAuthCookie(res, token) { res.setHeader('Set-Cookie', `sila_token=${token}; HttpOnly; Path=/; Max-Age=${30 * 86400}; SameSite=Lax${isProduction ? '; Secure' : ''}`); }
function clearAuthCookie(res) { res.setHeader('Set-Cookie', 'sila_token=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax'); }
function readToken(req) { const raw = req.headers.cookie || ''; const match = raw.match(/(?:^|; )sila_token=([^;]+)/); return match ? decodeURIComponent(match[1]) : null; }
function authRequired(req, res, next) {
  if (!pool || !jwtSecret) return res.status(503).json({ error: 'Authentication is not configured.' });
  try { req.user = jwt.verify(readToken(req) || '', jwtSecret); next(); }
  catch (error) { res.status(401).json({ error: 'Please log in to continue.' }); }
}
function validEmail(email) { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email); }
function resolveMode(mode) { const value = typeof mode === 'string' ? mode.toLowerCase() : 'general'; return modePrompts[value] ? value : 'general'; }

function integrationKeyRequired(req, res, next) {
  if (!integrationApiKey) {
    return res.status(503).json({ error: 'Integration API key is not configured.' });
  }
  const provided = req.headers['x-api-key'];
  if (provided !== integrationApiKey) return res.status(401).json({ error: 'Invalid integration key.' });
  next();
}

async function generateReply(message, mode = 'general') {
  const selectedMode = resolveMode(mode);
  if (!client) {
    throw new Error('The AI service is not configured yet.');
  }

  const completion = await client.chat.completions.create({
    model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
    messages: [
      { role: 'system', content: modePrompts[selectedMode].system },
      { role: 'user', content: message }
    ],
    temperature: 0.7,
    max_tokens: 850
  });

  return completion.choices?.[0]?.message?.content?.trim() || 'I could not generate a reply. Please try again.';
}

app.get('/api/health', async (req, res) => {
  let database = false;
  try {
    if (pool) { await pool.query('SELECT 1'); database = true; }
  } catch (error) {
    database = false;
  }
  res.json({ ok: true, aiConfigured: Boolean(client), databaseConfigured: Boolean(pool) && database, integrationApiConfigured: Boolean(integrationApiKey), model: process.env.OPENAI_MODEL || 'gpt-4o-mini' });
});

app.post('/api/auth/register', async (req, res) => {
  if (!pool || !jwtSecret) return res.status(503).json({ error: 'Authentication is not configured.' });
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email', [email, hash]);
    setAuthCookie(res, tokenFor(result.rows[0]));
    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }
    console.error(error);
    res.status(500).json({ error: 'Could not create account.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  if (!pool || !jwtSecret) return res.status(503).json({ error: 'Authentication is not configured.' });
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  try {
    const result = await pool.query('SELECT id,email,password_hash FROM users WHERE email=$1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }
    setAuthCookie(res, tokenFor(user));
    res.json({ user: { id: user.id, email: user.email } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not log in.' });
  }
});

app.post('/api/auth/logout', (req, res) => { clearAuthCookie(res); res.json({ ok: true }); });
app.get('/api/auth/me', authRequired, (req, res) => res.json({ user: { id: req.user.id, email: req.user.email } }));

app.get('/api/history', authRequired, async (req, res) => {
  try {
    const result = await pool.query('SELECT role,content,created_at FROM messages WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100', [req.user.id]);
    res.json({ messages: result.rows.reverse() });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not load chat history.' });
  }
});

app.delete('/api/history', authRequired, async (req, res) => {
  try {
    await pool.query('DELETE FROM messages WHERE user_id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Could not clear chat history.' });
  }
});

app.post('/api/chat', authRequired, async (req, res) => {
  const message = typeof req.body.message === 'string' ? req.body.message.trim() : '';
  const mode = resolveMode(req.body.mode);
  if (!message) return res.status(400).json({ error: 'Message is required.' });
  if (message.length > 8000) return res.status(413).json({ error: 'Message is too long.' });

  try {
    if (!pool) return res.status(503).json({ error: 'Database is not configured.' });
    await pool.query('INSERT INTO messages(user_id,role,content) VALUES($1,$2,$3)', [req.user.id, 'user', message]);
    const previous = await pool.query('SELECT role,content FROM messages WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20', [req.user.id]);

    const completion = await client.chat.completions.create({
      model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
      messages: [
        { role: 'system', content: modePrompts[mode].system },
        ...previous.rows.reverse().map((row) => ({ role: row.role, content: row.content }))
      ],
      temperature: 0.7,
      max_tokens: 850
    });

    const reply = completion.choices?.[0]?.message?.content?.trim() || 'I could not generate a reply. Please try again.';
    await pool.query('INSERT INTO messages(user_id,role,content) VALUES($1,$2,$3)', [req.user.id, 'assistant', reply]);
    res.json({ reply, mode });
  } catch (error) {
    console.error('Request failed:', error.message);
    res.status(502).json({ error: 'The AI service could not process your request.' });
  }
});

app.get('/api/integrations/modes', (req, res) => {
  res.json({
    modes: ['general', 'grammar', 'code', 'business', 'document'],
    websiteReady: true,
    mobileReady: true,
    whatsappReady: Boolean(whatsappVerifyToken),
    gmailReady: false
  });
});

app.post('/api/integrations/chat', integrationKeyRequired, async (req, res) => {
  const message = typeof req.body.message === 'string' ? req.body.message.trim() : '';
  const mode = resolveMode(req.body.mode);

  if (!message) return res.status(400).json({ error: 'Message is required.' });
  if (message.length > 8000) return res.status(413).json({ error: 'Message is too long.' });

  try {
    const reply = await generateReply(message, mode);
    res.json({ reply, mode, source: 'integration-api' });
  } catch (error) {
    console.error('Integration request failed:', error.message);
    res.status(502).json({ error: error.message || 'The AI service could not process your request.' });
  }
});

app.get('/api/webhooks/whatsapp', (req, res) => {
  if (!whatsappVerifyToken) return res.status(503).json({ error: 'WhatsApp webhook is not configured.' });
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === whatsappVerifyToken) {
    return res.status(200).send(challenge || 'ok');
  }

  return res.status(403).json({ error: 'Forbidden' });
});

app.post('/api/webhooks/whatsapp', async (req, res) => {
  if (!whatsappVerifyToken) return res.status(503).json({ error: 'WhatsApp webhook is not configured.' });

  try {
    const body = req.body || {};
    const entry = Array.isArray(body.entry) ? body.entry[0] : null;
    const change = entry && Array.isArray(entry.changes) ? entry.changes[0] : null;
    const value = change ? change.value : null;
    const messages = value && Array.isArray(value.messages) ? value.messages : [];

    if (!messages.length) {
      return res.status(200).json({ ok: true, message: 'Webhook received with no message payload.' });
    }

    const incomingText = messages[0]?.text?.body || '';
    const from = messages[0]?.from || 'unknown';
    if (!incomingText) return res.status(200).json({ ok: true, message: 'No text message to process.' });

    const reply = await generateReply(incomingText, 'general');
    res.status(200).json({ ok: true, reply, from, source: 'whatsapp-webhook' });
  } catch (error) {
    console.error('WhatsApp webhook failed:', error.message);
    res.status(502).json({ error: 'WhatsApp processing failed.' });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

initDb().then(() => app.listen(port, () => console.log(`SILA AI is running at http://localhost:${port}`))).catch((error) => {
  console.error('Database startup failed:', error);
  process.exit(1);
});
