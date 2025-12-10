// server.gemini.smart.js
// Robust Gemini-only server that fetches available models at startup
// and uses only models that claim to support generateContent.

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const morgan = require('morgan');

// 🔹 NEW: auth & DB imports
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 🔹 NEW: User model (schema in models/User.js)
const User = require('./modles/user');

const app = express();
const PORT = process.env.PORT || 4000;

/* =============== CONFIG =============== */
// Replace with your key
const GEMINI_API_KEY = "AIzaSyDDVeMLZo40T-q89aDrmxPJDF1sc5ZVal0";

// 🔹 NEW: Mongo + JWT config
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/ai_dashboard';
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-this';

if (!GEMINI_API_KEY) {
  console.warn('⚠️ GEMINI_API_KEY is empty. Please set your key in server.gemini.smart.js');
}

app.use(cors());
app.use(express.json({ limit: '12mb' }));
app.use(morgan('dev'));

// 🔹 NEW: Connect to MongoDB
mongoose
  .connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('✅ MongoDB connected:', MONGO_URI))
  .catch((err) => console.error('❌ MongoDB connection error:', err.message));

const axiosJSON = axios.create({
  timeout: 60_000,
  headers: { 'Content-Type': 'application/json' }
});

function maskKeySafe(key) {
  if (!key) return '<empty>';
  const s = String(key).trim();
  return `${s.slice(0, 6)}***** (len=${s.length})`;
}

/* =============== Helpers =============== */
function formatAxiosError(err) {
  if (!err) return null;
  if (err.response) return { status: err.response.status, data: err.response.data };
  if (err.request) return { message: 'No response received from remote host' };
  return { message: err.message };
}

const MODELS_LIST_URL = (key) =>
  `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(String(key).trim())}`;

async function fetchAvailableModels() {
  try {
    const url = MODELS_LIST_URL(GEMINI_API_KEY);
    const r = await axiosJSON.get(url);
    // r.data.models is expected; fall back safely
    const models = r.data?.models || [];
    return models;
  } catch (err) {
    console.error('Failed to fetch models list:', formatAxiosError(err));
    throw err;
  }
}

/* At startup we'll populate this with model ids we can use.
   Each item: { id: 'gemini-2.5-flash', displayName: '...', supportsGenerateContent: true }
*/
let RUNTIME_MODEL_QUEUE = [];

/* Build model queue from available models.
   Preference ordering heuristic: prefer names containing "flash" then "pro" then others.
*/
function buildModelQueueFromList(models) {
  if (!Array.isArray(models)) return [];

  // Normalize model entries into {id, name, supportedMethods}
  const normalized = models.map(m => ({
    id: m.name || m.model || m.modelId || m.displayName || '',
    displayName: m.displayName || '',
    metadata: m.metadata || {},
    supportedMethods: (m.supportedMethods || m.methods || []), // shape varies by API versions
  })).filter(x => !!x.id);

  // Filter models that claim to support generateContent (some metadata versions use supportedMethods or methods)
  const supported = normalized.filter(m => {
    const methods = (m.supportedMethods || []).map(String).map(s => s.toLowerCase());
    // some responses use 'generateContent' or 'models.generateContent' or contain strings — check substrings
    return methods.some(s => s.includes('generate') || s.includes('generatecontent') || s.includes('generate_content'));
  });

  // If supported list is empty, as a fallback include any model whose id contains 'gemini'
  const fallbackList = supported.length ? supported : normalized.filter(m => m.id.toLowerCase().includes('gemini'));

  // Sort by heuristic: flash first, then pro, then others
  fallbackList.sort((a, b) => {
    const score = (m) => {
      const s = (m.id || '').toLowerCase();
      if (s.includes('flash')) return 2;
      if (s.includes('pro')) return 1;
      return 0;
    };
    return score(b) - score(a);
  });

  // Map to simple array of model ids (the part used in the path)
  const queue = fallbackList.map(m => {
    // Many model entries include full resource like "projects/..../models/gemini-2.5-flash"
    // We'll pick a usable suffix if present.
    const full = m.id;
    const match = full.match(/([^/]+)$/);
    const id = match ? match[1] : full;
    return { id, raw: full, displayName: m.displayName || '' };
  });

  // dedupe preserving order
  const seen = new Set();
  const unique = [];
  for (const item of queue) {
    if (!seen.has(item.id)) {
      seen.add(item.id);
      unique.push(item);
    }
  }
  return unique;
}

/* =============== Startup: fetch models =============== */
async function initModelQueue() {
  try {
    console.log('Fetching available Gemini models with key (masked):', maskKeySafe(GEMINI_API_KEY));
    const models = await fetchAvailableModels();
    const queue = buildModelQueueFromList(models);
    if (!queue.length) {
      console.warn('No suitable models discovered from models.list; falling back to a conservative built-in list.');
      // conservative fallback: newer expected names first
      RUNTIME_MODEL_QUEUE = [
        { id: 'gemini-2.5-flash' },
        { id: 'gemini-2.5-pro' },
        { id: 'gemini-2.0-flash' },
        { id: 'gemini-2.0-pro' }
      ];
    } else {
      RUNTIME_MODEL_QUEUE = queue;
    }
    console.log('Runtime model queue:', RUNTIME_MODEL_QUEUE.map(m => m.id));
  } catch (err) {
    console.error('Error building runtime model queue. Server will still start but model calls may fail.', formatAxiosError(err));
    // set a minimal fallback so code path still tries something
    RUNTIME_MODEL_QUEUE = [{ id: 'gemini-2.5-flash' }, { id: 'gemini-2.5-pro' }];
  }
}

/* ================== New Utilities: bytes + pretty console table ================== */
function byteLengthOfString(str = '') {
  // returns byte length of UTF-8 encoding
  return Buffer.byteLength(String(str), 'utf8');
}
function formatBytes(n) {
  if (n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(Math.abs(n)) / Math.log(1024));
  return `${(n / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}
function pad(str, len, dir = 'right') {
  str = String(str || '');
  if (str.length >= len) return str;
  if (dir === 'right') return str + ' '.repeat(len - str.length);
  return ' '.repeat(len - str.length) + str;
}
function printAttemptsTable(attempts) {
  if (!Array.isArray(attempts) || !attempts.length) return;
  // columns: model, status, reqBytes, resBytes, duration, success, snippet
  const cols = [
    { k: 'model', w: 20 },
    { k: 'status', w: 8 },
    { k: 'req', w: 10 },
    { k: 'res', w: 10 },
    { k: 'dur', w: 8 },
    { k: 'ok', w: 6 },
    { k: 'snippet', w: 40 }
  ];
  const header = cols.map(c => pad(c.k.toUpperCase(), c.w)).join(' | ');
  console.log('\n=== Model Attempts Summary ===');
  console.log(header);
  console.log('-'.repeat(header.length));
  for (const a of attempts) {
    const model = pad(a.modelId || '<unknown>', cols[0].w);
    const status = pad(a.status != null ? String(a.status) : (a.error ? 'ERR' : '-'), cols[1].w);
    const req = pad(formatBytes(a.requestBytes || 0), cols[2].w, 'left');
    const res = pad(formatBytes(a.responseBytes || 0), cols[3].w, 'left');
    const dur = pad(a.durationMs != null ? `${a.durationMs}ms` : '-', cols[4].w, 'left');
    const ok = pad(a.success ? 'YES' : 'NO', cols[5].w);
    const snippet = pad((a.snippet || '').replace(/\n/g, ' ').slice(0, cols[6].w - 1), cols[6].w);
    console.log([model, status, req, res, dur, ok, snippet].join(' | '));
  }
  console.log('==============================\n');
}

/* Helper to extract retry seconds from API error details */
function extractRetrySecondsFromApiError(apiErr) {
  try {
    const details = apiErr?.data?.error?.details || apiErr?.data?.details || [];
    for (const d of details) {
      if (d && String(d['@type'] || '').includes('RetryInfo') && d.retryDelay) {
        const ds = String(d.retryDelay);
        const m = ds.match(/([\d.]+)s/);
        if (m) return Math.ceil(parseFloat(m[1]));
      }
    }
  } catch (e) {
    // ignore
  }
  return null;
}

/* =============== AUTH ROUTES (Login / Signup) =============== */

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email and password are required' });
    }

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ error: 'User already exists with this email' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      passwordHash,
    });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      message: 'Signup successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error('Signup error:', err);
    return res.status(500).json({ error: 'signup_failed', message: String(err.message || err) });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'login_failed', message: String(err.message || err) });
  }
});

/* =============== Chat endpoint =============== */
app.post('/api/chat', async (req, res) => {
  try {
    const { messages = [] } = req.body || {};
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'messages array required' });
    }

    const systemPrompt = 'You are a helpful assistant. Respond in clean plain text with spacing and bullet points.';
    const history = messages.map(m => `${m.role || 'user'}: ${m.text || ''}`).join('\n\n');

    const payload = {
      contents: [{ parts: [{ text: `${systemPrompt}\n\n${history}` }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 512 }
    };

    // Compute some sizes / diagnostics for the request we are about to send
    const payloadText = JSON.stringify(payload);
    const payloadBytes = byteLengthOfString(payloadText);
    const messagesSummary = {
      count: messages.length,
      totalChars: messages.reduce((s, m) => s + String(m.text || '').length, 0),
      totalBytesApprox: byteLengthOfString(messages.map(m => m.text || '').join('\n'))
    };

    let lastError = null;

    const attempts = []; // collect structured attempt info

    // Try each model until we get output
    for (const m of Array.from(RUNTIME_MODEL_QUEUE)) {
      const modelId = m.id;
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(modelId)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;
      const attempt = {
        modelId,
        url,
        startAt: new Date().toISOString(),
        startTs: Date.now(),
        requestBytes: payloadBytes,
        responseBytes: null,
        durationMs: null,
        success: false,
        status: null,
        error: null,
        snippet: null,
        raw: null
      };

      try {
        console.log(`Trying model ${modelId}... (payload ${formatBytes(payloadBytes)})`);
        const r = await axiosJSON.post(url, payload);

        attempt.durationMs = Date.now() - attempt.startTs;
        attempt.status = r.status;
        const rawStr = JSON.stringify(r.data || {});
        attempt.responseBytes = byteLengthOfString(rawStr);
        attempt.raw = r.data || {};
        attempt.snippet = (r.data?.candidates?.[0]?.content?.parts?.[0]?.text || '').slice(0, 300);
        const output = r.data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (output) {
          attempt.success = true;
          attempts.push(attempt);

          // print table for human operator
          printAttemptsTable(attempts);

          // Respond with structured data including what we sent and what we received
          return res.json({
            text: output,
            modelUsed: modelId,
            modelQueue: RUNTIME_MODEL_QUEUE.map(x => x.id),
            diagnostics: {
              systemPrompt,
              messagesSummary,
              payloadBytes,
              attempts
            },
            raw: r.data
          });
        } else {
          attempt.success = false;
          attempt.error = 'NO_OUTPUT';
          lastError = { message: 'No output', raw: r.data };
          console.warn(`Model ${modelId} returned no content.`);
        }
      } catch (err) {
        attempt.durationMs = Date.now() - attempt.startTs;
        const fmt = formatAxiosError(err);
        attempt.error = fmt;
        attempt.status = fmt?.status || null;
        // Attempt to set responseBytes from returned data if present
        try { attempt.responseBytes = byteLengthOfString(JSON.stringify(fmt?.data || {})); } catch (e) {}
        lastError = fmt;
        console.warn(`Model ${modelId} failed:`, fmt);

        // If model isn't found (404) — remove it from runtime queue so future requests don't try it
        if (fmt?.status === 404) {
          console.warn(`Removing model ${modelId} from runtime queue (404 not found)`);
          RUNTIME_MODEL_QUEUE = RUNTIME_MODEL_QUEUE.filter(x => x.id !== modelId);
        }

        // If rate limited (429) — extract retry info and return 429 to client with useful data
        if (fmt?.status === 429) {
          attempts.push(attempt); // keep last attempt recorded
          printAttemptsTable(attempts);
          const retryAfter = extractRetrySecondsFromApiError(fmt) || 30;
          return res.status(429).json({
            error: 'rate_limited',
            message: 'Remote API rate limit / quota exceeded. Please retry later.',
            retryAfterSeconds: retryAfter,
            lastError: fmt,
            diagnostics: {
              systemPrompt,
              messagesSummary,
              payloadBytes,
              attempts
            }
          });
        }
      } finally {
        // push attempt even if failed and not already pushed by 429 branch
        if (!attempts.includes(attempt)) attempts.push(attempt);
      }
    }

    // none succeeded -> return a 502 with diagnostics
    printAttemptsTable(attempts);
    return res.status(502).json({
      error: 'all_models_failed',
      message: 'No configured model produced output. See details.',
      lastError,
      attemptedModels: RUNTIME_MODEL_QUEUE.map(m => m.id),
      diagnostics: {
        systemPrompt,
        messagesSummary,
        payloadBytes,
        attempts
      }
    });

  } catch (err) {
    console.error('Critical /api/chat error:', err);
    return res.status(500).json({ error: 'server_error', message: String(err) });
  }
});

/* Simple health check */
app.get('/_health', (_, res) => res.json({ ok: true, time: new Date().toISOString() }));

/* Debug endpoint to inspect runtime model queue */
app.get('/api/debug/models', (_, res) => {
  res.json({ runtimeModelQueue: RUNTIME_MODEL_QUEUE, maskedKey: maskKeySafe(GEMINI_API_KEY) });
});

/* start server after attempting to build model queue */
initModelQueue().then(() => {
  app.listen(PORT, () => {
    console.log(`Backend running: http://localhost:${PORT}`);
    console.log('Model queue (runtime):', RUNTIME_MODEL_QUEUE.map(m => m.id).join(', '));
  });
}).catch(err => {
  console.error('Failed to initialize model queue', formatAxiosError(err));
  app.listen(PORT, () => console.log(`Backend running (models init failed): http://localhost:${PORT}`));
});
