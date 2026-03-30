/**
 * server.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OWASP A05 — Security Misconfiguration
 *
 * Security changes vs original:
 *  1. Body size limit reduced 10MB → 100KB. There is no endpoint that
 *     legitimately needs more than a few KB. 10MB allowed HTTP request
 *     bodies that could OOM the server.
 *  2. Helmet options expanded: Content-Security-Policy, HSTS, and
 *     X-Content-Type-Options are all now configured explicitly.
 *  3. CORS origin validated at boot — if FRONTEND_URL is not set in
 *     production the server refuses to start rather than silently
 *     accepting '*'.
 *  4. Global rate limiter applied to /api/* as a safety net;
 *     individual routes apply stricter per-endpoint limiters on top.
 *  5. morgan skipped entirely in production (log rotation and structured
 *     logging should be handled at the infrastructure level, not here;
 *     access logs can leak PII).
 *  6. Health endpoint no longer echoes the DB engine name — avoids giving
 *     attackers free recon on what database to target.
 */

const express    = require('express');
const cors       = require('cors');
const dotenv     = require('dotenv');
const helmet     = require('helmet');
const morgan     = require('morgan');
const { globalLimiter } = require('./middleware/rateLimiter');

dotenv.config();

// ── Boot-time environment validation ─────────────────────────────────────────
// database.js already validates JWT_SECRET; validate CORS origin here.
if (process.env.NODE_ENV === 'production' && !process.env.FRONTEND_URL) {
  console.error('FATAL: FRONTEND_URL must be set in production to configure CORS.');
  process.exit(1);
}

const app  = express();
const PORT = process.env.PORT || 5000;

// ── Security headers (Helmet) ─────────────────────────────────────────────────
// OWASP A05: explicit header configuration rather than Helmet defaults,
// so each decision is visible and auditable.
app.use(helmet({
  // Prevent browsers from sniffing MIME types (defence against MIME confusion attacks)
  contentTypeOptions: true,

  // HSTS: enforce HTTPS for 1 year; include sub-domains; allow preloading.
  // Only meaningful in production behind HTTPS termination.
  hsts: process.env.NODE_ENV === 'production'
    ? { maxAge: 31_536_000, includeSubDomains: true, preload: true }
    : false,

  // CSP: this is a pure API server — it should never serve HTML or scripts.
  // Deny everything to ensure no accidental browser rendering of responses.
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'none'"],
      scriptSrc:   ["'none'"],
      styleSrc:    ["'none'"],
      imgSrc:      ["'none'"],
      connectSrc:  ["'none'"],
      fontSrc:     ["'none'"],
      objectSrc:   ["'none'"],
      frameSrc:    ["'none'"],
    },
  },

  // Prevent this API's JSON responses from being loaded in an iframe
  frameguard: { action: 'deny' },

  // Do not include referrer when navigating from this API
  referrerPolicy: { policy: 'no-referrer' },
}));

// ── CORS ──────────────────────────────────────────────────────────────────────
// Allow only the configured frontend origin. In development, localhost:3000.
// In production, FRONTEND_URL must be set (validated above).
app.use(cors({
  origin:       process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials:  true,
  methods:      ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge:       86400, // cache pre-flight response for 24 h to reduce OPTIONS requests
}));

// ── Rate limiting — global safety net ────────────────────────────────────────
// Individual routes apply stricter limiters on top of this.
app.use('/api/', globalLimiter);

// ── Body parsing ──────────────────────────────────────────────────────────────
// OWASP A04: 100KB is generous for any legitimate API payload here.
// The original 10MB limit could be exploited to OOM the process.
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// ── Request logging (dev only) ────────────────────────────────────────────────
// Never log in production — access logs contain PII (IPs, email in query strings).
// Use a dedicated log aggregator (Datadog, CloudWatch, etc.) at the infra layer.
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// ── Health check ──────────────────────────────────────────────────────────────
// OWASP A05: do NOT reveal DB type, version, or internal service names.
app.get('/api/health', (_req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/auth',       require('./routes/auth'));
app.use('/api/industries', require('./routes/industries'));
app.use('/api/waste',      require('./routes/waste'));
app.use('/api/resources',  require('./routes/resource'));
app.use('/api/matches',    require('./routes/matches'));
app.use('/api/impact',     require('./routes/impact'));

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, error: 'Route not found' });
});

// ── Global error handler ──────────────────────────────────────────────────────
// OWASP A09: never leak stack traces or internal error messages to clients.
app.use((err, _req, res, _next) => {
  // Log full detail server-side for debugging
  console.error('Unhandled error:', err);
  res.status(err.status || 500).json({
    success: false,
    // Only show message in development; production gets a generic response
    error: process.env.NODE_ENV === 'production'
      ? 'An internal error occurred. Please try again later.'
      : err.message,
  });
});

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║   🚀  SymbioTech API Started                 ║
║   Port : ${PORT}                               ║
║   Env  : ${process.env.NODE_ENV || 'development'}                     ║
╚══════════════════════════════════════════════╝
  `);
});

module.exports = app;
