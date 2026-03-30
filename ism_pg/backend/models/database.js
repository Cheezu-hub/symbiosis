/**
 * database.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OWASP A02 — Cryptographic Failures / A05 — Security Misconfiguration
 *
 * Security changes vs original:
 *  1. JWT_SECRET — removed 'fallback_secret' hard-coded default.
 *     The server now refuses to start if JWT_SECRET is missing or weak
 *     (< 32 chars) in any environment. This prevents accidentally deploying
 *     with a known/weak secret.
 *  2. DB_PASSWORD — no default empty string in production (warns loudly).
 *  3. Pool SSL — enabled when NODE_ENV=production so credentials are
 *     encrypted in transit to the DB server.
 *  4. jwt.verify is called once at module load so require() isn't called
 *     per-request inside the hot path.
 */

const { Pool } = require('pg');
const jwt       = require('jsonwebtoken');
require('dotenv').config();

// ── Security boot-time checks ─────────────────────────────────────────────────

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  // Hard fail: running without a JWT secret means every token is invalid or
  // can be forged depending on the jwt library version.
  console.error('FATAL: JWT_SECRET environment variable is not set. Server refused to start.');
  console.error('Set a strong random value in your .env file:');
  console.error('  node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
  process.exit(1);
}

if (JWT_SECRET.length < 32) {
  // Short secrets are brute-forceable; reject them.
  console.error('FATAL: JWT_SECRET is too short (minimum 32 characters). Server refused to start.');
  process.exit(1);
}

// Warn (don't block) if running in production with no DB password
if (process.env.NODE_ENV === 'production' && !process.env.DB_PASSWORD) {
  console.warn('SECURITY WARNING: DB_PASSWORD is not set in production. Connections are unauthenticated.');
}

// ── PostgreSQL connection pool ────────────────────────────────────────────────
const poolConfig = {
  host:                    process.env.DB_HOST     || 'localhost',
  port:                    parseInt(process.env.DB_PORT || '5432', 10),
  database:                process.env.DB_NAME     || 'symbiotech',
  user:                    process.env.DB_USER     || 'postgres',
  password:                process.env.DB_PASSWORD,   // undefined is fine for local dev
  max:                     20,
  idleTimeoutMillis:       30000,
  connectionTimeoutMillis: 2000,
};

// Enable SSL in production so credentials are encrypted in transit
if (process.env.NODE_ENV === 'production') {
  poolConfig.ssl = { rejectUnauthorized: true };
}

const pool = new Pool(poolConfig);

pool.on('connect', () => console.log('✅ Database connected'));
pool.on('error',   (err) => {
  // Log the error type but NOT the full stack in production (may leak DB info)
  console.error('❌ Unexpected database error:', process.env.NODE_ENV === 'production' ? err.message : err);
  process.exit(-1);
});

// ── JWT middleware ────────────────────────────────────────────────────────────
/**
 * authenticateToken
 *
 * OWASP A07 — Identification and Authentication Failures
 *
 * Changes vs original:
 *  • Expired tokens now return 401 (session ended) not 403 (forbidden).
 *    This lets the frontend distinguish "log back in" from "no permission".
 *  • Token type prefix "Bearer " is enforced (case-insensitive).
 *  • jwt.verify options are explicit: algorithm whitelist prevents the
 *    "alg:none" attack where an attacker strips the signature.
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.toLowerCase().startsWith('bearer ')) {
    return res.status(401).json({ success: false, error: 'Authorization header missing or malformed. Use: Bearer <token>' });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(
    token,
    JWT_SECRET,
    { algorithms: ['HS256'] }, // OWASP: whitelist algorithm — prevents alg:none attack
    (err, decoded) => {
      if (err) {
        // Distinguish expired vs invalid so frontend can redirect to login cleanly
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({ success: false, error: 'Session expired. Please log in again.' });
        }
        return res.status(401).json({ success: false, error: 'Invalid token.' });
      }
      req.user = decoded;
      next();
    }
  );
};

module.exports = { pool, authenticateToken, JWT_SECRET };
