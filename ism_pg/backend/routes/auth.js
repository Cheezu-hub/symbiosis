/**
 * routes/auth.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OWASP A07 — Identification and Authentication Failures
 * OWASP A02 — Cryptographic Failures
 *
 * Security changes vs original:
 *  1. authLimiter applied to /login and /register (10 req / 15 min per IP).
 *  2. validateRegister / validateLogin strip unexpected fields, enforce
 *     length limits, validate email format, and cap passwords at 72 chars
 *     (bcrypt silently truncates at 72 — longer passwords give false sense
 *     of security while being equivalent to a 72-char password).
 *  3. JWT signed with explicit algorithm HS256 (matches verify whitelist
 *     in database.js — prevents alg:none downgrade attack).
 *  4. JWT_SECRET sourced from database.js (single source of truth; that
 *     module already validated it at boot — no 'fallback_secret' here).
 *  5. Login returns the SAME error message whether email or password is
 *     wrong — prevents user enumeration (OWASP A01).
 *  6. bcrypt work factor raised to 12 (2^12 = 4096 iterations; 10 was the
 *     original and is now below current OWASP recommendation).
 */

const express    = require('express');
const router     = express.Router();
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { pool, authenticateToken, JWT_SECRET } = require('../models/database');
const { authLimiter }                          = require('../middleware/rateLimiter');
const {
  validateRegister,
  validateLogin,
  validateProfileUpdate,
} = require('../middleware/validate');

// POST /api/auth/register
// Rate limit: 10 req / 15 min (authLimiter)
router.post('/register', authLimiter, validateRegister, async (req, res) => {
  try {
    const { companyName, industryType, email, phone, location, password } = req.body;

    // Check for duplicate email
    const existing = await pool.query(
      'SELECT id FROM industries WHERE contact_email = $1', [email]
    );
    if (existing.rows.length > 0) {
      // OWASP A01: return generic message so attackers can't enumerate accounts
      return res.status(400).json({ success: false, error: 'Registration failed. Please check your details.' });
    }

    // bcrypt cost factor 12 (OWASP 2023 recommendation: ≥ 10, prefer 12+)
    const hash   = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO industries (company_name, industry_type, location, contact_email, contact_phone, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, company_name, industry_type, contact_email, location`,
      [companyName, industryType || null, location || null, email, phone || null, hash]
    );

    const user  = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.contact_email },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '7d' } // explicit algorithm
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id:           user.id,
        companyName:  user.company_name,
        industryType: user.industry_type,
        email:        user.contact_email,
        location:     user.location,
      },
    });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ success: false, error: 'Registration failed.' });
  }
});

// POST /api/auth/login
// Rate limit: 10 req / 15 min (authLimiter)
router.post('/login', authLimiter, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM industries WHERE contact_email = $1', [email]
    );

    // OWASP A07: use constant-time compare even for "not found" case to
    // prevent timing-based user enumeration. We hash a dummy string so the
    // bcrypt compare always runs regardless.
    const DUMMY_HASH = '$2a$12$invalidhashpaddingtomatchbcryptlengthXXXXXXXXXXXXXXXX';
    const storedHash = result.rows.length > 0
      ? result.rows[0].password_hash
      : DUMMY_HASH;

    const valid = await bcrypt.compare(password, storedHash);

    // Same error message whether email was wrong or password was wrong
    if (result.rows.length === 0 || !valid) {
      return res.status(401).json({ success: false, error: 'Invalid email or password.' });
    }

    const user  = result.rows[0];
    const token = jwt.sign(
      { id: user.id, email: user.contact_email },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id:           user.id,
        companyName:  user.company_name,
        industryType: user.industry_type,
        email:        user.contact_email,
        location:     user.location,
      },
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ success: false, error: 'Login failed.' });
  }
});

// GET /api/auth/profile — protected
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, company_name, industry_type, contact_email, contact_phone,
              location, transport_radius_km, website, sustainability_score
       FROM industries WHERE id = $1`,
      [req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ success: false, error: 'User not found.' });

    const u = result.rows[0];
    res.json({
      success: true,
      user: {
        id:                  u.id,
        companyName:         u.company_name,
        industryType:        u.industry_type,
        email:               u.contact_email,
        phone:               u.contact_phone,
        location:            u.location,
        transportRadius:     u.transport_radius_km,
        website:             u.website,
        sustainabilityScore: u.sustainability_score,
      },
    });
  } catch (err) {
    console.error('Profile fetch error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch profile.' });
  }
});

// PUT /api/auth/profile — protected
router.put('/profile', authenticateToken, validateProfileUpdate, async (req, res) => {
  try {
    const { companyName, industryType, phone, location, transportRadius, website } = req.body;
    const result = await pool.query(
      `UPDATE industries SET
         company_name        = COALESCE($1, company_name),
         industry_type       = COALESCE($2, industry_type),
         contact_phone       = COALESCE($3, contact_phone),
         location            = COALESCE($4, location),
         transport_radius_km = COALESCE($5, transport_radius_km),
         website             = COALESCE($6, website),
         updated_at          = CURRENT_TIMESTAMP
       WHERE id = $7
       RETURNING id, company_name, industry_type, contact_email, contact_phone, location`,
      [companyName, industryType, phone, location, transportRadius, website, req.user.id]
    );
    const u = result.rows[0];
    res.json({
      success: true,
      user: {
        id:           u.id,
        companyName:  u.company_name,
        industryType: u.industry_type,
        email:        u.contact_email,
        phone:        u.contact_phone,
        location:     u.location,
      },
    });
  } catch (err) {
    console.error('Profile update error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to update profile.' });
  }
});

// POST /api/auth/logout
// Note: JWTs are stateless — true invalidation requires a token blacklist
// (Redis / DB table). For now we return 200 so the client clears its token.
// TODO: implement token blacklist if session revocation is required.
router.post('/logout', (_req, res) => {
  res.json({ success: true, message: 'Logged out successfully.' });
});

module.exports = router;
