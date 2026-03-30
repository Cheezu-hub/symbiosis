/**
 * routes/industries.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OWASP A01 — Broken Access Control
 *
 * Security changes vs original:
 *  1. GET /:id previously returned contact_email and contact_phone to anyone —
 *     this is PII. It now requires authentication to access contact details.
 *     The public view only returns company name, type, location, and score.
 *  2. validateQueryPagination caps limit at 100.
 *  3. validateId on /:id prevents path-parameter injection.
 *  4. industryType / location filter inputs are length-capped before use.
 */

const express  = require('express');
const router   = express.Router();
const { pool, authenticateToken } = require('../models/database');
const { validateId, validateQueryPagination } = require('../middleware/validate');

// GET /api/industries — public (non-PII fields only)
router.get('/', validateQueryPagination, async (req, res) => {
  try {
    const { industryType, location, limit, offset } = req.query;

    let query  = `SELECT id, company_name, industry_type, location,
                         transport_radius_km, sustainability_score
                  FROM industries WHERE 1=1`;
    const params = [];
    let   c      = 1;

    if (industryType && typeof industryType === 'string' && industryType.length <= 50) {
      query += ` AND industry_type = $${c++}`;
      params.push(industryType);
    }
    if (location && typeof location === 'string' && location.length <= 200) {
      query += ` AND location ILIKE $${c++}`;
      params.push(`%${location}%`);
    }

    query += ` ORDER BY sustainability_score DESC LIMIT $${c} OFFSET $${c + 1}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    res.json({
      success: true,
      data: result.rows.map(r => ({
        id:                  r.id,
        companyName:         r.company_name,
        industryType:        r.industry_type,
        location:            r.location,
        transportRadius:     r.transport_radius_km,
        sustainabilityScore: r.sustainability_score,
      })),
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch industries.' });
  }
});

// GET /api/industries/network — public (aggregate data, no PII)
router.get('/network', async (req, res) => {
  try {
    const industries = await pool.query(
      'SELECT id, company_name, industry_type, location FROM industries'
    );
    const matches = await pool.query(
      `SELECT m.id,
              wl.industry_id AS source_id,
              rr.industry_id AS target_id,
              wl.material_type AS material,
              wl.quantity      AS value
       FROM matches m
       JOIN waste_listings    wl ON m.waste_listing_id    = wl.id
       JOIN resource_requests rr ON m.resource_request_id = rr.id
       WHERE m.status = 'accepted'`
    );
    res.json({
      success: true,
      data: {
        nodes: industries.rows.map(r => ({
          id:       r.id,
          label:    r.company_name,
          type:     (r.industry_type || 'default').toLowerCase(),
          location: r.location,
        })),
        links: matches.rows.map(r => ({
          source:   r.source_id,
          target:   r.target_id,
          material: r.material,
          value:    parseFloat(r.value),
        })),
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch network.' });
  }
});

// GET /api/industries/:id
// Public view: returns non-PII fields.
// Authenticated view: also returns contact details.
router.get('/:id', validateId, async (req, res) => {
  try {
    // Check if the request carries a valid JWT (optional auth pattern)
    let isAuthenticated = false;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
      try {
        const jwt = require('jsonwebtoken');
        const { JWT_SECRET } = require('../models/database');
        jwt.verify(authHeader.split(' ')[1], JWT_SECRET, { algorithms: ['HS256'] });
        isAuthenticated = true;
      } catch (_) {
        // token invalid or expired — treat as unauthenticated
      }
    }

    const result = await pool.query(
      `SELECT id, company_name, industry_type, contact_email, contact_phone,
              location, transport_radius_km, website, sustainability_score, created_at
       FROM industries WHERE id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ success: false, error: 'Industry not found.' });

    const r    = result.rows[0];
    const data = {
      id:                  r.id,
      companyName:         r.company_name,
      industryType:        r.industry_type,
      location:            r.location,
      transportRadius:     r.transport_radius_km,
      website:             r.website,
      sustainabilityScore: r.sustainability_score,
      createdAt:           r.created_at,
    };

    // Only return PII (email / phone) to authenticated users
    if (isAuthenticated) {
      data.email = r.contact_email;
      data.phone = r.contact_phone;
    }

    res.json({ success: true, data });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch industry.' });
  }
});

module.exports = router;
