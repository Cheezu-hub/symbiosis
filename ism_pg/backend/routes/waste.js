/**
 * routes/waste.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OWASP A01 — Broken Access Control
 * OWASP A03 — Injection
 *
 * Security changes vs original:
 *  1. validateWasteListing / validateWasteUpdate validate and sanitise all
 *     body fields; unexpected fields are stripped before reaching the DB.
 *  2. validateQueryPagination enforces a max limit of 100 — prevents a
 *     client from dumping the entire table with limit=999999.
 *  3. validateId ensures /:id is a positive integer (prevents injection
 *     via path parameters like /waste/1;DROP TABLE).
 *  4. writeLimiter on POST/PUT/DELETE (30 mutations / 15 min per IP).
 *  5. searchLimiter on /search (60 req / 15 min; ILIKE is more expensive).
 *  6. Status filter uses a whitelist to prevent arbitrary values entering
 *     the query.
 */

const express  = require('express');
const router   = express.Router();
const { pool, authenticateToken } = require('../models/database');
const { writeLimiter, searchLimiter } = require('../middleware/rateLimiter');
const {
  validateId,
  validateWasteListing,
  validateWasteUpdate,
  validateQueryPagination,
} = require('../middleware/validate');

const ALLOWED_STATUSES = new Set(['available', 'reserved', 'expired']);

// GET /api/waste — public list
router.get('/', validateQueryPagination, async (req, res) => {
  try {
    const { status, materialType, limit, offset } = req.query;

    let query  = `SELECT wl.*, i.company_name AS provider_name, i.industry_type
                  FROM waste_listings wl
                  JOIN industries i ON wl.industry_id = i.id
                  WHERE 1=1`;
    const params = [];
    let   c      = 1;

    // Whitelist status to prevent arbitrary filter injection
    if (status && ALLOWED_STATUSES.has(status)) {
      query += ` AND wl.status = $${c++}`;
      params.push(status);
    }
    if (materialType && typeof materialType === 'string' && materialType.length <= 100) {
      query += ` AND wl.material_type ILIKE $${c++}`;
      params.push(`%${materialType}%`);
    }

    query += ` ORDER BY wl.created_at DESC LIMIT $${c} OFFSET $${c + 1}`;
    params.push(limit, offset); // already coerced + capped by validateQueryPagination

    const result = await pool.query(query, params);
    res.json({
      success: true,
      data: result.rows.map(r => ({
        id:           r.id,
        materialType: r.material_type,
        description:  r.description,
        quantity:     parseFloat(r.quantity),
        unit:         r.unit,
        location:     r.location,
        availableFrom:r.available_from,
        status:       r.status,
        providerName: r.provider_name,
        industryType: r.industry_type,
        createdAt:    r.created_at,
      })),
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch waste listings.' });
  }
});

// GET /api/waste/search — public (must be before /:id)
router.get('/search', searchLimiter, async (req, res) => {
  try {
    const q = req.query.q;
    if (!q || typeof q !== 'string' || q.trim().length === 0)
      return res.status(400).json({ success: false, error: 'Search query q is required.' });
    if (q.length > 100)
      return res.status(400).json({ success: false, error: 'Search query must be ≤ 100 characters.' });

    const result = await pool.query(
      `SELECT wl.*, i.company_name AS provider_name
       FROM waste_listings wl
       JOIN industries i ON wl.industry_id = i.id
       WHERE wl.material_type ILIKE $1 OR wl.description ILIKE $1
       ORDER BY wl.created_at DESC
       LIMIT 50`,
      [`%${q.trim()}%`]
    );
    res.json({
      success: true,
      data: result.rows.map(r => ({
        id:           r.id,
        materialType: r.material_type,
        description:  r.description,
        quantity:     parseFloat(r.quantity),
        unit:         r.unit,
        location:     r.location,
        status:       r.status,
        providerName: r.provider_name,
      })),
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Search failed.' });
  }
});

// GET /api/waste/:id — public
router.get('/:id', validateId, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT wl.*, i.company_name AS provider_name, i.contact_email, i.contact_phone
       FROM waste_listings wl
       JOIN industries i ON wl.industry_id = i.id
       WHERE wl.id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ success: false, error: 'Waste listing not found.' });

    const r = result.rows[0];
    res.json({
      success: true,
      data: {
        id:           r.id,
        materialType: r.material_type,
        description:  r.description,
        quantity:     parseFloat(r.quantity),
        unit:         r.unit,
        location:     r.location,
        availableFrom:r.available_from,
        status:       r.status,
        providerName: r.provider_name,
        contactEmail: r.contact_email,
        contactPhone: r.contact_phone,
        createdAt:    r.created_at,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch listing.' });
  }
});

// POST /api/waste — protected
router.post('/', authenticateToken, writeLimiter, validateWasteListing, async (req, res) => {
  try {
    const { materialType, description, quantity, unit, location, availableFrom } = req.body;
    const result = await pool.query(
      `INSERT INTO waste_listings
         (industry_id, material_type, description, quantity, unit, location, available_from)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [req.user.id, materialType, description || null, quantity, unit, location || null, availableFrom || null]
    );
    const r = result.rows[0];
    res.status(201).json({
      success: true,
      data: {
        id:           r.id,
        materialType: r.material_type,
        description:  r.description,
        quantity:     parseFloat(r.quantity),
        unit:         r.unit,
        location:     r.location,
        availableFrom:r.available_from,
        status:       r.status,
        createdAt:    r.created_at,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to create listing.' });
  }
});

// PUT /api/waste/:id — protected
router.put('/:id', authenticateToken, writeLimiter, validateId, validateWasteUpdate, async (req, res) => {
  try {
    const { id } = req.params;
    const { materialType, description, quantity, unit, location, availableFrom, status } = req.body;

    const check = await pool.query('SELECT industry_id FROM waste_listings WHERE id = $1', [id]);
    if (check.rows.length === 0)
      return res.status(404).json({ success: false, error: 'Waste listing not found.' });
    if (check.rows[0].industry_id !== req.user.id)
      return res.status(403).json({ success: false, error: 'Forbidden.' });

    const result = await pool.query(
      `UPDATE waste_listings SET
         material_type  = COALESCE($1, material_type),
         description    = COALESCE($2, description),
         quantity       = COALESCE($3, quantity),
         unit           = COALESCE($4, unit),
         location       = COALESCE($5, location),
         available_from = COALESCE($6, available_from),
         status         = COALESCE($7, status),
         updated_at     = CURRENT_TIMESTAMP
       WHERE id = $8
       RETURNING *`,
      [materialType, description, quantity, unit, location, availableFrom, status, id]
    );
    const r = result.rows[0];
    res.json({
      success: true,
      data: {
        id:           r.id,
        materialType: r.material_type,
        quantity:     parseFloat(r.quantity),
        unit:         r.unit,
        status:       r.status,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to update listing.' });
  }
});

// DELETE /api/waste/:id — protected
router.delete('/:id', authenticateToken, writeLimiter, validateId, async (req, res) => {
  try {
    const { id } = req.params;
    const check = await pool.query('SELECT industry_id FROM waste_listings WHERE id = $1', [id]);
    if (check.rows.length === 0)
      return res.status(404).json({ success: false, error: 'Waste listing not found.' });
    if (check.rows[0].industry_id !== req.user.id)
      return res.status(403).json({ success: false, error: 'Forbidden.' });

    await pool.query('DELETE FROM waste_listings WHERE id = $1', [id]);
    res.json({ success: true, message: 'Waste listing deleted.' });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to delete.' });
  }
});

module.exports = router;
