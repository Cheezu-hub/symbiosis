/**
 * routes/resource.js — same hardening pattern as waste.js
 */

const express  = require('express');
const router   = express.Router();
const { pool, authenticateToken } = require('../models/database');
const { writeLimiter, searchLimiter } = require('../middleware/rateLimiter');
const {
  validateId,
  validateResourceRequest,
  validateResourceUpdate,
  validateQueryPagination,
} = require('../middleware/validate');

const ALLOWED_STATUSES = new Set(['active', 'fulfilled', 'cancelled']);

// GET /api/resources
router.get('/', validateQueryPagination, async (req, res) => {
  try {
    const { status, materialNeeded, limit, offset } = req.query;

    let query  = `SELECT rr.*, i.company_name AS requester_name, i.industry_type
                  FROM resource_requests rr
                  JOIN industries i ON rr.industry_id = i.id
                  WHERE 1=1`;
    const params = [];
    let   c      = 1;

    if (status && ALLOWED_STATUSES.has(status)) {
      query += ` AND rr.status = $${c++}`;
      params.push(status);
    }
    if (materialNeeded && typeof materialNeeded === 'string' && materialNeeded.length <= 100) {
      query += ` AND rr.material_needed ILIKE $${c++}`;
      params.push(`%${materialNeeded}%`);
    }

    query += ` ORDER BY rr.created_at DESC LIMIT $${c} OFFSET $${c + 1}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    res.json({
      success: true,
      data: result.rows.map(r => ({
        id:             r.id,
        materialNeeded: r.material_needed,
        description:    r.description,
        quantity:       parseFloat(r.quantity),
        unit:           r.unit,
        industrySector: r.industry_sector,
        location:       r.location,
        requiredBy:     r.required_by,
        status:         r.status,
        requesterName:  r.requester_name,
        industryType:   r.industry_type,
        createdAt:      r.created_at,
      })),
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch resource requests.' });
  }
});

// POST /api/resources — protected
router.post('/', authenticateToken, writeLimiter, validateResourceRequest, async (req, res) => {
  try {
    const { materialNeeded, description, quantity, unit, industrySector, location, requiredBy } = req.body;
    const result = await pool.query(
      `INSERT INTO resource_requests
         (industry_id, material_needed, description, quantity, unit, industry_sector, location, required_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING *`,
      [req.user.id, materialNeeded, description || null, quantity, unit, industrySector || null, location || null, requiredBy || null]
    );
    const r = result.rows[0];
    res.status(201).json({
      success: true,
      data: {
        id:             r.id,
        materialNeeded: r.material_needed,
        description:    r.description,
        quantity:       parseFloat(r.quantity),
        unit:           r.unit,
        industrySector: r.industry_sector,
        location:       r.location,
        requiredBy:     r.required_by,
        status:         r.status,
        createdAt:      r.created_at,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to create resource request.' });
  }
});

// PUT /api/resources/:id — protected
router.put('/:id', authenticateToken, writeLimiter, validateId, validateResourceUpdate, async (req, res) => {
  try {
    const { id } = req.params;
    const { materialNeeded, description, quantity, unit, industrySector, location, requiredBy, status } = req.body;

    const check = await pool.query('SELECT industry_id FROM resource_requests WHERE id = $1', [id]);
    if (check.rows.length === 0)
      return res.status(404).json({ success: false, error: 'Resource request not found.' });
    if (check.rows[0].industry_id !== req.user.id)
      return res.status(403).json({ success: false, error: 'Forbidden.' });

    const result = await pool.query(
      `UPDATE resource_requests SET
         material_needed = COALESCE($1, material_needed),
         description     = COALESCE($2, description),
         quantity        = COALESCE($3, quantity),
         unit            = COALESCE($4, unit),
         industry_sector = COALESCE($5, industry_sector),
         location        = COALESCE($6, location),
         required_by     = COALESCE($7, required_by),
         status          = COALESCE($8, status),
         updated_at      = CURRENT_TIMESTAMP
       WHERE id = $9
       RETURNING *`,
      [materialNeeded, description, quantity, unit, industrySector, location, requiredBy, status, id]
    );
    const r = result.rows[0];
    res.json({
      success: true,
      data: {
        id:             r.id,
        materialNeeded: r.material_needed,
        quantity:       parseFloat(r.quantity),
        unit:           r.unit,
        status:         r.status,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to update resource request.' });
  }
});

// DELETE /api/resources/:id — protected
router.delete('/:id', authenticateToken, writeLimiter, validateId, async (req, res) => {
  try {
    const { id } = req.params;
    const check = await pool.query('SELECT industry_id FROM resource_requests WHERE id = $1', [id]);
    if (check.rows.length === 0)
      return res.status(404).json({ success: false, error: 'Resource request not found.' });
    if (check.rows[0].industry_id !== req.user.id)
      return res.status(403).json({ success: false, error: 'Forbidden.' });

    await pool.query('DELETE FROM resource_requests WHERE id = $1', [id]);
    res.json({ success: true, message: 'Resource request deleted.' });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to delete.' });
  }
});

module.exports = router;
