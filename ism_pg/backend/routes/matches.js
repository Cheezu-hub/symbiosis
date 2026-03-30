/**
 * routes/matches.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OWASP A01 — Broken Access Control
 *
 * Security changes vs original:
 *  1. aiMatchLimiter on POST /generate (5 req / 5 min) — prevents repeated
 *     expensive full-table scans from hammering the database.
 *  2. validateQueryPagination on GET / — caps limit at 100.
 *  3. validateId on /:id, /:id/accept, /:id/reject.
 *  4. All routes already required authentication (no change needed there).
 */

const express  = require('express');
const router   = express.Router();
const { pool, authenticateToken } = require('../models/database');
const { aiMatchLimiter }           = require('../middleware/rateLimiter');
const { validateId, validateQueryPagination } = require('../middleware/validate');

router.use(authenticateToken);

// ── AI Matching helpers ───────────────────────────────────────────────────────
const calculateMatchScore = (waste, request) => {
  let score = 0;
  const wasteType   = (waste.material_type    || '').toLowerCase().trim();
  const requestType = (request.material_needed || '').toLowerCase().trim();

  if (wasteType === requestType) {
    score += 50;
  } else if (wasteType.includes(requestType) || requestType.includes(wasteType)) {
    score += 35;
  } else {
    const ww = wasteType.split(/\s+/);
    const rw = requestType.split(/\s+/);
    score += ww.filter(w => rw.includes(w)).length * 10;
  }

  const wq = parseFloat(waste.quantity)    || 0;
  const rq = parseFloat(request.quantity)  || 0;
  if (wq > 0 && rq > 0) score += Math.round((Math.min(wq, rq) / Math.max(wq, rq)) * 20);

  if ((waste.unit || '').toLowerCase() === (request.unit || '').toLowerCase()) score += 10;

  const wl = (waste.location    || '').toLowerCase();
  const rl = (request.location  || '').toLowerCase();
  if (wl && rl) {
    if (wl === rl) {
      score += 20;
    } else {
      const ww2 = wl.split(/[\s,]+/);
      const rw2 = rl.split(/[\s,]+/);
      score += Math.min(15, ww2.filter(w => w.length > 2 && rw2.includes(w)).length * 7);
    }
  }

  return Math.min(100, Math.round(score));
};

const calculateImpact = (materialType, quantity) => {
  const co2Factors = {
    'fly ash': 0.8, 'steel slag': 0.6, 'blast furnace slag': 0.7,
    'waste heat': 1.2, 'chemical byproduct': 0.5, 'scrap metal': 1.5,
    'plastic waste': 2.0, 'paper waste': 0.9, 'glass waste': 0.3,
    'rubber waste': 1.8, 'wood waste': 0.4, 'textile waste': 1.1,
  };
  const key    = (materialType || '').toLowerCase().trim();
  const factor = Object.entries(co2Factors).find(([k]) => key.includes(k))?.[1] || 0.5;
  const qty    = parseFloat(quantity) || 0;
  return {
    co2ReductionTons: parseFloat((qty * factor).toFixed(2)),
    costSavings:      Math.round(qty * 2500),
    logisticsCost:    Math.round(qty * 300),
  };
};

// POST /api/matches/generate — AI matching engine
router.post('/generate', aiMatchLimiter, async (req, res) => {
  try {
    const wastesResult = await pool.query(
      `SELECT wl.*, i.company_name FROM waste_listings wl
       JOIN industries i ON wl.industry_id = i.id WHERE wl.status = 'available'`
    );
    const requestsResult = await pool.query(
      `SELECT rr.*, i.company_name FROM resource_requests rr
       JOIN industries i ON rr.industry_id = i.id WHERE rr.status = 'active'`
    );

    const wastes   = wastesResult.rows;
    const requests = requestsResult.rows;

    if (wastes.length === 0 || requests.length === 0) {
      return res.json({ success: true, message: 'No listings or requests available to match.', matchesCreated: 0 });
    }

    let matchesCreated = 0;
    for (const waste of wastes) {
      for (const request of requests) {
        if (waste.industry_id === request.industry_id) continue;

        const existing = await pool.query(
          'SELECT id FROM matches WHERE waste_listing_id=$1 AND resource_request_id=$2',
          [waste.id, request.id]
        );
        if (existing.rows.length > 0) continue;

        const score = calculateMatchScore(waste, request);
        if (score >= 30) {
          const impact = calculateImpact(waste.material_type, Math.min(waste.quantity, request.quantity));
          await pool.query(
            `INSERT INTO matches (waste_listing_id, resource_request_id, match_score, co2_reduction_tons, cost_savings, logistics_cost)
             VALUES ($1,$2,$3,$4,$5,$6)`,
            [waste.id, request.id, score, impact.co2ReductionTons, impact.costSavings, impact.logisticsCost]
          );
          matchesCreated++;
        }
      }
    }
    res.json({ success: true, message: `AI matching complete. ${matchesCreated} new match(es) created.`, matchesCreated });
  } catch (err) {
    console.error('Generate matches error:', err.message);
    res.status(500).json({ success: false, error: 'Failed to generate matches.' });
  }
});

// GET /api/matches
router.get('/', validateQueryPagination, async (req, res) => {
  try {
    const { status, limit, offset } = req.query;
    const userId = req.user.id;

    // Whitelist status values
    const ALLOWED = new Set(['pending', 'accepted', 'rejected']);
    let query  = `
      SELECT m.*,
             wl.material_type  AS waste_type,  wl.quantity AS waste_quantity,
             wl.unit           AS waste_unit,  wl.location AS waste_location,
             rr.material_needed AS resource_type, rr.location AS resource_location,
             i1.company_name   AS waste_provider,  i1.industry_type AS waste_provider_type,
             i2.company_name   AS resource_seeker, i2.industry_type AS resource_seeker_type
      FROM matches m
      JOIN waste_listings    wl ON m.waste_listing_id    = wl.id
      JOIN resource_requests rr ON m.resource_request_id = rr.id
      JOIN industries i1 ON wl.industry_id = i1.id
      JOIN industries i2 ON rr.industry_id = i2.id
      WHERE (wl.industry_id = $1 OR rr.industry_id = $1)`;
    const params = [userId];
    let   c      = 2;

    if (status && ALLOWED.has(status)) {
      query += ` AND m.status = $${c++}`;
      params.push(status);
    }

    query += ` ORDER BY m.match_score DESC, m.created_at DESC LIMIT $${c} OFFSET $${c + 1}`;
    params.push(limit, offset);

    const result = await pool.query(query, params);
    const count  = await pool.query(
      `SELECT COUNT(*) AS total FROM matches m
       JOIN waste_listings    wl ON m.waste_listing_id    = wl.id
       JOIN resource_requests rr ON m.resource_request_id = rr.id
       WHERE wl.industry_id = $1 OR rr.industry_id = $1`,
      [userId]
    );

    res.json({
      success: true,
      data: {
        matches: result.rows.map(r => ({
          id:               r.id,
          wasteType:        r.waste_type,
          resourceType:     r.resource_type,
          wasteProvider:    r.waste_provider,
          resourceSeeker:   r.resource_seeker,
          wasteProviderType:  r.waste_provider_type,
          resourceSeekerType: r.resource_seeker_type,
          quantity:         `${r.waste_quantity} ${r.waste_unit}`,
          wasteLocation:    r.waste_location,
          resourceLocation: r.resource_location,
          matchScore:       r.match_score,
          status:           r.status,
          co2Reduction:     parseFloat(r.co2_reduction_tons)  || 0,
          costSavings:      parseFloat(r.cost_savings)        || 0,
          logisticsCost:    parseFloat(r.logistics_cost)      || 0,
          createdAt:        r.created_at,
          acceptedAt:       r.accepted_at,
        })),
        pagination: {
          total:  parseInt(count.rows[0].total, 10),
          limit,
          offset,
        },
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch matches.' });
  }
});

// GET /api/matches/recommendations — must be before /:id
router.get('/recommendations', async (req, res) => {
  try {
    const rows = await pool.query(
      `SELECT m.*,
              wl.material_type AS waste_type, wl.quantity AS waste_quantity, wl.unit AS waste_unit,
              rr.material_needed AS resource_type,
              i1.company_name AS waste_provider, i2.company_name AS resource_seeker
       FROM matches m
       JOIN waste_listings    wl ON m.waste_listing_id    = wl.id
       JOIN resource_requests rr ON m.resource_request_id = rr.id
       JOIN industries i1 ON wl.industry_id = i1.id
       JOIN industries i2 ON rr.industry_id = i2.id
       WHERE m.status = 'pending'
         AND (wl.industry_id = $1 OR rr.industry_id = $1)
       ORDER BY m.match_score DESC
       LIMIT 10`,
      [req.user.id]
    );
    res.json({ success: true, data: rows.rows });
  } catch (err) {
    res.json({ success: true, data: [] });
  }
});

// GET /api/matches/:id
router.get('/:id', validateId, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*,
              wl.material_type AS waste_type, wl.description AS waste_description,
              wl.quantity AS waste_quantity, wl.unit AS waste_unit, wl.location AS waste_location,
              rr.material_needed AS resource_type, rr.description AS resource_description, rr.location AS resource_location,
              i1.company_name AS waste_provider, i1.contact_email AS waste_provider_email,
              i1.contact_phone AS waste_provider_phone, i1.location AS waste_provider_location,
              i2.company_name AS resource_seeker, i2.contact_email AS resource_seeker_email,
              i2.contact_phone AS resource_seeker_phone, i2.location AS resource_seeker_location
       FROM matches m
       JOIN waste_listings    wl ON m.waste_listing_id    = wl.id
       JOIN resource_requests rr ON m.resource_request_id = rr.id
       JOIN industries i1 ON wl.industry_id = i1.id
       JOIN industries i2 ON rr.industry_id = i2.id
       WHERE m.id = $1 AND (wl.industry_id = $2 OR rr.industry_id = $2)`,
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ success: false, error: 'Match not found.' });

    const r = result.rows[0];
    res.json({
      success: true,
      data: {
        id: r.id, wasteType: r.waste_type, wasteDescription: r.waste_description,
        resourceType: r.resource_type, resourceDescription: r.resource_description,
        wasteProvider: {
          name:     r.waste_provider,
          email:    r.waste_provider_email,
          phone:    r.waste_provider_phone,
          location: r.waste_provider_location,
        },
        resourceSeeker: {
          name:     r.resource_seeker,
          email:    r.resource_seeker_email,
          phone:    r.resource_seeker_phone,
          location: r.resource_seeker_location,
        },
        quantity:      `${r.waste_quantity} ${r.waste_unit}`,
        matchScore:    r.match_score,
        status:        r.status,
        co2Reduction:  parseFloat(r.co2_reduction_tons) || 0,
        costSavings:   parseFloat(r.cost_savings)       || 0,
        logisticsCost: parseFloat(r.logistics_cost)     || 0,
        createdAt:     r.created_at,
        acceptedAt:    r.accepted_at,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch match.' });
  }
});

// POST /api/matches/:id/accept
router.post('/:id/accept', validateId, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const check = await pool.query(
      `SELECT m.*, wl.industry_id AS waste_owner, rr.industry_id AS resource_owner, wl.quantity AS waste_quantity
       FROM matches m
       JOIN waste_listings    wl ON m.waste_listing_id    = wl.id
       JOIN resource_requests rr ON m.resource_request_id = rr.id
       WHERE m.id = $1`,
      [id]
    );
    if (check.rows.length === 0) return res.status(404).json({ success: false, error: 'Match not found.' });
    const match = check.rows[0];
    if (match.waste_owner !== userId && match.resource_owner !== userId)
      return res.status(403).json({ success: false, error: 'Forbidden.' });
    if (match.status === 'accepted')
      return res.status(400).json({ success: false, error: 'Match already accepted.' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`UPDATE matches SET status='accepted', accepted_at=CURRENT_TIMESTAMP WHERE id=$1`, [id]);
      await client.query(`UPDATE waste_listings SET status='reserved' WHERE id=$1`, [match.waste_listing_id]);
      await client.query(`UPDATE resource_requests SET status='fulfilled' WHERE id=$1`, [match.resource_request_id]);
      if (match.co2_reduction_tons) {
        await client.query(
          `INSERT INTO impact_metrics (industry_id, co2_reduced_tons, waste_diverted_tons, recorded_date)
           VALUES ($1,$2,$3,CURRENT_DATE)
           ON CONFLICT (industry_id, recorded_date) DO UPDATE SET
             co2_reduced_tons    = impact_metrics.co2_reduced_tons    + EXCLUDED.co2_reduced_tons,
             waste_diverted_tons = impact_metrics.waste_diverted_tons + EXCLUDED.waste_diverted_tons`,
          [match.waste_owner, match.co2_reduction_tons, match.waste_quantity]
        );
      }
      await client.query(
        `UPDATE industries SET
           sustainability_score = LEAST(100, sustainability_score + 5),
           updated_at           = CURRENT_TIMESTAMP
         WHERE id = $1 OR id = $2`,
        [match.waste_owner, match.resource_owner]
      );
      await client.query('COMMIT');
      res.json({ success: true, message: 'Match accepted.' });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to accept match.' });
  }
});

// POST /api/matches/:id/reject
router.post('/:id/reject', validateId, async (req, res) => {
  try {
    const { id } = req.params;
    const check  = await pool.query(
      `SELECT wl.industry_id AS waste_owner, rr.industry_id AS resource_owner
       FROM matches m
       JOIN waste_listings    wl ON m.waste_listing_id    = wl.id
       JOIN resource_requests rr ON m.resource_request_id = rr.id
       WHERE m.id = $1`,
      [id]
    );
    if (check.rows.length === 0) return res.status(404).json({ success: false, error: 'Match not found.' });
    const match = check.rows[0];
    if (match.waste_owner !== req.user.id && match.resource_owner !== req.user.id)
      return res.status(403).json({ success: false, error: 'Forbidden.' });

    await pool.query(`UPDATE matches SET status='rejected' WHERE id=$1`, [id]);
    res.json({ success: true, message: 'Match rejected.' });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to reject match.' });
  }
});

module.exports = router;
