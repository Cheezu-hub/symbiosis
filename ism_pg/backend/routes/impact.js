/**
 * routes/impact.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OWASP A03 — Injection
 *
 * Critical fix: the original code interpolated `period` directly into the
 * SQL string via template literal:
 *
 *   const dateFn = fmt[period] || fmt.monthly;
 *   pool.query(`SELECT ${dateFn} as period ...`)
 *
 * While the `fmt` object acted as a limited safeguard, this pattern is
 * inherently fragile — any future change could introduce injection.
 * Fixed by:
 *   1. validateReportPeriod middleware validates period against a whitelist
 *      BEFORE the route handler runs.
 *   2. The SQL string is built from a pre-defined map of safe PostgreSQL
 *      function strings — never from user input directly.
 *   3. validateImpactCalculation validates the POST body.
 */

const express  = require('express');
const router   = express.Router();
const { pool, authenticateToken } = require('../models/database');
const { validateReportPeriod, validateImpactCalculation } = require('../middleware/validate');

router.use(authenticateToken);

// Safe, pre-built SQL fragments — period value is validated before this map is consulted
const DATE_TRUNC_SQL = {
  weekly:  "DATE_TRUNC('week',  recorded_date)",
  monthly: "DATE_TRUNC('month', recorded_date)",
  yearly:  "DATE_TRUNC('year',  recorded_date)",
};

// GET /api/impact/metrics
router.get('/metrics', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         SUM(co2_reduced_tons)        AS co2,
         SUM(waste_diverted_tons)     AS waste,
         SUM(water_saved_liters)      AS water,
         SUM(energy_saved_mwh)        AS energy,
         SUM(raw_material_saved_tons) AS raw
       FROM impact_metrics
       WHERE industry_id = $1`,
      [req.user.id]
    );
    const r = result.rows[0];
    res.json({
      success: true,
      data: {
        co2Reduced:       parseFloat(r.co2)   || 0,
        wasteDiverted:    parseFloat(r.waste)  || 0,
        waterSaved:       parseFloat(r.water)  || 0,
        energySaved:      parseFloat(r.energy) || 0,
        rawMaterialSaved: parseFloat(r.raw)    || 0,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch metrics.' });
  }
});

// GET /api/impact/report?period=monthly|weekly|yearly
// validateReportPeriod runs first — rejects any value not in the whitelist
router.get('/report', validateReportPeriod, async (req, res) => {
  try {
    // Safe: period is guaranteed to be one of the three whitelisted values
    const dateFn = DATE_TRUNC_SQL[req.query.period];

    const result = await pool.query(
      // dateFn is from a hard-coded map, never from user input
      `SELECT
         ${dateFn}                    AS period,
         SUM(co2_reduced_tons)        AS co2,
         SUM(waste_diverted_tons)     AS waste,
         SUM(water_saved_liters)      AS water,
         SUM(energy_saved_mwh)        AS energy
       FROM impact_metrics
       WHERE industry_id = $1
       GROUP BY ${dateFn}
       ORDER BY period DESC
       LIMIT 12`,
      [req.user.id]
    );
    res.json({
      success: true,
      data: result.rows.map(r => ({
        period:        r.period,
        co2Reduced:    parseFloat(r.co2)   || 0,
        wasteDiverted: parseFloat(r.waste)  || 0,
        waterSaved:    parseFloat(r.water)  || 0,
        energySaved:   parseFloat(r.energy) || 0,
      })),
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch report.' });
  }
});

// POST /api/impact/calculate
router.post('/calculate', validateImpactCalculation, async (req, res) => {
  try {
    const { wasteTons, materialType } = req.body;
    const factors = {
      'fly ash': 0.8, 'steel slag': 0.6,
      'waste heat': 1.2, 'chemical byproduct': 0.5,
    };
    const factor = factors[(materialType || '').toLowerCase()] || 0.5;
    res.json({
      success: true,
      data: {
        co2ReducedTons:       wasteTons * factor,
        landfillDivertedTons: wasteTons,
        rawMaterialSavedTons: wasteTons * 0.8,
        waterSavedLiters:     wasteTons * 1000,
        energySavedMwh:       wasteTons * 0.3,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Calculation failed.' });
  }
});

// GET /api/impact/sustainability-score
router.get('/sustainability-score', async (req, res) => {
  try {
    const userId  = req.user.id;
    const ind     = await pool.query('SELECT sustainability_score FROM industries WHERE id = $1', [userId]);
    const impact  = await pool.query(
      `SELECT SUM(co2_reduced_tons) AS co2, SUM(waste_diverted_tons) AS waste
       FROM impact_metrics WHERE industry_id = $1`, [userId]
    );
    const matches = await pool.query(
      `SELECT COUNT(*) AS cnt FROM matches m
       JOIN waste_listings wl ON m.waste_listing_id = wl.id
       WHERE wl.industry_id = $1 AND m.status = 'accepted'`, [userId]
    );

    const score = ind.rows[0]?.sustainability_score || 0;
    const imp   = impact.rows[0];
    const cnt   = parseInt(matches.rows[0].cnt, 10);

    res.json({
      success: true,
      data: {
        overallScore: score,
        breakdown: {
          wasteDiversion:     Math.min(100, Math.round((parseFloat(imp.waste) || 0) / 10)),
          carbonReduction:    Math.min(100, Math.round((parseFloat(imp.co2)   || 0) / 5)),
          collaboration:      Math.min(100, cnt * 5),
          resourceEfficiency: Math.min(100, Math.round(score * 0.8)),
        },
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch score.' });
  }
});

module.exports = router;
