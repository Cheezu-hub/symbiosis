/**
 * rateLimiter.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OWASP A04 / A07 — Rate Limiting
 *
 * Strategy: tiered limiters matched to risk level of each endpoint.
 *
 *  Tier | Endpoints                        | Window   | Max hits
 *  ─────┼──────────────────────────────────┼──────────┼──────────
 *  1    | POST /auth/login, /auth/register | 15 min   | 10  (brute-force guard)
 *  2    | All other /api/* routes          | 15 min   | 150 (general API)
 *  3    | POST /waste, /resources (write)  | 15 min   | 30  (mutation guard)
 *  4    | POST /matches/generate (AI)      |  5 min   | 5   (expensive op)
 *  5    | GET  /waste/search, /resources   | 15 min   | 60  (search guard)
 *
 * All limiters:
 *  • Use standardHeaders (RateLimit-* RFC draft) and suppress legacy X-RateLimit-*
 *  • Return a structured JSON 429 with retryAfter so clients can back off correctly
 *  • Skip counting successful responses to avoid penalising legitimate traffic
 *    (only failed / rate-limited requests count against the window — disabled for
 *    auth tier so failed logins still count)
 */

const rateLimit = require('express-rate-limit');

// ── Shared 429 handler ────────────────────────────────────────────────────────
const handler429 = (req, res, _next, options) => {
  // OWASP: never expose internal detail in error message
  res.status(429).json({
    success:    false,
    error:      'Too many requests. Please slow down.',
    retryAfter: Math.ceil(options.windowMs / 1000), // seconds
  });
};

// ── Tier 1 — Auth endpoints (strictest) ──────────────────────────────────────
// Protects against credential stuffing and brute-force login attacks.
// 10 attempts per IP per 15 minutes covers legitimate users while blocking bots.
const authLimiter = rateLimit({
  windowMs:        15 * 60 * 1000, // 15 minutes
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         handler429,
  // Count ALL requests (including successful logins) so a script can't
  // succeed 10 times and then keep going — intentional.
  skipSuccessfulRequests: false,
  message: 'Too many authentication attempts. Try again in 15 minutes.',
});

// ── Tier 2 — Global API limiter ───────────────────────────────────────────────
// Broad safety net for any route not covered by a stricter limiter.
const globalLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             150,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         handler429,
  skipSuccessfulRequests: true, // only penalise errors / rejected requests
});

// ── Tier 3 — Write operations (POST/PUT/DELETE on data resources) ─────────────
// Prevents spam creation of waste listings / resource requests.
const writeLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             30,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         handler429,
  skipSuccessfulRequests: true,
});

// ── Tier 4 — AI matching (expensive DB operation) ────────────────────────────
// Full table scan + insert loop; limit aggressively to protect DB.
const aiMatchLimiter = rateLimit({
  windowMs:        5 * 60 * 1000, // 5 minutes
  max:             5,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         handler429,
  skipSuccessfulRequests: false,
});

// ── Tier 5 — Search endpoints ────────────────────────────────────────────────
// ILIKE queries are more expensive than index lookups; throttle accordingly.
const searchLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             60,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         handler429,
  skipSuccessfulRequests: true,
});

module.exports = { authLimiter, globalLimiter, writeLimiter, aiMatchLimiter, searchLimiter };
