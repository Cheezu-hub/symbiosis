/**
 * validate.js
 * ─────────────────────────────────────────────────────────────────────────────
 * OWASP A03 — Injection / A04 — Insecure Design
 *
 * Central input validation and sanitisation layer.
 *
 * Design principles:
 *  1. Whitelist fields — strip any key not explicitly allowed (prevents mass
 *     assignment attacks where an attacker POSTs extra fields like
 *     { "sustainability_score": 100 } to escalate their own account).
 *  2. Type coercion — convert strings to numbers before they reach the DB.
 *  3. Length limits — cap every string to a reasonable max so the DB is never
 *     fed multi-megabyte strings.
 *  4. Format checks — validate email, URL, date, enum values.
 *  5. Numeric bounds — quantity/radius must be positive and within sane range.
 *  6. Integer IDs — route params like /:id must be a positive integer.
 *  7. Return 400 with a descriptive message on first failure (fail-fast).
 *
 * None of this uses eval / regex catastrophes; all checks are O(1) or O(n)
 * where n is the string length.
 */

const validator = require('validator');

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Strip HTML tags and control characters from a string.
 * Does NOT use DOMParser (server has no DOM); uses a simple regex
 * sufficient for preventing stored-XSS in text fields.
 */
const sanitizeStr = (val) =>
  typeof val === 'string'
    ? val.replace(/<[^>]*>/g, '').replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim()
    : val;

/** Return a 400 response and halt the middleware chain. */
const fail = (res, message) => res.status(400).json({ success: false, error: message });

/** Validate that a route param is a positive integer. */
const validateId = (req, res, next) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id <= 0 || String(id) !== req.params.id) {
    return fail(res, 'Invalid ID — must be a positive integer.');
  }
  req.params.id = id; // coerce to number so route handlers don't need to parseInt
  next();
};

// ── Allowed INDUSTRY_TYPES enum ───────────────────────────────────────────────
const INDUSTRY_TYPES = new Set([
  'steel', 'cement', 'chemical', 'manufacturing', 'energy', 'textile', 'construction', 'other'
]);

// ── Allowed STATUS values per resource ───────────────────────────────────────
const WASTE_STATUSES    = new Set(['available', 'reserved', 'expired']);
const RESOURCE_STATUSES = new Set(['active', 'fulfilled', 'cancelled']);
const UNITS             = new Set(['tons', 'kg', 'mwh', 'liters', 'cubic meters', 'units']);
const REPORT_PERIODS    = new Set(['weekly', 'monthly', 'yearly']);

// ── Schema definitions ────────────────────────────────────────────────────────

/**
 * validateRegister
 * Allowed fields: companyName, industryType, email, phone, location, password
 * Rejects any extra fields to prevent mass-assignment.
 */
const validateRegister = (req, res, next) => {
  // OWASP A03: whitelist — strip unexpected fields
  const ALLOWED = new Set(['companyName','industryType','email','phone','location','password']);
  Object.keys(req.body).forEach(k => { if (!ALLOWED.has(k)) delete req.body[k]; });

  const { companyName, industryType, email, phone, location, password } = req.body;

  // Required fields
  if (!companyName || typeof companyName !== 'string')
    return fail(res, 'companyName is required and must be a string.');
  if (!email || typeof email !== 'string')
    return fail(res, 'email is required and must be a string.');
  if (!password || typeof password !== 'string')
    return fail(res, 'password is required and must be a string.');

  // Length limits (prevent bcrypt DoS: passwords > 72 chars are silently
  // truncated by bcrypt — an attacker could supply 1MB strings)
  if (companyName.length  < 2  || companyName.length  > 120)
    return fail(res, 'companyName must be 2–120 characters.');
  if (password.length     < 8  || password.length     > 72)
    return fail(res, 'password must be 8–72 characters.');
  if (location && location.length > 200)
    return fail(res, 'location must be ≤ 200 characters.');
  if (phone && phone.length > 20)
    return fail(res, 'phone must be ≤ 20 characters.');

  // Email format
  if (!validator.isEmail(email))
    return fail(res, 'email format is invalid.');
  if (email.length > 254)
    return fail(res, 'email must be ≤ 254 characters (RFC 5321).');

  // Industry type enum
  if (industryType && !INDUSTRY_TYPES.has(industryType.toLowerCase()))
    return fail(res, `industryType must be one of: ${[...INDUSTRY_TYPES].join(', ')}.`);

  // Sanitise free-text fields (XSS prevention)
  req.body.companyName  = sanitizeStr(companyName);
  req.body.email        = validator.normalizeEmail(email) || email.toLowerCase().trim();
  req.body.location     = sanitizeStr(location);
  req.body.phone        = sanitizeStr(phone);
  req.body.industryType = industryType ? industryType.toLowerCase().trim() : undefined;

  next();
};

/**
 * validateLogin
 * Only email + password; reject everything else.
 */
const validateLogin = (req, res, next) => {
  const ALLOWED = new Set(['email', 'password']);
  Object.keys(req.body).forEach(k => { if (!ALLOWED.has(k)) delete req.body[k]; });

  const { email, password } = req.body;

  if (!email    || typeof email    !== 'string') return fail(res, 'email is required.');
  if (!password || typeof password !== 'string') return fail(res, 'password is required.');
  if (!validator.isEmail(email))                 return fail(res, 'email format is invalid.');
  if (email.length > 254)                        return fail(res, 'email too long.');
  // Limit password length to 72 chars before hitting bcrypt
  if (password.length > 72)                      return fail(res, 'password too long.');

  req.body.email = validator.normalizeEmail(email) || email.toLowerCase().trim();
  next();
};

/**
 * validateProfileUpdate
 * All fields optional but each must pass its constraint if present.
 */
const validateProfileUpdate = (req, res, next) => {
  const ALLOWED = new Set(['companyName','industryType','phone','location','transportRadius','website']);
  Object.keys(req.body).forEach(k => { if (!ALLOWED.has(k)) delete req.body[k]; });

  const { companyName, industryType, phone, location, transportRadius, website } = req.body;

  if (companyName !== undefined) {
    if (typeof companyName !== 'string' || companyName.length < 2 || companyName.length > 120)
      return fail(res, 'companyName must be 2–120 characters.');
    req.body.companyName = sanitizeStr(companyName);
  }
  if (industryType !== undefined) {
    if (!INDUSTRY_TYPES.has(industryType.toLowerCase()))
      return fail(res, `industryType must be one of: ${[...INDUSTRY_TYPES].join(', ')}.`);
    req.body.industryType = industryType.toLowerCase().trim();
  }
  if (phone !== undefined) {
    if (typeof phone !== 'string' || phone.length > 20)
      return fail(res, 'phone must be ≤ 20 characters.');
    req.body.phone = sanitizeStr(phone);
  }
  if (location !== undefined) {
    if (typeof location !== 'string' || location.length > 200)
      return fail(res, 'location must be ≤ 200 characters.');
    req.body.location = sanitizeStr(location);
  }
  if (transportRadius !== undefined) {
    const r = Number(transportRadius);
    if (isNaN(r) || r < 0 || r > 5000)
      return fail(res, 'transportRadius must be a number between 0 and 5000 km.');
    req.body.transportRadius = r;
  }
  if (website !== undefined && website !== '') {
    if (!validator.isURL(website, { require_protocol: true, protocols: ['http','https'] }))
      return fail(res, 'website must be a valid http/https URL.');
    if (website.length > 300)
      return fail(res, 'website URL must be ≤ 300 characters.');
    req.body.website = sanitizeStr(website);
  }

  next();
};

/**
 * validateWasteListing
 * Required: materialType, quantity, unit
 */
const validateWasteListing = (req, res, next) => {
  const ALLOWED = new Set(['materialType','description','quantity','unit','location','availableFrom']);
  Object.keys(req.body).forEach(k => { if (!ALLOWED.has(k)) delete req.body[k]; });

  const { materialType, description, quantity, unit, location, availableFrom } = req.body;

  if (!materialType || typeof materialType !== 'string')
    return fail(res, 'materialType is required.');
  if (materialType.length > 100)
    return fail(res, 'materialType must be ≤ 100 characters.');

  if (quantity === undefined || quantity === null)
    return fail(res, 'quantity is required.');
  const qty = Number(quantity);
  if (isNaN(qty) || qty <= 0 || qty > 10_000_000)
    return fail(res, 'quantity must be a positive number ≤ 10,000,000.');

  if (!unit || typeof unit !== 'string')
    return fail(res, 'unit is required.');
  if (!UNITS.has(unit.toLowerCase()))
    return fail(res, `unit must be one of: ${[...UNITS].join(', ')}.`);

  if (description && (typeof description !== 'string' || description.length > 1000))
    return fail(res, 'description must be ≤ 1000 characters.');
  if (location && (typeof location !== 'string' || location.length > 200))
    return fail(res, 'location must be ≤ 200 characters.');
  if (availableFrom && !validator.isDate(availableFrom))
    return fail(res, 'availableFrom must be a valid date (YYYY-MM-DD).');

  // Sanitise and coerce
  req.body.materialType  = sanitizeStr(materialType);
  req.body.description   = sanitizeStr(description);
  req.body.location      = sanitizeStr(location);
  req.body.unit          = unit.toLowerCase().trim();
  req.body.quantity      = qty;

  next();
};

/**
 * validateWasteUpdate
 * Same constraints but all fields optional (PATCH semantics via PUT).
 */
const validateWasteUpdate = (req, res, next) => {
  const ALLOWED = new Set(['materialType','description','quantity','unit','location','availableFrom','status']);
  Object.keys(req.body).forEach(k => { if (!ALLOWED.has(k)) delete req.body[k]; });

  const { materialType, quantity, unit, description, location, availableFrom, status } = req.body;

  if (materialType !== undefined) {
    if (typeof materialType !== 'string' || materialType.length > 100)
      return fail(res, 'materialType must be ≤ 100 characters.');
    req.body.materialType = sanitizeStr(materialType);
  }
  if (quantity !== undefined) {
    const qty = Number(quantity);
    if (isNaN(qty) || qty <= 0 || qty > 10_000_000)
      return fail(res, 'quantity must be a positive number ≤ 10,000,000.');
    req.body.quantity = qty;
  }
  if (unit !== undefined) {
    if (!UNITS.has(unit.toLowerCase()))
      return fail(res, `unit must be one of: ${[...UNITS].join(', ')}.`);
    req.body.unit = unit.toLowerCase().trim();
  }
  if (status !== undefined && !WASTE_STATUSES.has(status.toLowerCase()))
    return fail(res, `status must be one of: ${[...WASTE_STATUSES].join(', ')}.`);
  if (description !== undefined)
    req.body.description = sanitizeStr(description);
  if (location !== undefined)
    req.body.location = sanitizeStr(location);
  if (availableFrom && !validator.isDate(availableFrom))
    return fail(res, 'availableFrom must be a valid date (YYYY-MM-DD).');

  next();
};

/**
 * validateResourceRequest
 */
const validateResourceRequest = (req, res, next) => {
  const ALLOWED = new Set(['materialNeeded','description','quantity','unit','industrySector','location','requiredBy']);
  Object.keys(req.body).forEach(k => { if (!ALLOWED.has(k)) delete req.body[k]; });

  const { materialNeeded, quantity, unit, description, industrySector, location, requiredBy } = req.body;

  if (!materialNeeded || typeof materialNeeded !== 'string')
    return fail(res, 'materialNeeded is required.');
  if (materialNeeded.length > 100)
    return fail(res, 'materialNeeded must be ≤ 100 characters.');

  if (quantity === undefined || quantity === null)
    return fail(res, 'quantity is required.');
  const qty = Number(quantity);
  if (isNaN(qty) || qty <= 0 || qty > 10_000_000)
    return fail(res, 'quantity must be a positive number ≤ 10,000,000.');

  if (!unit || typeof unit !== 'string')
    return fail(res, 'unit is required.');
  if (!UNITS.has(unit.toLowerCase()))
    return fail(res, `unit must be one of: ${[...UNITS].join(', ')}.`);

  if (description && description.length > 1000)
    return fail(res, 'description must be ≤ 1000 characters.');
  if (industrySector && industrySector.length > 100)
    return fail(res, 'industrySector must be ≤ 100 characters.');
  if (location && location.length > 200)
    return fail(res, 'location must be ≤ 200 characters.');
  if (requiredBy && !validator.isDate(requiredBy))
    return fail(res, 'requiredBy must be a valid date (YYYY-MM-DD).');

  req.body.materialNeeded  = sanitizeStr(materialNeeded);
  req.body.description     = sanitizeStr(description);
  req.body.industrySector  = sanitizeStr(industrySector);
  req.body.location        = sanitizeStr(location);
  req.body.unit            = unit.toLowerCase().trim();
  req.body.quantity        = qty;

  next();
};

/**
 * validateResourceUpdate
 */
const validateResourceUpdate = (req, res, next) => {
  const ALLOWED = new Set(['materialNeeded','description','quantity','unit','industrySector','location','requiredBy','status']);
  Object.keys(req.body).forEach(k => { if (!ALLOWED.has(k)) delete req.body[k]; });

  const { materialNeeded, quantity, unit, status } = req.body;

  if (materialNeeded !== undefined && materialNeeded.length > 100)
    return fail(res, 'materialNeeded must be ≤ 100 characters.');
  if (quantity !== undefined) {
    const qty = Number(quantity);
    if (isNaN(qty) || qty <= 0 || qty > 10_000_000)
      return fail(res, 'quantity must be a positive number ≤ 10,000,000.');
    req.body.quantity = qty;
  }
  if (unit !== undefined && !UNITS.has(unit.toLowerCase()))
    return fail(res, `unit must be one of: ${[...UNITS].join(', ')}.`);
  if (status !== undefined && !RESOURCE_STATUSES.has(status.toLowerCase()))
    return fail(res, `status must be one of: ${[...RESOURCE_STATUSES].join(', ')}.`);

  if (req.body.materialNeeded) req.body.materialNeeded = sanitizeStr(req.body.materialNeeded);
  if (req.body.description)    req.body.description    = sanitizeStr(req.body.description);
  if (req.body.location)       req.body.location       = sanitizeStr(req.body.location);
  if (unit)                    req.body.unit            = unit.toLowerCase().trim();

  next();
};

/**
 * validateQueryPagination
 * Enforces sane limit/offset on any GET list endpoint.
 * Max limit = 100, default = 50. Prevents "SELECT * LIMIT 9999999".
 */
const validateQueryPagination = (req, _res, next) => {
  let limit  = parseInt(req.query.limit,  10);
  let offset = parseInt(req.query.offset, 10);

  if (isNaN(limit)  || limit  < 1)   limit  = 50;
  if (isNaN(offset) || offset < 0)   offset = 0;
  if (limit > 100)                   limit  = 100; // hard cap

  req.query.limit  = limit;
  req.query.offset = offset;
  next();
};

/**
 * validateReportPeriod
 * Ensures the `period` query param is one of the safe whitelist values
 * BEFORE it is interpolated into a SQL string in impact.js.
 */
const validateReportPeriod = (req, res, next) => {
  const period = req.query.period || 'monthly';
  if (!REPORT_PERIODS.has(period))
    return fail(res, `period must be one of: ${[...REPORT_PERIODS].join(', ')}.`);
  req.query.period = period;
  next();
};

/**
 * validateImpactCalculation
 */
const validateImpactCalculation = (req, res, next) => {
  const ALLOWED = new Set(['wasteTons', 'materialType']);
  Object.keys(req.body).forEach(k => { if (!ALLOWED.has(k)) delete req.body[k]; });

  const { wasteTons, materialType } = req.body;

  if (wasteTons === undefined)
    return fail(res, 'wasteTons is required.');
  const qty = Number(wasteTons);
  if (isNaN(qty) || qty <= 0 || qty > 10_000_000)
    return fail(res, 'wasteTons must be a positive number ≤ 10,000,000.');

  if (materialType !== undefined && typeof materialType !== 'string')
    return fail(res, 'materialType must be a string.');
  if (materialType && materialType.length > 100)
    return fail(res, 'materialType must be ≤ 100 characters.');

  req.body.wasteTons    = qty;
  req.body.materialType = sanitizeStr(materialType || '');
  next();
};

module.exports = {
  validateId,
  validateRegister,
  validateLogin,
  validateProfileUpdate,
  validateWasteListing,
  validateWasteUpdate,
  validateResourceRequest,
  validateResourceUpdate,
  validateQueryPagination,
  validateReportPeriod,
  validateImpactCalculation,
};
