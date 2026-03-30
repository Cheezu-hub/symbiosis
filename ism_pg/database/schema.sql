-- SymbioTech PostgreSQL Schema
-- Run with: psql -U postgres -d symbiotech -f schema.sql

CREATE TABLE IF NOT EXISTS industries (
  id                   SERIAL PRIMARY KEY,
  company_name         TEXT    NOT NULL,
  industry_type        TEXT,
  location             TEXT,
  contact_email        TEXT    NOT NULL UNIQUE,
  contact_phone        TEXT,
  password_hash        TEXT    NOT NULL,
  transport_radius_km  INTEGER DEFAULT 100,
  website              TEXT,
  sustainability_score INTEGER DEFAULT 50,
  created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS waste_listings (
  id             SERIAL PRIMARY KEY,
  industry_id    INTEGER NOT NULL REFERENCES industries(id) ON DELETE CASCADE,
  material_type  TEXT    NOT NULL,
  description    TEXT,
  quantity       NUMERIC NOT NULL,
  unit           TEXT    NOT NULL,
  location       TEXT,
  available_from DATE,
  status         TEXT    DEFAULT 'available',
  created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS resource_requests (
  id              SERIAL PRIMARY KEY,
  industry_id     INTEGER NOT NULL REFERENCES industries(id) ON DELETE CASCADE,
  material_needed TEXT    NOT NULL,
  description     TEXT,
  quantity        NUMERIC NOT NULL,
  unit            TEXT    NOT NULL,
  industry_sector TEXT,
  location        TEXT,
  required_by     DATE,
  status          TEXT    DEFAULT 'active',
  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS matches (
  id                  SERIAL PRIMARY KEY,
  waste_listing_id    INTEGER NOT NULL REFERENCES waste_listings(id)    ON DELETE CASCADE,
  resource_request_id INTEGER NOT NULL REFERENCES resource_requests(id) ON DELETE CASCADE,
  match_score         NUMERIC,
  status              TEXT    DEFAULT 'pending',
  co2_reduction_tons  NUMERIC DEFAULT 0,
  cost_savings        NUMERIC DEFAULT 0,
  logistics_cost      NUMERIC DEFAULT 0,
  logistics_details   TEXT,
  accepted_at         TIMESTAMP,
  created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS impact_metrics (
  id                      SERIAL PRIMARY KEY,
  industry_id             INTEGER NOT NULL REFERENCES industries(id) ON DELETE CASCADE,
  co2_reduced_tons        NUMERIC DEFAULT 0,
  waste_diverted_tons     NUMERIC DEFAULT 0,
  water_saved_liters      NUMERIC DEFAULT 0,
  energy_saved_mwh        NUMERIC DEFAULT 0,
  raw_material_saved_tons NUMERIC DEFAULT 0,
  recorded_date           DATE    DEFAULT CURRENT_DATE,
  UNIQUE (industry_id, recorded_date)
);
