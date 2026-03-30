# SymbioTech — Industrial Symbiosis Platform

## Project Structure
```
ism_fixed/
├── backend/          # Node.js + Express API (SQLite)
├── forntend/         # React frontend
├── ai-engine/        # Python AI matching engine (optional)
└── database/         # schema.sql (reference only — auto-created)
```

---

## Quick Start (2 terminals, no database setup needed)

### Terminal 1 — Backend
```bash
cd backend

# Copy env file (edit JWT_SECRET if you want)
cp .env.example .env

# Install dependencies
npm install

# Start — SQLite database is created automatically on first run
npm run dev
```

You'll see:
```
✅ Database ready: /path/to/symbiotech.db
🚀 SymbioTech API (SQLite) Started — Port: 5000
```

Test it works:
```
http://localhost:5000/api/health
```

### Terminal 2 — Frontend
```bash
cd forntend

npm install
npm start
```

Opens at **http://localhost:3000**

That's it — no PostgreSQL, no setup, no config files to edit.

---

## What Changed (PostgreSQL → SQLite)

| Before | After |
|--------|-------|
| PostgreSQL server must be installed & running | Single `.db` file, zero install |
| `pg` npm package | `better-sqlite3` npm package |
| `$1, $2` query placeholders | `?` placeholders |
| `ILIKE` | `LOWER(field) LIKE LOWER(?)` |
| `RETURNING *` | `run()` → `lastInsertRowid` → `get()` |
| `pool.connect()` transactions | `db.transaction(() => { ... })()` |
| `DATE_TRUNC('month', ...)` | `strftime('%Y-%m', ...)` |
| Must run `schema.sql` manually | Tables auto-created on startup |
| `.env` needs DB_HOST, DB_PORT, DB_USER, DB_PASSWORD | Only JWT_SECRET needed |

---

## Environment Variables

### backend/.env
```env
PORT=5000
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
JWT_SECRET=change_this_to_a_long_random_string
# DB_PATH=./symbiotech.db   ← optional, this is the default
```

### forntend/.env (optional)
```env
REACT_APP_API_URL=http://localhost:5000/api
```
