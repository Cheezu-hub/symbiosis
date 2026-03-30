# SymbioTech AI Engine

Two FastAPI services — run ONE of them (they share the same port 8000).

## Install (run once)
```
pip install -r requirements.txt
```

## Run the matching engine
```
uvicorn matching:app --host 0.0.0.0 --port 8000 --reload
```

## Run the impact calculator
```
uvicorn impact:app --host 0.0.0.0 --port 8001 --reload
```

## Test it works
Open browser: http://localhost:8000/api/health

## API Endpoints

### matching.py
- GET  /api/health
- POST /api/match          — send waste + request lists, get ranked matches
- GET  /api/impact/calculate?waste_tons=100&material_type=fly+ash

### impact.py
- GET  /api/health
- GET  /api/impact/calculate?waste_tons=100&material_type=fly_ash
- GET  /api/impact/sustainability-score?waste_diverted=500&co2_reduced=200&matches_completed=5
