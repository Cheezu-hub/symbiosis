from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import re

app = FastAPI(title="SymbioTech AI Matching Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Models ────────────────────────────────────────────────────────────────────
class WasteMaterial(BaseModel):
    id: Optional[int] = None
    material_type: str
    description: Optional[str] = ""
    quantity: float
    unit: str
    location: Optional[str] = ""

class ResourceRequest(BaseModel):
    id: Optional[int] = None
    material_needed: str
    quantity: float
    unit: str
    industry_sector: Optional[str] = ""
    location: Optional[str] = ""

class MatchRequest(BaseModel):
    wastes: List[WasteMaterial]
    requests: List[ResourceRequest]

# ── CO2 / cost factors ────────────────────────────────────────────────────────
CO2_FACTORS = {
    "fly ash": 0.5, "fly_ash": 0.5,
    "steel slag": 0.4, "steel_slag": 0.4,
    "blast furnace slag": 0.7,
    "waste heat": 0.8, "waste_heat": 0.8,
    "chemical byproduct": 0.6, "chemical_byproduct": 0.6,
    "scrap metal": 1.5,
    "plastic waste": 2.0,
    "paper waste": 0.9,
    "textile waste": 1.1, "textile_waste": 0.3,
    "glass waste": 0.3,
    "rubber waste": 1.8,
    "wood waste": 0.4,
}

COST_PER_TON = {
    "fly ash": 1500, "fly_ash": 1500,
    "steel slag": 2000, "steel_slag": 2000,
    "waste heat": 5000, "waste_heat": 5000,
    "scrap metal": 8000,
    "chemical byproduct": 3000,
}

WATER_FACTORS = {
    "fly ash": 500, "fly_ash": 500,
    "steel slag": 300, "steel_slag": 300,
    "chemical byproduct": 800, "chemical_byproduct": 800,
}

ENERGY_FACTORS = {
    "fly ash": 0.8, "fly_ash": 0.8,
    "steel slag": 0.5, "steel_slag": 0.5,
    "waste heat": 1.2, "waste_heat": 1.2,
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def normalize(text: str) -> str:
    return re.sub(r'\s+', ' ', (text or "").lower().strip())

def tokenize(text: str):
    return set(re.split(r'[\s,_\-]+', normalize(text)))

def material_similarity(a: str, b: str) -> float:
    """Returns 0.0 – 1.0 similarity between two material names."""
    na, nb = normalize(a), normalize(b)
    if na == nb:
        return 1.0
    if na in nb or nb in na:
        return 0.75
    ta, tb = tokenize(a), tokenize(b)
    meaningful_a = {w for w in ta if len(w) > 2}
    meaningful_b = {w for w in tb if len(w) > 2}
    if not meaningful_a or not meaningful_b:
        return 0.0
    overlap = meaningful_a & meaningful_b
    return len(overlap) / max(len(meaningful_a), len(meaningful_b))

def location_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.5   # unknown → neutral
    na, nb = normalize(a), normalize(b)
    if na == nb:
        return 1.0
    wa = set(re.split(r'[\s,]+', na))
    wb = set(re.split(r'[\s,]+', nb))
    meaningful = {w for w in wa | wb if len(w) > 2}
    overlap = {w for w in wa if w in wb and len(w) > 2}
    if not meaningful:
        return 0.5
    return len(overlap) / len(meaningful)

def calculate_match_score(waste: WasteMaterial, req: ResourceRequest) -> int:
    # Material match  — 50 pts
    mat_sim = material_similarity(waste.material_type, req.material_needed)
    score   = mat_sim * 50

    # Quantity ratio  — 20 pts
    if waste.quantity > 0 and req.quantity > 0:
        ratio  = min(waste.quantity, req.quantity) / max(waste.quantity, req.quantity)
        score += ratio * 20

    # Unit match      — 10 pts
    if normalize(waste.unit) == normalize(req.unit):
        score += 10

    # Location        — 20 pts
    score += location_similarity(waste.location, req.location) * 20

    return min(100, round(score))

def get_impact(material_type: str, quantity: float) -> dict:
    key = normalize(material_type)
    co2    = quantity * CO2_FACTORS.get(key, 0.35)
    water  = quantity * WATER_FACTORS.get(key, 400)
    energy = quantity * ENERGY_FACTORS.get(key, 0.6)
    cost   = quantity * COST_PER_TON.get(key, 1800)
    return {
        "co2_reduced_tons":       round(co2,    2),
        "landfill_diverted_tons": round(quantity, 2),
        "raw_material_saved_tons":round(quantity * 0.8, 2),
        "water_saved_liters":     round(water,  2),
        "energy_saved_mwh":       round(energy, 2),
        "cost_savings_estimate":  round(cost,   2),
    }

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
@app.get("/api/health")
def health():
    return {"status": "OK", "service": "SymbioTech AI Engine", "port": 8000}

@app.post("/api/match")
def match_waste_resources(body: MatchRequest):
    """Match waste materials with resource requests and return ranked results."""
    results = []

    for waste in body.wastes:
        for req in body.requests:
            score = calculate_match_score(waste, req)
            if score >= 30:
                matched_qty = min(waste.quantity, req.quantity)
                impact      = get_impact(waste.material_type, matched_qty)
                results.append({
                    "waste_material":    waste.material_type,
                    "resource_needed":   req.material_needed,
                    "waste_id":          waste.id,
                    "request_id":        req.id,
                    "match_score":       score,
                    "quantity_available":waste.quantity,
                    "quantity_needed":   req.quantity,
                    "unit":              waste.unit,
                    **impact,
                })

    results.sort(key=lambda x: x["match_score"], reverse=True)
    return {"matches": results, "total": len(results)}

@app.get("/api/match")
def match_by_industry(industry_id: int = Query(..., description="Industry ID to find matches for")):
    """Stub for GET-based matching — returns empty list (real matching via POST)."""
    return {"matches": [], "message": "Use POST /api/match with waste and request lists"}

@app.get("/api/impact/calculate")
def calculate_impact_get(
    waste_tons:    float = Query(..., description="Waste quantity in tons"),
    material_type: str   = Query(..., description="Type of waste material"),
):
    return get_impact(material_type, waste_tons)

@app.post("/api/impact/calculate")
def calculate_impact_post(waste_tons: float, material_type: str):
    return get_impact(material_type, waste_tons)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
