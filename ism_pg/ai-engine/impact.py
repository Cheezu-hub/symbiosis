from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="SymbioTech Impact Calculator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Factors ───────────────────────────────────────────────────────────────────
CO2_FACTORS = {
    "fly_ash": 0.5,    "fly ash": 0.5,
    "steel_slag": 0.4, "steel slag": 0.4,
    "blast furnace slag": 0.7,
    "waste_heat": 0.8, "waste heat": 0.8,
    "chemical_byproduct": 0.6, "chemical byproduct": 0.6,
    "scrap metal": 1.5,
    "plastic waste": 2.0,
    "paper waste": 0.9,
    "textile_waste": 0.3, "textile waste": 1.1,
    "glass waste": 0.3,
    "rubber waste": 1.8,
    "wood waste": 0.4,
    "default": 0.35
}

WATER_FACTORS = {
    "fly_ash": 500,    "fly ash": 500,
    "steel_slag": 300, "steel slag": 300,
    "chemical_byproduct": 800, "chemical byproduct": 800,
    "default": 400
}

ENERGY_FACTORS = {
    "fly_ash": 0.8,    "fly ash": 0.8,
    "steel_slag": 0.5, "steel slag": 0.5,
    "waste_heat": 1.2, "waste heat": 1.2,
    "default": 0.6
}

COST_PER_TON = {
    "fly_ash": 1500,    "fly ash": 1500,
    "steel_slag": 2000, "steel slag": 2000,
    "waste_heat": 5000, "waste heat": 5000,
    "scrap metal": 8000,
    "default": 1800
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_factor(factors: dict, material_key: str) -> float:
    return factors.get(material_key, factors["default"])

def get_rating(score: float) -> str:
    """Return a text rating based on sustainability score."""
    if score >= 80:
        return "Excellent"
    elif score >= 60:
        return "Good"
    elif score >= 40:
        return "Moderate"
    elif score >= 20:
        return "Developing"
    else:
        return "Getting Started"

# ── Models ────────────────────────────────────────────────────────────────────
class ImpactCalculation(BaseModel):
    co2_reduced_tons:       float
    landfill_diverted_tons: float
    raw_material_saved_tons:float
    water_saved_liters:     float
    energy_saved_mwh:       float
    cost_savings_estimate:  float

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
@app.get("/api/health")
def health():
    return {"status": "OK", "service": "SymbioTech Impact Calculator", "port": 8000}

@app.get("/api/impact/calculate", response_model=ImpactCalculation)
def calculate_impact(
    waste_tons:    float = Query(..., description="Waste quantity in tons"),
    material_type: str   = Query(..., description="Type of waste material"),
):
    """Calculate environmental impact of waste diversion."""
    key = material_type.lower().replace(" ", "_")

    co2_reduced         = waste_tons * get_factor(CO2_FACTORS,    key)
    water_saved         = waste_tons * get_factor(WATER_FACTORS,   key)
    energy_saved        = waste_tons * get_factor(ENERGY_FACTORS,  key)
    cost_savings        = waste_tons * get_factor(COST_PER_TON,    key)
    raw_material_saved  = waste_tons * 0.8

    return ImpactCalculation(
        co2_reduced_tons=       round(co2_reduced,        2),
        landfill_diverted_tons= round(waste_tons,         2),
        raw_material_saved_tons=round(raw_material_saved, 2),
        water_saved_liters=     round(water_saved,        2),
        energy_saved_mwh=       round(energy_saved,       2),
        cost_savings_estimate=  round(cost_savings,       2),
    )

@app.get("/api/impact/sustainability-score")
def calculate_sustainability_score(
    waste_diverted:     float = Query(0,  description="Total waste diverted in tons"),
    co2_reduced:        float = Query(0,  description="Total CO2 reduced in tons"),
    matches_completed:  int   = Query(0,  description="Number of completed matches"),
    months_active:      int   = Query(1,  description="Months on platform"),
):
    """Calculate sustainability score (0–100)."""
    waste_score         = min(25, waste_diverted / 10)
    carbon_score        = min(25, co2_reduced    / 5)
    collaboration_score = min(25, matches_completed * 2)
    consistency_score   = min(25, months_active     * 2)

    total_score = waste_score + carbon_score + collaboration_score + consistency_score

    return {
        "overall_score": round(total_score, 1),
        "breakdown": {
            "waste_diversion":  round(waste_score,         1),
            "carbon_reduction": round(carbon_score,        1),
            "collaboration":    round(collaboration_score, 1),
            "consistency":      round(consistency_score,   1),
        },
        "rating": get_rating(total_score),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
