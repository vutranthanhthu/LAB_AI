"""
Web Phishing Detection — FastAPI Backend
Run: uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
"""

from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.schemas import HealthResponse, PredictRequest, PredictResponse
from backend.model import PhishingModel

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Web Phishing Detection API",
    description="Detect phishing URLs using a trained machine-learning model.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Chrome extension / Streamlit dashboard
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model once at startup (fails gracefully — model_loaded = False)
_model = PhishingModel()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, summary="Health check")
async def health() -> HealthResponse:
    """Return service health and model status."""
    return HealthResponse(
        status="ok",
        model_loaded=_model.is_loaded,
        time=datetime.now(timezone.utc).isoformat(),
        thresholds=_model.thresholds,
    )


@app.post("/predict", response_model=PredictResponse, summary="Predict phishing URL")
async def predict(body: PredictRequest) -> PredictResponse:
    """
    Analyse a URL and return phishing probability + verdict.

    - **url**: The full URL to analyse (required).
    """
    if not body.url.strip():
        raise HTTPException(status_code=422, detail="URL must not be empty.")

    result = _model.predict(body.url.strip())
    return PredictResponse(**result)
