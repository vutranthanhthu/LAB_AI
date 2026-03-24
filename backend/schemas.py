"""Pydantic models for request / response validation."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, field_validator


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    time: str
    thresholds: Dict[str, float]


class PredictRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        return v


class PredictResponse(BaseModel):
    url: str
    is_phishing: bool
    confidence: float          # probability of being phishing (0–1)
    verdict: str               # "phishing" | "safe" | "suspicious"
    features: Optional[Dict[str, Any]] = None
    model_version: str = "1.0.0"
