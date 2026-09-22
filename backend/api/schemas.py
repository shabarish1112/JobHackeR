"""Typed API request/response contracts."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator


class InspectionRequest(BaseModel):
    offer_text: str | None = Field(None, max_length=100_000)
    company_url: HttpUrl | None = None
    company_name: str | None = Field(None, max_length=200)
    document_text: str | None = Field(None, max_length=100_000)

    @field_validator("offer_text", "company_name", "document_text")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class InspectionResponse(BaseModel):
    threat_score: float = Field(..., ge=0, le=100)
    risk_level: Literal["low", "medium", "high"]
    red_flags: list[str] = Field(default_factory=list)
    actionable_recommendations: list[str] = Field(default_factory=list)
    score_signals: list[dict[str, Any]] = Field(default_factory=list)
    intelligence: dict[str, Any] = Field(default_factory=dict)
    reporting: list[dict[str, Any]] = Field(default_factory=list)
    company_search_results: list[dict[str, Any]] = Field(default_factory=list)
    document: dict[str, Any] | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
