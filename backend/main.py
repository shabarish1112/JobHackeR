"""FastAPI application entry point.

The API and the single-page frontend intentionally share one origin/port so
local desktop and same-Wi-Fi mobile testing use exactly one website address.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api.routes import router as api_router

ROOT_DIR = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT_DIR / "frontend"


def _cors_origins() -> list[str]:
    configured = os.getenv("JOBHACKER_CORS_ORIGINS", "").strip()
    if not configured:
        # Same-origin is the default. CORS remains available for an explicit
        # external integration without forcing a permissive wildcard policy.
        return []
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


app = FastAPI(
    title="Job Hacker Intelligence API",
    version="2.2.0",
    description="Explainable recruitment-scam inspection with public RDAP/TLS intelligence and optional reputation APIs.",
)

origins = _cors_origins()
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add low-cost browser security headers to every response."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    return response


app.include_router(api_router)


@app.get("/health", tags=["system"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "version": app.version}


@app.get("/", include_in_schema=False)
async def frontend_root():
    return FileResponse(FRONTEND_DIR / "index.html")


# Static assets are served by the same FastAPI process and therefore the same
# host/port as the API. This is the key to the single-site experience.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
