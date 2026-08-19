"""
Health Check Endpoints (/healthz, /readyz, /livez).
"""

from datetime import UTC, datetime

from fastapi import APIRouter

from app.core.config import settings
from app.schemas.schemas import HealthResponse

router = APIRouter()


@router.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    """Basic service health status."""
    return HealthResponse(
        status="ok",
        version=settings.VERSION,
        environment=settings.ARKA_ENV,
        timestamp=datetime.now(UTC),
    )


@router.get("/readyz", response_model=HealthResponse)
async def readyz() -> HealthResponse:
    """Readiness probe for Kubernetes / Load Balancer."""
    return HealthResponse(
        status="ready",
        version=settings.VERSION,
        environment=settings.ARKA_ENV,
        timestamp=datetime.now(UTC),
    )


@router.get("/livez", response_model=HealthResponse)
async def livez() -> HealthResponse:
    """Liveness probe."""
    return HealthResponse(
        status="live",
        version=settings.VERSION,
        environment=settings.ARKA_ENV,
        timestamp=datetime.now(UTC),
    )
