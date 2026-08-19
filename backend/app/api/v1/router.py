"""
V1 API Router Assembly.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    agents,
    alerts,
    auth,
    dashboard,
    events,
    health,
    incidents,
    rules,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health Checks"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication & Tenants"])
api_router.include_router(events.router, prefix="/events", tags=["Events & Ingestion"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alert Management"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incident Management"])
api_router.include_router(agents.router, prefix="/agents", tags=["Agent Management"])
api_router.include_router(rules.router, prefix="/rules", tags=["Detection Rules"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["SOC Dashboard"])
