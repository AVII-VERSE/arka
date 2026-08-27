"""
V1 API Router Assembly.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    active_response,
    agents,
    alerts,
    auth,
    cloud_container,
    command_audit,
    dashboard,
    events,
    health,
    incidents,
    inventory,
    rules,
    sca,
    vulnerabilities,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health Checks"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication & Tenants"])
api_router.include_router(events.router, prefix="/events", tags=["Events & Ingestion"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alert Management"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incident Management"])
api_router.include_router(agents.router, prefix="/agents", tags=["Agent Management"])
api_router.include_router(inventory.router, prefix="/inventory", tags=["System Inventory"])
api_router.include_router(sca.router, prefix="/sca", tags=["Security Configuration Assessment"])
api_router.include_router(
    active_response.router, prefix="/active_response", tags=["Automated Active Response"]
)
api_router.include_router(
    vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerability Detection"]
)
api_router.include_router(
    command_audit.router, prefix="/command_audit", tags=["Command & Syscall Audit"]
)
api_router.include_router(
    cloud_container.router, prefix="/cloud_container", tags=["Container & Cloud Security"]
)
api_router.include_router(rules.router, prefix="/rules", tags=["Detection Rules"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["SOC Dashboard"])
