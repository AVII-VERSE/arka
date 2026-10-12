"""
ARKA FastAPI Application Entrypoint.
Advanced Real-time Kinetic Analytics.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import AsyncSessionLocal, Base, engine
from app.core.exceptions import ARKAException
from app.core.logging import logger, setup_logging
from app.core.security import get_password_hash
from app.models.models import (
    DetectionRule,
    RoleEnum,
    SeverityEnum,
    Tenant,
    User,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application Lifespan Context Manager."""
    setup_logging()
    logger.info("Initializing ARKA Backend Service...", env=settings.ARKA_ENV, version=settings.VERSION)

    # Auto-create tables for local development / test engine
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database schema validated successfully.")

        # Seed initial tenant and default admin users if not present
        async with AsyncSessionLocal() as session:
            t_res = await session.execute(select(Tenant).where(Tenant.id == "default-tenant"))
            tenant = t_res.scalar_one_or_none()
            if not tenant:
                tenant = Tenant(
                    id="default-tenant",
                    name="ARKA SOC Primary",
                    slug="arka-soc",
                    is_active=True,
                )
                session.add(tenant)
                await session.flush()
                logger.info("Seeded default tenant: ARKA SOC Primary")

            u_res = await session.execute(select(User).where(User.email == "admin@arka-siem.org"))
            admin_user = u_res.scalar_one_or_none()
            if not admin_user:
                admin_user = User(
                    id="admin-user-01",
                    tenant_id="default-tenant",
                    email="admin@arka-siem.org",
                    hashed_password=get_password_hash("admin123"),
                    full_name="Lead SOC Analyst",
                    role=RoleEnum.SUPER_ADMIN,
                    is_active=True,
                )
                session.add(admin_user)
                logger.info("Seeded default admin user: admin@arka-siem.org")

            # Seed default detection rules if none exist
            dr_res = await session.execute(select(DetectionRule).limit(1))
            if not dr_res.scalar_one_or_none():
                default_rules = [
                    DetectionRule(
                        id="rule-001",
                        tenant_id="default-tenant",
                        rule_code="ARKA-RULE-001",
                        name="Multiple Failed Authentication Attempts (Brute Force)",
                        description="Detects repeated logon failures exceeding threshold from single source within short window.",
                        severity=SeverityEnum.HIGH,
                        enabled=True,
                        mitre_tactic="Credential Access",
                        mitre_technique_id="T1110",
                        mitre_technique_name="Brute Force",
                        conditions={"event_type": "authentication", "action": "logon_failed"},
                        threshold={"count": 5, "timeframe_seconds": 60},
                    ),
                    DetectionRule(
                        id="rule-002",
                        tenant_id="default-tenant",
                        rule_code="ARKA-RULE-002",
                        name="Suspicious Encoded PowerShell Execution",
                        description="Detects PowerShell launched with -EncodedCommand or obfuscation flags.",
                        severity=SeverityEnum.CRITICAL,
                        enabled=True,
                        mitre_tactic="Execution",
                        mitre_technique_id="T1059.001",
                        mitre_technique_name="PowerShell",
                        conditions={"process": "powershell.exe", "flags": ["-enc", "-encodedcommand"]},
                        threshold={"count": 1, "timeframe_seconds": 10},
                    ),
                    DetectionRule(
                        id="rule-003",
                        tenant_id="default-tenant",
                        rule_code="ARKA-RULE-003",
                        name="Critical System File Integrity Breach (FIM)",
                        description="Detects unauthorized modification or deletion of protected system binaries or configurations.",
                        severity=SeverityEnum.HIGH,
                        enabled=True,
                        mitre_tactic="Defense Evasion",
                        mitre_technique_id="T1070",
                        mitre_technique_name="Indicator Removal on Host",
                        conditions={"event_type": "fim", "action": "file_modified"},
                        threshold={"count": 1, "timeframe_seconds": 5},
                    ),
                    DetectionRule(
                        id="rule-004",
                        tenant_id="default-tenant",
                        rule_code="ARKA-RULE-004",
                        name="Outbound Connection to Known Malicious C2 IP",
                        description="Identifies outbound network connection directed towards high-threat indicator or malicious C2.",
                        severity=SeverityEnum.CRITICAL,
                        enabled=True,
                        mitre_tactic="Command and Control",
                        mitre_technique_id="T1071",
                        mitre_technique_name="Application Layer Protocol",
                        conditions={"event_type": "network", "direction": "outbound"},
                        threshold={"count": 1, "timeframe_seconds": 1},
                    ),
                ]
                for r in default_rules:
                    session.add(r)
                logger.info("Seeded %d standard detection rules.", len(default_rules))

            await session.commit()
    except Exception as e:
        logger.warning("Database schema auto-creation or seed deferred", error=str(e))

    yield

    logger.info("Shutting down ARKA Backend Service...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Advanced Real-time Kinetic Analytics (ARKA) SIEM Core Platform API",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ARKAException)
async def arka_exception_handler(request: Request, exc: ARKAException) -> JSONResponse:
    """Custom exception handler for ARKA domain exceptions."""
    logger.warning("ARKA Domain Exception", error_code=exc.error_code, detail=exc.detail, path=request.url.path)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error_code": exc.error_code,
            "detail": exc.detail,
            "extra": exc.extra,
        },
    )


# Register API V1 Router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", include_in_schema=False)
async def root() -> dict:
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": f"{settings.API_V1_STR}/docs",
    }
