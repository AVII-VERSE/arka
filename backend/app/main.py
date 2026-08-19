"""
ARKA FastAPI Application Entrypoint.
Advanced Real-time Kinetic Analytics.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import Base, engine
from app.core.exceptions import ARKAException
from app.core.logging import logger, setup_logging


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
    except Exception as e:
        logger.warning("Database schema auto-creation deferred or failed", error=str(e))

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
