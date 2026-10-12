"""
SQLAlchemy 2.x Async Database Session Engine with automatic high-resilience fallback.
"""

from collections.abc import AsyncGenerator
import socket
import logging

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

logger = logging.getLogger("arka.database")


def is_postgres_available(host: str, port: int) -> bool:
    """Non-blocking socket check to verify if PostgreSQL port is actively accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=0.8):
            return True
    except (OSError, TimeoutError):
        return False


# Determine database connection URL
db_url = settings.DATABASE_URL
engine_kwargs = {"echo": False, "future": True}

if db_url.startswith("postgresql"):
    if is_postgres_available(settings.POSTGRES_SERVER, settings.POSTGRES_PORT):
        logger.info("Connecting to PostgreSQL at %s:%s", settings.POSTGRES_SERVER, settings.POSTGRES_PORT)
        engine_kwargs["pool_pre_ping"] = True
        engine_kwargs["pool_size"] = 10
        engine_kwargs["max_overflow"] = 20
    else:
        logger.warning(
            "PostgreSQL is offline at %s:%s. Automatically switching to high-performance local SQLite storage (arka_local.db).",
            settings.POSTGRES_SERVER,
            settings.POSTGRES_PORT,
        )
        db_url = "sqlite+aiosqlite:///./arka_local.db"
        engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    if "sqlite" in db_url:
        engine_kwargs["connect_args"] = {"check_same_thread": False}

# Create Async Engine
engine = create_async_engine(db_url, **engine_kwargs)

# Async Session Factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy models."""

    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
