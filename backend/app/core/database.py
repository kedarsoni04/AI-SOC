"""
Database engine and session management.
Supports both PostgreSQL (asyncpg) and SQLite (aiosqlite) for local dev.
"""
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)

from app.core.config import settings


# ── Detect SQLite ─────────────────────────────────────────────────────────────
_is_sqlite = settings.database_url.startswith("sqlite")

# ── Engine ────────────────────────────────────────────────────────────────────
connect_args = {}
if _is_sqlite:
    connect_args = {"check_same_thread": False}

engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,
    connect_args=connect_args,
    pool_pre_ping=not _is_sqlite,  # SQLite doesn't support pool_pre_ping
)

# ── Session factory ───────────────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a DB session, auto-closes after request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    """Create all tables (dev only — use Alembic migrations in production)."""
    from app.models.models import Base as ModelsBase
    async with engine.begin() as conn:
        await conn.run_sync(ModelsBase.metadata.create_all)


async def drop_tables() -> None:
    """Drop all tables (test helper)."""
    from app.models.models import Base as ModelsBase
    async with engine.begin() as conn:
        await conn.run_sync(ModelsBase.metadata.drop_all)
