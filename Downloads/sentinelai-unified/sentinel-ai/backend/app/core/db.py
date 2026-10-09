"""
Database engine + session management.

Design decision: async SQLAlchemy 2.0 style throughout, since the whole
platform is built on async I/O (FastAPI + eventual Celery/async workers).
A single `get_db` dependency yields one session per request and always
closes it, even on exceptions.
"""
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG, future=True)
AsyncSessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
