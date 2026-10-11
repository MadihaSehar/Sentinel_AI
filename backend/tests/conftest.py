"""
Shared pytest fixtures for the SentinelAI test suite.

Ensures `app` is importable regardless of where pytest is invoked from,
clears the prompt cache between tests so prompt-loading tests don't leak
state, and provides database + HTTP client fixtures for the API and
storage integration tests.

The integration fixtures run against an in-memory SQLite database (one
per test, fully isolated) so the suite needs no external Postgres/Redis.
Generic SQLAlchemy column types (`Uuid`, the custom `GUID` TypeDecorator)
keep the models portable between Postgres and SQLite.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401 — registers every model on Base.metadata
from app.ai.prompt_loader import load_prompt
from app.core.db import Base, get_db
from app.main import app


@pytest.fixture(autouse=True)
def _clear_prompt_cache():
    load_prompt.cache_clear()
    yield
    load_prompt.cache_clear()


# --------------------------------------------------------------------------- #
# Synchronous DB session (Response Intelligence storage tests)
# --------------------------------------------------------------------------- #
@pytest.fixture
def db_session():
    """A sync SQLAlchemy Session backed by a fresh in-memory SQLite DB."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine, expire_on_commit=False)
    session = TestSession()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# --------------------------------------------------------------------------- #
# Async HTTP client fixtures (API endpoint tests)
# --------------------------------------------------------------------------- #
@pytest_asyncio.fixture
async def _async_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def client(_async_engine):
    """An httpx AsyncClient wired to the ASGI app with an isolated DB."""
    TestSession = async_sessionmaker(
        bind=_async_engine, expire_on_commit=False, class_=AsyncSession
    )

    async def _override_get_db():
        async with TestSession() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def authed_client(client):
    """An AsyncClient that has registered a user and carries a bearer token."""
    creds = {"email": "tester@example.com", "password": "password123"}
    await client.post("/api/auth/register", json=creds)
    resp = await client.post("/api/auth/login", json=creds)
    token = resp.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    yield client
