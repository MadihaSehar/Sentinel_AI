"""
SentinelAI backend entrypoint.

Phase 1 scope: app wiring, auth, projects, assessments + the authorization
gate, and dev-mode schema creation. Scanning/tooling/AI routes are added in
later phases and will mount under the same `/api` prefix.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.models  # noqa: F401  — registers all models on Base.metadata
from app.api.routes import assessments, auth, projects
from app.core.config import get_settings
from app.core.db import Base, engine

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.ENVIRONMENT == "development":
        # Dev convenience only. Staging/production use Alembic migrations
        # (backend/alembic/), never create_all.
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="Multi-Model AI-Powered Web Security Assessment & Vulnerability "
    "Intelligence Platform — authorized-use only.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(projects.router, prefix=settings.API_V1_PREFIX)
app.include_router(assessments.router, prefix=settings.API_V1_PREFIX)


@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "app": settings.APP_NAME, "environment": settings.ENVIRONMENT}
