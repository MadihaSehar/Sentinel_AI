# SentinelAI — Unified Project Structure

This repository was assembled by merging the original **phase-by-phase build
folders** (Phases 1–11 + the consensus / false-positive modules) into one
coherent, runnable tree. Each original phase folder contained only the files
that phase *added or changed*; they have been layered in order (later phases
overriding earlier ones) so that an IDE/agent (e.g. Antigravity) can locate
and execute everything from a single root.

## Layout

```
sentinel-ai/
├── backend/                  # FastAPI backend (Python 3.12+)
│   ├── app/
│   │   ├── main.py           # App entrypoint (ASGI: app.main:app)
│   │   ├── api/routes/       # auth, projects, assessments
│   │   ├── core/             # config, db, security, deps, scope_engine, network_safety
│   │   ├── models/           # SQLAlchemy ORM (core schema)
│   │   ├── schemas/          # Pydantic schemas
│   │   ├── services/         # project/assessment services, scope enforcement, extractors
│   │   ├── orchestrator/     # recon / discovery / vulnerability pipelines
│   │   ├── tools/            # allowlisted tool registry (recon/discovery/vulnerability)
│   │   ├── analysis/         # Phase 6 response-intelligence (similarity, reflection, DOM…)
│   │   ├── analyzers/        # Phase 7 vulnerability analyzers (sqli, xss, idor, …)
│   │   ├── payloads/         # Phase 8 payload knowledge base loader
│   │   ├── evidence/         # false-positive engine + evidence rules
│   │   └── ai/               # Phase 9–10 AI providers, prompts, consensus engine
│   ├── tests/                # pytest suite (mirrors app/)
│   ├── requirements.txt      # UNIFIED deps (reconciled from every phase)
│   ├── requirements-ai.txt   # AI-only subset (kept for reference)
│   └── pytest.ini
├── frontend/                 # Phase 11 Next.js + TypeScript SOC dashboard
├── payload-kb/               # Normalized payload JSON (xss, sqli, injection/access, api)
├── docker/                   # backend.Dockerfile
├── docs/                     # per-phase design notes
├── docker-compose.yml        # db (postgres) + redis + backend
├── .env.example
└── README.md                 # original project README
```

## How to run

**Backend (local):**
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example ../.env   # then fill in values
uvicorn app.main:app --reload       # http://localhost:8000  (/health, /docs)
```

**Backend tests:**
```bash
cd backend && pytest
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev          # http://localhost:3000
```

**Full stack (Docker):**
```bash
docker compose up --build
```

## Phase → directory provenance

| Phase | Area | Merged into |
|-------|------|-------------|
| 1 | Foundation (FastAPI, auth, DB, projects, assessments) | `backend/app/{core,models,schemas,services,api}` |
| 2 | Scope engine + authorization gate | `backend/app/core/{scope_engine,network_safety}.py`, `services/scope_enforcement.py` |
| 3 | Recon tools | `backend/app/tools/recon/`, `orchestrator/recon_pipeline.py` |
| 4 | Discovery | `backend/app/tools/discovery/`, `orchestrator/discovery_pipeline.py` |
| 5 | Nuclei | `backend/app/tools/vulnerability/nuclei.py`, `orchestrator/vulnerability_pipeline.py` |
| 6 | Response intelligence | `backend/app/analysis/`, `models/response_intel.py` |
| 7 | Vulnerability analyzers | `backend/app/analyzers/` |
| 8 | Payload knowledge base | `backend/app/payloads/`, `payload-kb/` |
| 9 | AI integration | `backend/app/ai/{providers,prompts,service}` |
| 10 | Consensus + false-positive | `backend/app/ai/consensus/`, `backend/app/evidence/` |
| 11 | Dashboard | `frontend/` |

## Known gaps / follow-ups

These are pre-existing in the original phase code — the merge preserved them
rather than silently rewriting your friend's logic:

1. **Routes not fully mounted.** `app/main.py` mounts only `auth`, `projects`,
   and `assessments` routers. The later-phase subsystems (orchestrator, tools,
   analyzers, AI, consensus) exist as importable modules and are exercised by
   their own pytest suites, but no API routes were added for them in the
   original phases. Add routers under `app/api/routes/` and `include_router(...)`
   in `main.py` to expose them over HTTP.

2. **`response_intel` uses a separate `Base`.** `app/models/response_intel.py`
   (Phase 6) declares its own `DeclarativeBase`, so its tables are **not**
   registered on `app.core.db.Base` and won't be created by the dev-mode
   `create_all` in `main.py`. To unify, re-point it at `from app.core.db import Base`
   and add it to `app/models/__init__.py`.

3. **Merge fix applied.** `app/models/__init__.py` had been overwritten with an
   empty file by a later phase; it has been restored so the core models register
   correctly. `backend/requirements.txt` was empty in the last phase and has been
   rebuilt as the union of every phase's dependencies.

All 102 backend Python files pass `python -m py_compile`.
