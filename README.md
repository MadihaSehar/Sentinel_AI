# SentinelAI

**Multi-Model AI-Powered Web Security Assessment & Vulnerability Intelligence Platform**

> ⚠️ **Authorized use only.** SentinelAI is built for penetration testing, bug
> bounty programs, CTFs, and lab environments where the target is explicitly
> in scope. The platform enforces an authorization gate (below) before any
> future scanning module can run — but that gate only enforces what you tell
> it. You are responsible for having real authorization to test your target.

---

## 1. Status

This repo currently implements **Phases 1–2** of the roadmap below:
project foundation, auth, the authorization/scope data model + gate
(Phase 1), and the **Scope Enforcement Layer** — domain/CIDR matching,
SSRF protection, and rate-limit/concurrency admission control (Phase 2).
No scanning, reconnaissance, or AI analysis code exists yet — those begin
in Phase 3, built on top of this foundation.

Fully working and tested:

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v   # 32/32 passing
```

or via Docker:

```bash
cp .env.example .env   # then set SECRET_KEY (see .env.example)
docker compose up --build
# API: http://localhost:8000/docs
```

---

## 2. Architecture

```
User
 │
 ▼
Authorization & Scope Engine   ← Phase 1/2 (this repo, today)
 │
 ▼
AI Orchestrator                ← Phase 9/10
 │
 ▼
Reconnaissance → Discovery → Vulnerability Candidate Detection
 │
 ▼
Controlled Validation → Response Analysis
 │
 ▼
Multi-Model Verification (Gemini / Grok / DeepSeek) → Consensus
 │
 ▼
Confidence Scoring → Human Confirmation → Security Report
```

**Core principle:** the AI reasons over evidence and proposes actions; it
never gets direct shell or network access. Every tool execution (future
phases) will go through an allowlisted Tool Registry, and every tool run
will be re-validated against the Scope Enforcement Layer before it's
permitted — regardless of what any AI provider "decides."

### Repository layout

```
sentinel-ai/
├── backend/
│   └── app/
│       ├── api/routes/     # FastAPI routers (HTTP only, thin)
│       ├── core/           # config, db, security, deps
│       ├── models/         # SQLAlchemy ORM models
│       ├── schemas/        # Pydantic request/response models
│       ├── services/       # business logic (authorization gate lives here)
│       ├── orchestrator/   # Phase 9/10: AI planning engine
│       ├── ai/             # Phase 9: provider abstraction, prompts, consensus
│       ├── scanners/       # Phase 3+: recon/discovery/vuln/analyzers
│       ├── tools/          # Phase 3+: Tool Registry (subfinder, nuclei, etc.)
│       ├── payloads/       # Phase 8: normalized PayloadsAllTheThings KB
│       ├── evidence/       # Phase 6: request/response evidence model
│       └── reporting/      # Phase 12: HTML/PDF report generation
├── frontend/                # Next.js dashboard (Phase 11)
├── workers/                 # Celery workers (Phase 3+)
├── payload-kb/               # Normalized payload knowledge base data
├── nuclei-templates/
├── docker/
└── docs/
```

---

## 3. The authorization gate — how it actually works

This is the architectural centerpiece of Phase 1, because every later
phase's safety depends on it.

1. **Creating** an assessment (`POST /projects/{id}/assessments`) always
   produces `status=DRAFT`, `authorization_confirmed=False` — regardless
   of what's in the request body. There is no way to create a
   pre-authorized assessment.
2. **Authorizing** it requires a dedicated, separate call
   (`POST /assessments/{id}/authorize`) with:
   - an exact confirmation phrase (`"I CONFIRM AUTHORIZATION"`) — not a
     checkbox that's easy to script past without reading,
   - an explicit `acknowledgement: true` boolean,
   - the authenticated user's identity and a timestamp, both recorded.
   This transition is one-way: an already-authorized assessment can't be
   re-authorized (`409 Conflict`), preventing silent re-confirmation after
   scope has changed.
3. **Starting** (`POST /assessments/{id}/start`) checks
   `authorization_confirmed` and `status == AUTHORIZED` and rejects with
   `403` otherwise. This check is implemented once, in
   `services/assessment_service.py` / the route handler — not duplicated
   per-tool — so Phase 3+ tool execution code has exactly one gate to
   inherit, not one to reimplement per scanner.
4. Every transition writes to `audit_logs` (user, assessment, action,
   description, timestamp) — append-only, never edited.
5. **Scope rules** are explicit include/exclude rows
   (`domain_include` / `domain_exclude` / `cidr_include` / `cidr_exclude`),
   not a single target string — because real engagements have carve-outs
   ("`*.example.com` in scope, but `admin.example.com` and `10.0.0.0/8`
   explicitly excluded"). The target itself is always implicitly added as
   an include rule. This table is pure data in Phase 1; the Scope
   Enforcement Layer that *consults* it before every network operation is
   built in Phase 2, reusing this schema unchanged.
6. **Rate limit and concurrency are clamped server-side**
   (`MAX_SCAN_RATE_LIMIT`, `MAX_SCAN_CONCURRENCY` in `core/config.py`) —
   a request body claiming `rate_limit_rps: 9999` is silently capped to
   the platform ceiling, never trusted as-is. This is tested in
   `test_rate_limit_and_concurrency_are_clamped_server_side`.

Run `pytest backend/tests/test_authorization_gate.py -v` to see all of
this enforced end-to-end.

---

## 4. The Scope Enforcement Layer (Phase 2)

This is what every future tool call (Phase 3 onward) will be routed
through. It lives in `app/services/scope_enforcement.py` and has three
pieces:

**`ScopeEnforcer.check_host(assessment, host, resolve=False)`** — pure
matching logic, no network I/O by default:
- Domain rules support wildcards: `*.example.com` matches any subdomain
  **and** the bare apex `example.com` (the bug-bounty-program convention).
  An exact rule with no wildcard matches only that literal host.
- `DOMAIN_EXCLUDE` / `CIDR_EXCLUDE` always win over any include rule.
- IP literals require an **explicit** `CIDR_INCLUDE` rule — a domain
  wildcard never implicitly authorizes a bare IP.
- With `resolve=True`, it performs a real DNS lookup (injectable resolver,
  so this is fully unit-testable without touching the network — see the
  `fake_resolver` fixtures in `tests/test_scope_enforcement.py`) and
  re-checks every resolved address against the same rules. This catches a
  DNS record that points somewhere the scope rules never authorized —
  including a form of DNS-rebinding-style SSRF against the platform's own
  network.

**SSRF protection (`app/core/network_safety.py`)** splits "disallowed"
into two tiers, because collapsing them would break a legitimate use case:
- **Always blocked, never scope-overridable:** loopback (127.0.0.0/8,
  ::1), link-local (169.254.0.0/16, fe80::/10), known cloud
  instance-metadata IPs (169.254.169.254, etc.), multicast, unspecified,
  and IETF-reserved ranges. No CIDR include rule can re-authorize these —
  they would target the scanning platform's own host or its cloud
  provider's control plane, never a real engagement target.
- **RFC1918 private ranges (10/8, 172.16/12, 192.168/16):** NOT
  auto-blocked, because internal-network pentests are a real, legitimate
  engagement type, and the Phase 25 lab environment (Juice Shop, DVWA,
  WebGoat) typically runs on private/local addresses. These are only
  reachable when a `CIDR_INCLUDE` rule explicitly names them — see
  `test_private_ip_blocked_without_explicit_cidr_include` vs.
  `test_private_ip_allowed_with_explicit_cidr_include`.

**`NetworkGate.guard(assessment, host)`** — the single async context
manager every future scanner call will sit inside:
```python
async with network_gate.guard(assessment, "sub.example.com") as decision:
    ...  # the actual bounded network operation
```
Before yielding, it checks, in order: (1) assessment status is `QUEUED`
or `RUNNING` — note `AUTHORIZED`-but-not-started deliberately does **not**
pass, since "authorize" and "start" are two separate audited actions; (2)
`authorization_confirmed` is true (defense in depth, even though status
alone should never reach this point otherwise); (3) current time is
within the assessment's scan window, if one is set; (4) the host passes
`ScopeEnforcer.check_host`. Only then does it acquire a
rate-limit/concurrency slot and yield — any failure raises
`ScopeViolationError` before any network I/O has happened.

**`RateLimiter`** is an in-memory, per-assessment token-interval +
`asyncio.Semaphore` limiter. It's intentionally simple for Phase 2 — a
single-process limiter is sufficient because nothing calls it across
process boundaries yet. Phase 3 introduces Celery workers, at which point
this becomes Redis-backed so the same limit holds across multiple worker
processes; `acquire()`'s signature is deliberately already shaped so that
swap won't change any caller.

An API endpoint, `POST /assessments/{id}/scope/check`, lets a researcher
validate their scope config directly (`{"host": "admin.example.com"}` →
`{"allowed": false, "reason": "..."}`). Pattern-matching alone
(`resolve: false`, the default) needs no authorization since it's pure
local computation; passing `resolve: true` performs a real DNS lookup
against the target, so it requires the assessment to already be
authorized — the same rule Phase 3's tools inherit for free by going
through `NetworkGate` instead of reimplementing this check.

---

## 5. Design decisions worth flagging

- **Async SQLAlchemy 2.0 + asyncpg** throughout — the whole platform is
  I/O-bound (DB, future HTTP scanning, future AI calls), so sync ORM calls
  would become a bottleneck under concurrent assessments.
- **Cross-dialect `Uuid` type** (not `postgresql.UUID`) on every model, so
  the test suite can run against in-memory SQLite without a running
  Postgres instance, while production still gets Postgres's native UUID
  column type.
- **Service layer separate from routes.** Route handlers only do HTTP
  concerns (parsing, status codes, dependency injection); all business
  logic — especially the authorization transition — lives in
  `app/services/` so it's unit-testable without an HTTP client and so
  there's exactly one implementation to audit.
- **JWTs carry only `sub` + `exp`,** no roles/permissions — those are
  re-checked against the database on every request, so a permission
  change takes effect immediately instead of waiting for token expiry.
- **bcrypt pinned to 4.0.1** — newer bcrypt releases (4.1+) dropped the
  `__about__` attribute passlib's version probe relies on, which breaks
  password hashing entirely. Pinned until passlib ships a compatible
  release.
- **`.env.example` is the single source of truth** for every environment
  variable the whole roadmap will eventually need (AI provider keys, tool
  paths), even though most aren't consumed yet — so the file never needs
  restructuring later, only filling in.

---

## 6. Roadmap

| Phase | Scope | Status |
|---|---|---|
| 1 | Foundation: Docker, FastAPI, Postgres, Redis, auth, projects, assessments, **authorization gate** | ✅ Done |
| 2 | Scope Enforcement Layer: domain/CIDR matching, SSRF protection, rate limit/concurrency admission control | ✅ Done (this repo) |
| 3 | Recon tools: subfinder, dnsx, httpx, naabu — first callers of `NetworkGate` | Next |
| 4 | Discovery: katana, gau, waybackurls, ffuf, dirsearch | Planned |
| 5 | Nuclei integration | Planned |
| 6 | Response intelligence: request/response storage, diffing, reflection detection | Planned |
| 7 | Vulnerability analyzers | Planned |
| 8 | Payload Knowledge Base (normalized PayloadsAllTheThings) | Planned |
| 9 | AI provider abstraction: Gemini / Grok / DeepSeek | Planned |
| 10 | Consensus engine, false-positive reduction | Planned |
| 11 | Next.js SOC-style dashboard, live scan view, attack-surface graph | Planned |
| 12 | HTML/PDF reporting | Planned |
| 13 | Full test coverage, integration tests | Planned |
| 14 | Deployment hardening | Planned |

---

## 7. Running tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

32/32 tests currently passing:
- **Authorization gate** (`test_authorization_gate.py`): draft-state
  defaults, the 403 on unauthorized start, confirmation-phrase/
  acknowledgement validation, the one-way authorize transition (409 on
  re-authorize), server-side rate limit/concurrency clamping, domain
  validation, cross-user access isolation (404, not 403).
- **Scope enforcement** (`test_scope_enforcement.py`): wildcard domain
  matching (including the apex-matches convention), exclude-overrides-
  include, IP literals requiring explicit CIDR includes, always-blocked
  SSRF ranges holding even against an explicit CIDR include, private
  ranges allowed only when explicitly scoped, DNS-resolve re-checking
  resolved IPs, `NetworkGate` lifecycle/scan-window admission control, and
  the rate limiter's concurrency ceiling + minimum-interval enforcement.
- **Scope check endpoint** (`test_scope_check_endpoint.py`): pattern
  matching works pre-authorization; `resolve=true` requires it.

## 8. License

See `LICENSE` (add your organization's chosen license before any public
or shared use).
