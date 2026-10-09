# Phase 11 — Dashboard

## What this phase delivers

A real, building Next.js 14 (App Router) + TypeScript + Tailwind project
in `frontend/`, implementing every page listed in section 18:

Dashboard · Projects · New Assessment · Live Assessment · Attack Surface ·
Assets · Subdomains · Endpoints · Technologies · Vulnerabilities ·
Evidence · AI Analysis · Tool Runs · Payload Knowledge Base · Reports ·
Settings

`npm run build` succeeds with zero errors (verified — see below).

## What's fully built vs. stubbed

**Fully built:** Dashboard, Projects, New Assessment, Live Assessment,
Attack Surface, Vulnerabilities. These are the pages the master prompt
describes in the most detail (sections 3, 19, 20, 21) and the ones that
directly consume Phase 9/10's data shapes.

**Stubbed (`ComingSoon` placeholder):** Assets, Subdomains, Endpoints,
Technologies, Evidence, AI Analysis, Tool Runs, Payload Knowledge Base,
Reports, Settings. These are nav-complete (the sidebar links all work,
section 18 is fully represented) but their detail views depend on
backend tables (`subdomains`, `endpoints`, `tool_results`, etc.) that
don't exist yet in this build. Building a detail page against data that
doesn't exist produces a page that *looks* done but tests nothing real —
better to be honest about what's scaffolded vs. implemented.

## Key design decisions

**1. Types are a hand-written mirror of the backend, not a guess.**
`lib/types.ts` defines `ConsensusStatus`, `Severity`, and `Finding`
exactly matching `app/ai/consensus/engine.py` (Phase 10) and section 14's
Vulnerability Evidence Model — field names, value sets, everything. The
Vulnerabilities page renders `consensusStatus`, `agreementScore`, and
`modelCount` directly from this shape, so when Phase 1's FastAPI backend
serializes a real `ConsensusResult`, the frontend doesn't need to change
— only `lib/api.ts`'s mock-vs-real data source does.

**2. One API module, never raw `fetch()` in components.**
`lib/api.ts` is the only place that calls `fetch()` or opens a
`WebSocket`. Every component goes through `api.*`. This means swapping
from demo data to the live backend (Phase 1-8) is a change to one file,
not a search-and-replace across the component tree.

**3. The live WebSocket client is real, not mocked.**
`createEventSocket()` in `lib/api.ts` actually opens a WebSocket at
`/assessments/{id}/events` (section 33) with exponential backoff
reconnect, and the Live Assessment page wires it to a real `useEffect`
that updates connection status and an event feed. Since no backend is
attached in this standalone build, the connection fails to open and the
UI falls back to demo pipeline data — but the client code itself needs
no changes once Phase 1-8's WebSocket endpoint exists.

**4. The New Assessment form enforces section 3's authorization gate.**
The submit button is disabled until target, scope pattern, AND the
authorization checkbox are all filled in — mirroring section 2's
pipeline starting with "Authorization & Scope Engine" before anything
else runs. This is a UI-layer convenience only; the backend's Scope
Enforcement Layer must independently re-validate everything server-side
regardless of what this form sends, since a client-side check is
trivially bypassable.

**5. Dark, SOC-style theme via Tailwind utility classes, no component library.**
Severity/status colors live in one place (`lib/format.ts`) rather than
being repeated inline, so the color mapping for "critical" or
"REQUIRES_MANUAL_REVIEW" only needs to change in one spot. No Tailwind
UI kit was added — section 18 doesn't call for one, and it would be
another thing to keep in sync with the platform's actual visual needs
once real data starts flowing in.

**6. Mock data is isolated and labeled, not sprinkled through components.**
`lib/mock-data.ts` is the single source of placeholder data, with a
comment at the top explaining it's temporary and listing where it's
used. Every page that imports from it is trivially greppable
(`grep -rl mock-data frontend/app`) when it's time to wire up Phase 1-8's
real backend.

## What Phase 11 deliberately does NOT do

- **No real backend connection.** This build has no FastAPI server to
  talk to (Phases 1-8 live in your separate repo per our setup). Every
  page renders from `lib/mock-data.ts`; `lib/api.ts` is written against
  the real contract but unexercised beyond the WebSocket's connection
  attempt.
- **No auth/RBAC UI.** Section 23's API authentication and RBAC
  requirements apply to the backend; a login screen for the dashboard
  itself wasn't in section 18's page list and wasn't built.
- **No attack-surface graph visualization.** Section 20 describes a
  visual relationship graph; the Attack Surface page here is a flat,
  readable list of assets instead. A real graph (e.g. via a library like
  react-flow or d3) is a reasonable follow-up once there's real
  hierarchical data to render — building graph layout logic against
  three fake rows wouldn't prove anything.

## Running it

```bash
cd frontend
npm install
cp .env.example .env.local   # point NEXT_PUBLIC_API_BASE_URL at your backend
npm run dev                   # http://localhost:3000
npm run build                 # production build — verified clean
```

## Wiring to the real backend

Once Phase 1-8's FastAPI app is up:

1. Set `NEXT_PUBLIC_API_BASE_URL` to its origin in `.env.local`.
2. In each page currently importing from `lib/mock-data`, swap to the
   matching `api.*` call (e.g. `mockFindings` → `await api.getFindings(id)`)
   and convert the page to a server component or add a loading state.
3. Nothing in `lib/types.ts`, `lib/api.ts`, or the component layer needs
   to change — they were written against the real contract from the start.
