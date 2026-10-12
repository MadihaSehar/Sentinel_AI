/**
 * Typed API client for the SentinelAI backend (section 33's REST surface).
 *
 * This is the only place the component layer talks to the backend. It:
 *   - bootstraps a session (register-or-login a dashboard user, cache the
 *     bearer token) so every request is authenticated;
 *   - exposes the create → start → stop flow plus stage/finding reads;
 *   - opens the live events WebSocket with reconnect/backoff.
 *
 * Point it at the backend with NEXT_PUBLIC_API_BASE_URL (default
 * http://localhost:8000/api). The dashboard's single sign-in user is
 * configurable via NEXT_PUBLIC_DASHBOARD_EMAIL / _PASSWORD — this is a
 * single-operator convenience, not a replacement for the backend's auth,
 * which is still enforced on every route.
 */
import type {
  AssessmentType,
  Finding,
  Severity,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000/api";

const DASHBOARD_EMAIL = process.env.NEXT_PUBLIC_DASHBOARD_EMAIL ?? "dashboard@sentinelai.example.com";
const DASHBOARD_PASSWORD = process.env.NEXT_PUBLIC_DASHBOARD_PASSWORD ?? "sentinel-dashboard-dev";
const TOKEN_STORAGE_KEY = "sentinelai.token";

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// --------------------------------------------------------------------------- //
// Auth bootstrap
// --------------------------------------------------------------------------- //
let cachedToken: string | null = null;
let authInFlight: Promise<string> | null = null;

function readStoredToken(): string | null {
  if (cachedToken) return cachedToken;
  if (typeof window === "undefined") return null;
  try {
    cachedToken = window.localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    cachedToken = null;
  }
  return cachedToken;
}

function storeToken(token: string): void {
  cachedToken = token;
  try {
    window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
  } catch {
    // Private mode / storage disabled — in-memory token still works.
  }
}

function clearToken(): void {
  cachedToken = null;
  try {
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

async function login(): Promise<string> {
  const creds = { email: DASHBOARD_EMAIL, password: DASHBOARD_PASSWORD };
  // Register is idempotent-ish: a 409 (already exists) is fine, we just log in.
  await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...creds, full_name: "Dashboard Operator" }),
  }).catch(() => undefined);

  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(creds),
  });
  if (!res.ok) {
    throw new ApiError(res.status, `Sign-in failed: ${await res.text().catch(() => res.statusText)}`);
  }
  const body = (await res.json()) as { access_token: string };
  storeToken(body.access_token);
  return body.access_token;
}

/** Returns a valid bearer token, logging in if needed (deduped). */
async function ensureToken(): Promise<string> {
  const existing = readStoredToken();
  if (existing) return existing;
  if (!authInFlight) {
    authInFlight = login().finally(() => {
      authInFlight = null;
    });
  }
  return authInFlight;
}

// --------------------------------------------------------------------------- //
// Core request helper (auth + one retry on 401)
// --------------------------------------------------------------------------- //
async function request<T>(path: string, init?: RequestInit, retry = true): Promise<T> {
  const token = await ensureToken();
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...init?.headers,
    },
  });

  if (res.status === 401 && retry) {
    // Token expired/invalid — drop it and retry once with a fresh sign-in.
    clearToken();
    return request<T>(path, init, false);
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, body || res.statusText);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// --------------------------------------------------------------------------- //
// Backend response shapes (snake_case, as FastAPI returns them)
// --------------------------------------------------------------------------- //
interface ScopeRuleRead {
  id: string;
  rule_type: string;
  value: string;
}

export interface AssessmentRead {
  id: string;
  project_id: string;
  name: string;
  target: string;
  assessment_type: string; // "bug_bounty" | "pentest" | "ctf" | "lab"
  status: string; // draft | authorized | queued | running | completed | failed | stopped
  authorization_confirmed: boolean;
  rate_limit_rps: number;
  concurrency: number;
  scope_rules: ScopeRuleRead[];
  created_at: string;
}

interface FindingResponse {
  id: string;
  title: string;
  category: string;
  cwe: string | null;
  owasp: string | null;
  severity: string;
  confidence: number;
  endpoint: string;
  method: string;
  parameter: string | null;
  evidence: string[];
  affected_assets: string[];
  recommendation: string;
  references: string[];
  consensus_status: string;
  agreement_score: number;
  model_count: number;
  created_at: string;
}

const ASSESSMENT_TYPE_LABELS: Record<string, AssessmentType> = {
  bug_bounty: "Bug Bounty",
  pentest: "Pentest",
  ctf: "CTF",
  lab: "Lab",
};

export function assessmentTypeLabel(raw: string): AssessmentType {
  return ASSESSMENT_TYPE_LABELS[raw] ?? "Bug Bounty";
}

function mapFinding(f: FindingResponse): Finding {
  const severity = (["critical", "high", "medium", "low", "info"].includes(f.severity)
    ? f.severity
    : "info") as Severity;
  return {
    id: f.id,
    title: f.title,
    category: f.category,
    cwe: f.cwe,
    owasp: f.owasp,
    severity,
    confidence: f.confidence,
    endpoint: f.endpoint,
    method: f.method,
    parameter: f.parameter,
    evidence: f.evidence ?? [],
    affectedAssets: f.affected_assets ?? [],
    recommendation: f.recommendation,
    references: f.references ?? [],
    consensusStatus: (f.consensus_status as Finding["consensusStatus"]) ?? "REQUIRES_MANUAL_REVIEW",
    agreementScore: f.agreement_score,
    modelCount: f.model_count,
    createdAt: f.created_at,
  };
}

// --------------------------------------------------------------------------- //
// Public API
// --------------------------------------------------------------------------- //
export interface CreateAssessmentInput {
  target: string;
  assessmentType: AssessmentType;
  scope: {
    allowedDomains: string[];
    allowedCidrs: string[];
    excludedDomains: string[];
    excludedCidrs: string[];
    rateLimitPerSecond: number;
    concurrency: number;
    authorizationConfirmed: boolean;
  };
}

export const api = {
  listAssessments: () => request<AssessmentRead[]>("/assessments"),

  getAssessment: (id: string) => request<AssessmentRead>(`/assessments/${id}`),

  /** Create (and, when authorized in the form, authorize) an assessment. */
  createAssessment: (input: CreateAssessmentInput) =>
    request<AssessmentRead>("/assessments", {
      method: "POST",
      body: JSON.stringify(input),
    }),

  startAssessment: (id: string) =>
    request<AssessmentRead>(`/assessments/${id}/start`, { method: "POST" }),

  stopAssessment: (id: string) =>
    request<AssessmentRead>(`/assessments/${id}/stop`, { method: "POST" }),

  getFindings: async (id: string): Promise<Finding[]> => {
    const rows = await request<FindingResponse[]>(`/assessments/${id}/findings`);
    return rows.map(mapFinding);
  },

  eventsWebSocketUrl: (id: string) => {
    const httpBase =
      API_BASE.startsWith("http") || typeof window === "undefined"
        ? API_BASE
        : window.location.origin + API_BASE;
    const wsBase = httpBase.replace(/^http/, "ws");
    return `${wsBase}/assessments/${id}/events`;
  },
};

export { ApiError };

/**
 * Absolute URL for a report endpoint, e.g. reportUrl("/reports/sample", "pdf").
 * Used for plain anchor links / downloads (not fetch).
 */
export function reportUrl(path: string, format?: "html" | "pdf" | "sarif"): string {
  const base =
    API_BASE.startsWith("http") || typeof window === "undefined"
      ? API_BASE
      : window.location.origin + API_BASE;
  const query = format ? `?format=${format}` : "";
  return `${base}${path}${query}`;
}

/** One live event as published by the backend orchestrator (events.py). */
export interface BackendScanEvent {
  type: "scan" | "stage" | "log" | "heartbeat" | "error" | string;
  timestamp: string;
  payload: Record<string, unknown>;
}

/**
 * Subscribes to an assessment's live WebSocket event stream and calls
 * `onEvent` for each parsed event. Reconnects with backoff on drop.
 * Returns a disconnect function.
 */
export function createEventSocket(
  assessmentId: string,
  onEvent: (event: BackendScanEvent) => void,
  onStatusChange: (status: "connecting" | "open" | "closed") => void
): () => void {
  let socket: WebSocket | null = null;
  let closedByCaller = false;
  let retryDelayMs = 1000;

  function connect() {
    if (closedByCaller) return;
    onStatusChange("connecting");
    try {
      socket = new WebSocket(api.eventsWebSocketUrl(assessmentId));
    } catch {
      scheduleReconnect();
      return;
    }

    socket.onopen = () => {
      retryDelayMs = 1000;
      onStatusChange("open");
    };
    socket.onmessage = (ev) => {
      try {
        onEvent(JSON.parse(ev.data) as BackendScanEvent);
      } catch {
        // Malformed frame — drop it rather than crash the UI.
      }
    };
    socket.onclose = () => {
      onStatusChange("closed");
      scheduleReconnect();
    };
    socket.onerror = () => {
      socket?.close();
    };
  }

  function scheduleReconnect() {
    if (closedByCaller) return;
    setTimeout(connect, retryDelayMs);
    retryDelayMs = Math.min(retryDelayMs * 2, 15000);
  }

  connect();

  return () => {
    closedByCaller = true;
    socket?.close();
  };
}
