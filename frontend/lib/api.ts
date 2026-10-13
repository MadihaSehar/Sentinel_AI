/**
 * Typed API client for the SentinelAI backend.
 *
 * This talks to the real FastAPI backend (section 33's REST surface + the
 * section 19 WebSocket event stream). It handles three things the backend
 * requires that the UI would otherwise have to expose by hand:
 *
 *   1. Base URL resolution. In the browser the API lives on the same host the
 *      dashboard is served from, on port 8000 — not the Docker-internal
 *      `backend` hostname. We derive it from `window.location` unless
 *      NEXT_PUBLIC_API_BASE_URL overrides it.
 *   2. Auth. Every endpoint is JWT-guarded. We bootstrap a local account on
 *      first use (register + login), cache the token, and re-auth on 401.
 *   3. Projects. Assessments are created under a project, so we get-or-create
 *      a default project transparently.
 */
import type { AssessmentType } from "./types";

/* --------------------------------------------------------------------------- */
/* Base URL                                                                    */
/* --------------------------------------------------------------------------- */

function resolveApiBase(): string {
  const env = process.env.NEXT_PUBLIC_API_BASE_URL;
  if (env && env.trim() !== "") return env.replace(/\/+$/, "");
  if (typeof window !== "undefined") {
    // Same host as the dashboard, backend port 8000.
    return `${window.location.protocol}//${window.location.hostname}:8000/api`;
  }
  return "/api";
}

const API_BASE = resolveApiBase();

/* --------------------------------------------------------------------------- */
/* Auth bootstrap                                                              */
/* --------------------------------------------------------------------------- */

// Namespaced/versioned so a change to the dev-account scheme (e.g. the email
// domain) discards stale values from a previous version.
const LS_TOKEN = "sentinel.v2.token";
const LS_EMAIL = "sentinel.v2.email";
const LS_PASSWORD = "sentinel.v2.password"; // local dev account only
const LS_PROJECT = "sentinel.v2.projectId";
const LS_LAST_ASSESSMENT = "sentinel.v2.lastAssessmentId";

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

function ls(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    return null;
  }
}

function randomId(n = 12): string {
  const bytes = new Uint8Array(n);
  (globalThis.crypto ?? ({} as Crypto)).getRandomValues?.(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function devCredentials(): { email: string; password: string } {
  const store = ls();
  let email = store?.getItem(LS_EMAIL) ?? "";
  let password = store?.getItem(LS_PASSWORD) ?? "";
  if (!email || !password) {
    // Not a reserved/special-use domain (.local etc.) — the backend's email
    // validator rejects those.
    email = `local-${randomId(5)}@sentinelai.io`;
    password = `Dev-${randomId(10)}`; // >= 8 chars
    store?.setItem(LS_EMAIL, email);
    store?.setItem(LS_PASSWORD, password);
  }
  return { email, password };
}

async function rawJson<T>(path: string, init: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init.headers },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, body || res.statusText);
  }
  // 204 / empty body tolerance.
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

/** Logs in with the cached dev account, registering it first if needed. */
async function login(): Promise<string> {
  const { email, password } = devCredentials();
  try {
    const tok = await rawJson<{ access_token: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    return tok.access_token;
  } catch (err) {
    if (err instanceof ApiError && (err.status === 400 || err.status === 401)) {
      // No such account yet — register, then log in.
      await rawJson("/auth/register", {
        method: "POST",
        body: JSON.stringify({ email, password, full_name: "Local User" }),
      });
      const tok = await rawJson<{ access_token: string }>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      return tok.access_token;
    }
    throw err;
  }
}

async function getToken(forceRefresh = false): Promise<string> {
  const store = ls();
  if (!forceRefresh) {
    const cached = store?.getItem(LS_TOKEN);
    if (cached) return cached;
  }
  const token = await login();
  store?.setItem(LS_TOKEN, token);
  return token;
}

/** Authenticated JSON request. Re-authenticates once on a 401. */
async function authJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  let token = await getToken();
  const run = (tok: string) =>
    rawJson<T>(path, { ...init, headers: { ...init.headers, Authorization: `Bearer ${tok}` } });
  try {
    return await run(token);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      token = await getToken(true);
      return run(token);
    }
    throw err;
  }
}

/* --------------------------------------------------------------------------- */
/* Backend response shapes (snake_case, as the API returns them)               */
/* --------------------------------------------------------------------------- */

export interface AssessmentRaw {
  id: string;
  project_id: string;
  name: string;
  target: string;
  assessment_type: string;
  status: string;
  authorization_confirmed: boolean;
  rate_limit_rps: number;
  concurrency: number;
  scope_rules: { id: string; rule_type: string; value: string }[];
  created_at: string;
}

export interface FindingRaw {
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

/* --------------------------------------------------------------------------- */
/* Projects                                                                    */
/* --------------------------------------------------------------------------- */

async function ensureProject(): Promise<string> {
  const store = ls();
  const cached = store?.getItem(LS_PROJECT);
  if (cached) return cached;

  const existing = await authJson<{ id: string; name: string }[]>("/projects");
  let projectId = existing.find((p) => p.name === "Default")?.id ?? existing[0]?.id;

  if (!projectId) {
    const created = await authJson<{ id: string }>("/projects", {
      method: "POST",
      body: JSON.stringify({
        name: "Default",
        description: "Default project for dashboard-created assessments",
      }),
    });
    projectId = created.id;
  }
  store?.setItem(LS_PROJECT, projectId);
  return projectId;
}

/* --------------------------------------------------------------------------- */
/* Public API                                                                  */
/* --------------------------------------------------------------------------- */

const TYPE_MAP: Record<AssessmentType, string> = {
  "Bug Bounty": "bug_bounty",
  Pentest: "pentest",
  CTF: "ctf",
  Lab: "lab",
};

export interface CreateScanInput {
  target: string;
  assessmentType: AssessmentType;
  scopePattern: string;
  excludedDomains?: string[];
  excludedCidrs?: string[];
  rateLimit?: number;
  concurrency?: number;
}

export const api = {
  /** List all assessments for the current user (flat endpoint). */
  listAssessments: () => authJson<AssessmentRaw[]>("/assessments"),

  /** Single assessment by id (flat endpoint). */
  getAssessment: (id: string) => authJson<AssessmentRaw>(`/assessments/${id}`),

  /** Persisted findings for an assessment. */
  getFindings: (id: string) => authJson<FindingRaw[]>(`/assessments/${id}/findings`),

  /**
   * Full "live scan" bootstrap: create the assessment under the default
   * project, confirm authorization, and start it. Returns the real
   * assessment id to navigate the live view to.
   */
  async createAndStartScan(input: CreateScanInput): Promise<string> {
    const projectId = await ensureProject();

    const scopeRules: { rule_type: string; value: string }[] = [
      { rule_type: "domain_include", value: input.scopePattern },
      ...(input.excludedDomains ?? []).map((v) => ({ rule_type: "domain_exclude", value: v })),
      ...(input.excludedCidrs ?? []).map((v) => ({ rule_type: "cidr_exclude", value: v })),
    ];

    const created = await authJson<AssessmentRaw>(
      `/projects/${projectId}/assessments`,
      {
        method: "POST",
        body: JSON.stringify({
          name: input.target,
          target: input.target,
          assessment_type: TYPE_MAP[input.assessmentType],
          scope_rules: scopeRules,
          rate_limit_rps: input.rateLimit ?? 5,
          concurrency: input.concurrency ?? 10,
        }),
      }
    );

    await authJson(`/projects/${projectId}/assessments/${created.id}/authorize`, {
      method: "POST",
      body: JSON.stringify({
        confirmation_phrase: "I CONFIRM AUTHORIZATION",
        acknowledgement: true,
      }),
    });

    await authJson(`/projects/${projectId}/assessments/${created.id}/start`, { method: "POST" });

    ls()?.setItem(LS_LAST_ASSESSMENT, created.id);
    return created.id;
  },

  /** WebSocket URL for an assessment's live event stream. */
  eventsWebSocketUrl: (id: string) => {
    const httpBase = API_BASE.startsWith("http")
      ? API_BASE
      : (typeof window !== "undefined" ? window.location.origin : "") + API_BASE;
    const wsBase = httpBase.replace(/^http/, "ws");
    return `${wsBase}/assessments/${id}/events`;
  },
};

export { ApiError };

/** The id of the most recently created assessment, if any (browser only). */
export function getLastAssessmentId(): string | null {
  return ls()?.getItem(LS_LAST_ASSESSMENT) ?? null;
}

/**
 * Absolute URL for a report endpoint, e.g. reportUrl("/reports/sample", "pdf").
 * Used for plain anchor links / downloads (not fetch).
 */
export function reportUrl(path: string, format?: "html" | "pdf" | "sarif"): string {
  const base = API_BASE.startsWith("http")
    ? API_BASE
    : (typeof window !== "undefined" ? window.location.origin : "") + API_BASE;
  const query = format ? `?format=${format}` : "";
  return `${base}${path}${query}`;
}

/* --------------------------------------------------------------------------- */
/* Live event stream                                                           */
/* --------------------------------------------------------------------------- */

/** One event off the assessment WebSocket. Fields depend on `type`. */
export interface LiveEvent {
  type: string;
  timestamp?: string;
  stage?: string;
  status?: string;
  message?: string;
  [key: string]: unknown;
}

/**
 * Subscribes to an assessment's live WebSocket event stream and calls
 * `onEvent` for each parsed event. Reconnects with backoff on drop.
 * Returns a disconnect function.
 */
export function createEventSocket(
  assessmentId: string,
  onEvent: (event: LiveEvent) => void,
  onStatusChange: (status: "connecting" | "open" | "closed") => void
): () => void {
  let socket: WebSocket | null = null;
  let closedByCaller = false;
  let retryDelayMs = 1000;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;

  function scheduleReconnect() {
    if (closedByCaller) return;
    retryTimer = setTimeout(connect, retryDelayMs);
    retryDelayMs = Math.min(retryDelayMs * 2, 15000);
  }

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
        onEvent(JSON.parse(ev.data) as LiveEvent);
      } catch {
        // Malformed event — drop it rather than crash the UI.
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

  connect();

  return () => {
    closedByCaller = true;
    if (retryTimer) clearTimeout(retryTimer);
    socket?.close();
  };
}
