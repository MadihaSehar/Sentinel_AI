/**
 * Typed API client for the SentinelAI backend (section 33's REST surface).
 *
 * Phase 11 ships this against Phase 1-8's FastAPI backend contract, but
 * since that backend isn't part of this build, every function here is a
 * thin, swappable wrapper: real fetch calls, pointed at
 * NEXT_PUBLIC_API_BASE_URL, with the exact shapes the backend is
 * expected to return. Nothing in the component layer should ever call
 * `fetch()` directly — only this module — so swapping mock responses
 * for the live backend later is a one-file change.
 */
import type { Assessment, Finding, PipelineStage, ScanEvent, ScopeRule } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "/api";

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new ApiError(res.status, body || res.statusText);
  }
  return res.json() as Promise<T>;
}

export const api = {
  listAssessments: () => request<Assessment[]>("/assessments"),

  getAssessment: (id: string) => request<Assessment>(`/assessments/${id}`),

  createAssessment: (input: {
    target: string;
    assessmentType: Assessment["assessmentType"];
    scope: ScopeRule;
  }) =>
    request<Assessment>("/assessments", {
      method: "POST",
      body: JSON.stringify(input),
    }),

  startAssessment: (id: string) =>
    request<void>(`/assessments/${id}/start`, { method: "POST" }),

  stopAssessment: (id: string) =>
    request<void>(`/assessments/${id}/stop`, { method: "POST" }),

  getPipelineStages: (id: string) =>
    request<PipelineStage[]>(`/assessments/${id}/stages`),

  getFindings: (id: string) => request<Finding[]>(`/assessments/${id}/findings`),

  /**
   * Section 33: GET /api/assessments/{id}/events — in production this is
   * the WebSocket URL for live progress (section 19), not a plain GET.
   */
  eventsWebSocketUrl: (id: string) => {
    const httpBase = API_BASE.startsWith("http") ? API_BASE : window.location.origin + API_BASE;
    const wsBase = httpBase.replace(/^http/, "ws");
    return `${wsBase}/assessments/${id}/events`;
  },
};

export { ApiError };

/**
 * React hook: subscribes to an assessment's live WebSocket event stream
 * and calls `onEvent` for each parsed `ScanEvent`. Reconnects with
 * backoff on drop. Returns the current connection state so the UI can
 * show "Live" / "Reconnecting" / "Disconnected".
 */
export function createEventSocket(
  assessmentId: string,
  onEvent: (event: ScanEvent) => void,
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
        const parsed = JSON.parse(ev.data) as ScanEvent;
        onEvent(parsed);
      } catch {
        // Malformed event from the wire — drop it rather than crash the UI.
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
