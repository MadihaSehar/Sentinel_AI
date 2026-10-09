/**
 * Shared types for the SentinelAI dashboard.
 *
 * These intentionally mirror the backend shapes exactly:
 *  - Severity / ConsensusStatus match `app/ai/consensus/engine.py` (Phase 10)
 *  - Finding matches section 14's "Vulnerability Evidence Model"
 *  - PipelineStage/StageStatus match the live-scan checklist in section 19
 *
 * Keeping these as a hand-written mirror (rather than codegen from the
 * OpenAPI schema) is a deliberate Phase 11 shortcut — once Phase 1's
 * FastAPI app exposes real Pydantic schemas, swap this file for a
 * generated client (e.g. `openapi-typescript`) instead of maintaining it
 * by hand.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ConsensusStatus =
  | "CONFIRMED"
  | "NO_FINDING"
  | "REQUIRES_MANUAL_REVIEW"
  | "INSUFFICIENT_DATA";

export type AssessmentType = "Bug Bounty" | "Pentest" | "CTF" | "Lab";

export type AssessmentState =
  | "pending"
  | "running"
  | "paused"
  | "completed"
  | "failed"
  | "stopped";

export interface ScopeRule {
  allowedDomains: string[];
  allowedCidrs: string[];
  excludedDomains: string[];
  excludedCidrs: string[];
  rateLimitPerSecond: number;
  concurrency: number;
  authorizationConfirmed: boolean;
}

export interface Assessment {
  id: string;
  target: string;
  assessmentType: AssessmentType;
  state: AssessmentState;
  scope: ScopeRule;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  findingsCount: Record<Severity, number>;
}

/** Matches section 19's live scan checklist exactly. */
export type PipelineStageName =
  | "recon"
  | "dns"
  | "http_discovery"
  | "port_discovery"
  | "crawler"
  | "directory_scan"
  | "nuclei"
  | "ai_analysis"
  | "report";

export type StageStatus = "pending" | "running" | "done" | "skipped" | "error";

export interface PipelineStage {
  name: PipelineStageName;
  label: string;
  status: StageStatus;
  progressPercent: number | null; // null when not applicable (e.g. pending/done)
}

/** One live event over the assessment's WebSocket (section 19 / 33). */
export interface ScanEvent {
  type:
    | "stage_update"
    | "asset_discovered"
    | "finding_created"
    | "tool_started"
    | "tool_finished"
    | "ai_decision"
    | "error"
    | "log";
  timestamp: string;
  payload: Record<string, unknown>;
}

/** Mirrors section 14's Vulnerability Evidence Model. */
export interface Finding {
  id: string;
  title: string;
  category: string;
  cwe: string | null;
  owasp: string | null;
  severity: Severity;
  confidence: number; // 0-1
  endpoint: string;
  method: string;
  parameter: string | null;
  evidence: string[];
  affectedAssets: string[];
  recommendation: string;
  references: string[];
  consensusStatus: ConsensusStatus;
  agreementScore: number; // 0-1, from ConsensusEngine
  modelCount: number;
  createdAt: string;
}

export interface Asset {
  id: string;
  hostname: string;
  ipAddresses: string[];
  technologies: string[];
  openPorts: number[];
  httpStatus: number | null;
  discoveredAt: string;
}

export interface ToolRun {
  id: string;
  toolName: string;
  target: string;
  status: "queued" | "running" | "completed" | "failed" | "timeout";
  startedAt: string;
  finishedAt: string | null;
  resultCount: number | null;
}

export interface AiDecision {
  id: string;
  action: string;
  target: string;
  reason: string;
  priority: "high" | "medium" | "low";
  confidence: number;
  createdAt: string;
}
