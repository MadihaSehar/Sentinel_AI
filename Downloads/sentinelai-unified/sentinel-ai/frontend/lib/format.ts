import type { ConsensusStatus, Severity, StageStatus } from "./types";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_STYLES: Record<Severity, { bg: string; text: string; ring: string }> = {
  critical: { bg: "bg-rose-500/10", text: "text-rose-400", ring: "ring-rose-500/30" },
  high: { bg: "bg-orange-500/10", text: "text-orange-400", ring: "ring-orange-500/30" },
  medium: { bg: "bg-amber-500/10", text: "text-amber-400", ring: "ring-amber-500/30" },
  low: { bg: "bg-sky-500/10", text: "text-sky-400", ring: "ring-sky-500/30" },
  info: { bg: "bg-slate-500/10", text: "text-slate-400", ring: "ring-slate-500/30" },
};

export const CONSENSUS_STYLES: Record<ConsensusStatus, { bg: string; text: string; label: string }> = {
  CONFIRMED: { bg: "bg-emerald-500/10", text: "text-emerald-400", label: "Confirmed" },
  NO_FINDING: { bg: "bg-slate-500/10", text: "text-slate-400", label: "No finding" },
  REQUIRES_MANUAL_REVIEW: {
    bg: "bg-amber-500/10",
    text: "text-amber-400",
    label: "Needs review",
  },
  INSUFFICIENT_DATA: { bg: "bg-slate-500/10", text: "text-slate-500", label: "Insufficient data" },
};

export const STAGE_STATUS_STYLES: Record<StageStatus, { dot: string; text: string }> = {
  pending: { dot: "bg-slate-600", text: "text-slate-500" },
  running: { dot: "bg-cyan-400 animate-pulse", text: "text-cyan-400" },
  done: { dot: "bg-emerald-400", text: "text-emerald-400" },
  skipped: { dot: "bg-slate-600", text: "text-slate-600" },
  error: { dot: "bg-rose-500", text: "text-rose-400" },
};

export function formatConfidence(confidence: number): string {
  return `${Math.round(confidence * 100)}%`;
}

export function formatRelativeTime(iso: string): string {
  const date = new Date(iso);
  const diffMs = Date.now() - date.getTime();
  const diffSec = Math.round(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.round(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.round(diffHr / 24);
  return `${diffDay}d ago`;
}
