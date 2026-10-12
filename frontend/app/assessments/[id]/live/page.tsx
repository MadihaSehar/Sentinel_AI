"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { PipelineStageList } from "@/components/PipelineStageList";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  api,
  assessmentTypeLabel,
  createEventSocket,
  type AssessmentRead,
  type BackendScanEvent,
} from "@/lib/api";
import { formatRelativeTime } from "@/lib/format";
import type { Finding, PipelineStage, PipelineStageName, StageStatus } from "@/lib/types";

/**
 * Section 19's live scan page — fully wired to the backend.
 *
 * On mount it loads the assessment, then opens the live WebSocket at
 * `/assessments/{id}/events`. Pipeline stage state is driven entirely by the
 * orchestrator's `stage` events; overall progress by `scan` events; and when
 * the scan finishes it pulls the persisted findings. `createEventSocket`
 * reconnects with backoff, so a dropped socket recovers on its own.
 */

// The stages the scan orchestrator actually emits (scan_orchestrator.py),
// in order. Labels are display-only.
const ORCHESTRATOR_STAGES: { name: string; label: string }[] = [
  { name: "recon", label: "Recon" },
  { name: "discovery", label: "Discovery" },
  { name: "vulnerability", label: "Vulnerability" },
  { name: "analyze", label: "Analyzers" },
  { name: "report", label: "Promote & Persist" },
];

function initialStages(): PipelineStage[] {
  return ORCHESTRATOR_STAGES.map((s) => ({
    name: s.name as PipelineStageName,
    label: s.label,
    status: "pending" as StageStatus,
    progressPercent: null,
  }));
}

function describeEvent(ev: BackendScanEvent): string {
  const p = ev.payload ?? {};
  switch (ev.type) {
    case "scan":
      if (p.status === "running") return `Scan started on ${p.target ?? "target"}`;
      if (p.status === "completed") return `Scan completed — ${p.findings ?? 0} finding(s)`;
      if (p.status === "failed") return `Scan failed: ${p.message ?? "unknown error"}`;
      return `Scan ${p.status ?? ""}`;
    case "stage": {
      const extras = Object.entries(p)
        .filter(([k]) => k !== "stage" && k !== "status")
        .map(([k, v]) => `${k}=${v}`)
        .join(" ");
      return `${p.stage}: ${p.status}${extras ? ` (${extras})` : ""}`;
    }
    case "log":
      return String(p.message ?? "log");
    case "error":
      return `Error: ${p.message ?? "unknown"}`;
    default:
      return ev.type;
  }
}

export default function LiveAssessmentPage({ params }: { params: { id: string } }) {
  const id = params.id;
  const [assessment, setAssessment] = useState<AssessmentRead | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<"connecting" | "open" | "closed">(
    "connecting"
  );
  const [scanStatus, setScanStatus] = useState<string>("pending");
  const [stages, setStages] = useState<PipelineStage[]>(initialStages);
  const [events, setEvents] = useState<BackendScanEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const findingsLoaded = useRef(false);

  // Load assessment metadata.
  useEffect(() => {
    let active = true;
    api
      .getAssessment(id)
      .then((a) => {
        if (active) {
          setAssessment(a);
          setScanStatus(a.status);
        }
      })
      .catch((err) => active && setLoadError(err?.message ?? "Failed to load assessment"));
    return () => {
      active = false;
    };
  }, [id]);

  const loadFindings = useCallback(() => {
    if (findingsLoaded.current) return;
    findingsLoaded.current = true;
    api.getFindings(id).then(setFindings).catch(() => undefined);
  }, [id]);

  const handleEvent = useCallback(
    (ev: BackendScanEvent) => {
      if (ev.type === "heartbeat") return;
      setEvents((prev) => [ev, ...prev].slice(0, 100));

      if (ev.type === "stage") {
        const stageName = String(ev.payload?.stage ?? "");
        const stageStatus = String(ev.payload?.status ?? "") as StageStatus;
        setStages((prev) =>
          prev.map((s) => (s.name === stageName ? { ...s, status: stageStatus } : s))
        );
      }

      if (ev.type === "scan") {
        const status = String(ev.payload?.status ?? "");
        if (status) setScanStatus(status);
        if (status === "completed") loadFindings();
      }
    },
    [loadFindings]
  );

  // Open the live socket.
  useEffect(() => {
    const disconnect = createEventSocket(id, handleEvent, setConnectionStatus);
    return disconnect;
  }, [id, handleEvent]);

  const title = assessment?.target ?? "Assessment";
  const typeLabel = assessment ? assessmentTypeLabel(assessment.assessment_type) : "";
  const isTerminal = ["completed", "failed", "stopped"].includes(scanStatus);

  async function handleStop() {
    try {
      const updated = await api.stopAssessment(id);
      setScanStatus(updated.status);
    } catch {
      /* ignore — status will reconcile on next load */
    }
  }

  return (
    <div className="p-8">
      <header className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">{title}</h1>
          <p className="mt-1 text-sm text-slate-500">
            Assessment {id.slice(0, 8)} · {typeLabel} ·{" "}
            <span className="uppercase tracking-wide">{scanStatus}</span>
          </p>
          {loadError && <p className="mt-1 text-sm text-rose-400">{loadError}</p>}
        </div>
        <div className="flex items-center gap-4">
          {!isTerminal && (
            <button
              onClick={handleStop}
              className="rounded-md px-3 py-1.5 text-xs font-medium text-rose-300 ring-1 ring-rose-500/40 transition-colors hover:bg-rose-500/10"
            >
              Stop scan
            </button>
          )}
          <div className="flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${
                connectionStatus === "open"
                  ? "bg-emerald-400"
                  : connectionStatus === "connecting"
                    ? "bg-amber-400 animate-pulse"
                    : "bg-rose-500"
              }`}
            />
            <span className="text-xs text-slate-500">
              {connectionStatus === "open"
                ? "Live"
                : connectionStatus === "connecting"
                  ? "Connecting…"
                  : "Disconnected"}
            </span>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-1">
          <PipelineStageList stages={stages} />
        </div>

        <div className="lg:col-span-1">
          <div className="rounded-lg border border-slate-800 bg-slate-900/50">
            <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
              Findings {findings.length > 0 ? `(${findings.length})` : ""}
            </div>
            <div className="max-h-96 divide-y divide-slate-800/70 overflow-y-auto">
              {findings.length === 0 ? (
                <div className="px-4 py-6 text-center text-xs text-slate-600">
                  {isTerminal
                    ? "No findings persisted for this scan."
                    : "Findings appear here once the scan completes."}
                </div>
              ) : (
                findings.map((f) => (
                  <div key={f.id} className="px-4 py-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-sm text-slate-200">{f.title}</span>
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <div className="mt-0.5 truncate font-mono text-xs text-slate-500">
                      {f.method} {f.endpoint}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="lg:col-span-1">
          <div className="rounded-lg border border-slate-800 bg-slate-900/50">
            <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
              Live Event Feed
            </div>
            <div className="max-h-96 divide-y divide-slate-800/70 overflow-y-auto">
              {events.length === 0 ? (
                <div className="px-4 py-6 text-center text-xs text-slate-600">
                  Waiting for events from the assessment&apos;s WebSocket…
                </div>
              ) : (
                events.map((event, i) => (
                  <div key={i} className="px-4 py-2 text-xs">
                    <span className="text-slate-500">{formatRelativeTime(event.timestamp)}</span>{" "}
                    <span
                      className={
                        event.type === "error"
                          ? "text-rose-400"
                          : event.type === "scan"
                            ? "text-cyan-300"
                            : "text-slate-300"
                      }
                    >
                      {describeEvent(event)}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
