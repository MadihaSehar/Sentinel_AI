"use client";

import { useEffect, useRef, useState } from "react";
import {
  api,
  createEventSocket,
  type AssessmentRaw,
  type FindingRaw,
  type LiveEvent,
} from "@/lib/api";
import { formatRelativeTime } from "@/lib/format";

/**
 * Live scan view, wired to the real backend.
 *
 * - Assessment metadata and persisted findings come over REST.
 * - Stage progress and the event feed are driven by the section 19 WebSocket,
 *   which streams the orchestrator's coarse stages: recon → discovery →
 *   vulnerability → analyze → report. When the scan reports completion we
 *   refetch findings so the results panel fills in.
 */

type StageStatus = "pending" | "running" | "done" | "error";

const STAGE_ORDER: { key: string; label: string }[] = [
  { key: "recon", label: "Recon" },
  { key: "discovery", label: "Discovery" },
  { key: "vulnerability", label: "Vulnerability" },
  { key: "analyze", label: "Analyze" },
  { key: "report", label: "Report" },
];

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-rose-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-sky-400",
  info: "text-slate-400",
};

function stageDot(status: StageStatus): string {
  if (status === "done") return "bg-emerald-400";
  if (status === "running") return "bg-cyan-400 animate-pulse";
  if (status === "error") return "bg-rose-500";
  return "bg-slate-600";
}

export default function LiveAssessmentPage({ params }: { params: { id: string } }) {
  const { id } = params;
  const [assessment, setAssessment] = useState<AssessmentRaw | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<"connecting" | "open" | "closed">(
    "connecting"
  );
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [stages, setStages] = useState<Record<string, StageStatus>>(() =>
    Object.fromEntries(STAGE_ORDER.map((s) => [s.key, "pending" as StageStatus]))
  );
  const [scanStatus, setScanStatus] = useState<string | null>(null);
  const [findings, setFindings] = useState<FindingRaw[]>([]);

  // Avoid stale closures when refetching findings from inside the socket cb.
  const refetchFindings = useRef<() => void>(() => {});

  useEffect(() => {
    let cancelled = false;

    async function loadFindings() {
      try {
        const rows = await api.getFindings(id);
        if (!cancelled) setFindings(rows);
      } catch {
        /* findings may not exist until the scan finishes */
      }
    }
    refetchFindings.current = loadFindings;

    (async () => {
      try {
        const a = await api.getAssessment(id);
        if (!cancelled) {
          setAssessment(a);
          setScanStatus(a.status);
        }
      } catch (err) {
        if (!cancelled) setLoadError(err instanceof Error ? err.message : "Failed to load.");
      }
      loadFindings();
    })();

    const disconnect = createEventSocket(
      id,
      (event) => {
        setEvents((prev) => [event, ...prev].slice(0, 100));

        if (event.type === "stage" && typeof event.stage === "string") {
          const raw = String(event.status ?? "");
          const status: StageStatus =
            raw === "done" ? "done" : raw === "error" ? "error" : "running";
          setStages((prev) => ({ ...prev, [event.stage as string]: status }));
        }

        if (event.type === "scan" && typeof event.status === "string") {
          setScanStatus(event.status);
          if (event.status === "completed" || event.status === "failed") {
            refetchFindings.current();
          }
        }
      },
      setConnectionStatus
    );

    return () => {
      cancelled = true;
      disconnect();
    };
  }, [id]);

  const target = assessment?.target ?? id;

  return (
    <div className="p-8">
      <header className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">{target}</h1>
          <p className="mt-1 text-sm text-slate-500">
            Assessment {id}
            {assessment ? ` · ${assessment.assessment_type}` : ""}
            {scanStatus ? ` · ${scanStatus}` : ""}
          </p>
        </div>
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
      </header>

      {loadError && (
        <div className="mb-6 rounded-md border border-rose-500/30 bg-rose-500/5 px-3 py-2 text-sm text-rose-300">
          {loadError}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Pipeline */}
        <div className="lg:col-span-1">
          <div className="rounded-lg border border-slate-800 bg-slate-900/50">
            <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
              Pipeline
            </div>
            <div className="divide-y divide-slate-800/70">
              {STAGE_ORDER.map((s) => {
                const status = stages[s.key];
                return (
                  <div key={s.key} className="flex items-center justify-between px-4 py-2.5">
                    <div className="flex items-center gap-2.5">
                      <span className={`h-2 w-2 rounded-full ${stageDot(status)}`} />
                      <span className="text-sm text-slate-300">{s.label}</span>
                    </div>
                    <span className="text-xs font-medium uppercase tracking-wide text-slate-500">
                      {status}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Findings */}
        <div className="lg:col-span-1">
          <div className="rounded-lg border border-slate-800 bg-slate-900/50">
            <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
              <span>Findings</span>
              <span className="text-xs text-slate-500">{findings.length}</span>
            </div>
            <div className="max-h-96 divide-y divide-slate-800/70 overflow-y-auto">
              {findings.length === 0 ? (
                <div className="px-4 py-6 text-center text-xs text-slate-600">
                  No findings yet. They appear here as the scan confirms them.
                </div>
              ) : (
                findings.map((f) => (
                  <div key={f.id} className="px-4 py-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-slate-200">{f.title}</span>
                      <span
                        className={`text-xs font-medium uppercase ${
                          SEVERITY_COLOR[f.severity] ?? "text-slate-400"
                        }`}
                      >
                        {f.severity}
                      </span>
                    </div>
                    {f.endpoint && (
                      <div className="mt-0.5 truncate font-mono text-xs text-slate-500">
                        {f.method} {f.endpoint}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Live event feed */}
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
                    {event.timestamp && (
                      <span className="text-slate-500">
                        {formatRelativeTime(event.timestamp)}{" "}
                      </span>
                    )}
                    <span className="text-slate-300">
                      {event.type}
                      {event.stage ? `:${event.stage}` : ""}
                      {event.status ? ` · ${event.status}` : ""}
                    </span>
                    {typeof event.message === "string" && event.message && (
                      <span className="text-slate-500"> — {event.message}</span>
                    )}
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
