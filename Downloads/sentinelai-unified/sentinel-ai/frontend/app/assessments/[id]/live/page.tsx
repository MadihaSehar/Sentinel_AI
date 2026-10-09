"use client";

import { useEffect, useState } from "react";
import { PipelineStageList } from "@/components/PipelineStageList";
import { createEventSocket } from "@/lib/api";
import { formatRelativeTime } from "@/lib/format";
import { mockAssessments, mockPipelineStages, mockToolRuns } from "@/lib/mock-data";
import type { PipelineStage, ScanEvent } from "@/lib/types";

/**
 * Section 19's live scan page. `createEventSocket()` is real — it opens
 * a WebSocket at `/assessments/{id}/events` with reconnect/backoff — but
 * since no backend is attached in this build, the connection will fail
 * to open and the page falls back to the static demo stage list so the
 * UI stays reviewable. Swap `mockPipelineStages` for state driven by
 * incoming `stage_update` events once Phase 1-8's WebSocket endpoint is live.
 */
export default function LiveAssessmentPage({ params }: { params: { id: string } }) {
  const assessment = mockAssessments.find((a) => a.id === params.id) ?? mockAssessments[0];
  const [connectionStatus, setConnectionStatus] = useState<"connecting" | "open" | "closed">(
    "connecting"
  );
  const [stages] = useState<PipelineStage[]>(mockPipelineStages);
  const [events, setEvents] = useState<ScanEvent[]>([]);

  useEffect(() => {
    const disconnect = createEventSocket(
      assessment.id,
      (event) => setEvents((prev) => [event, ...prev].slice(0, 50)),
      setConnectionStatus
    );
    return disconnect;
  }, [assessment.id]);

  return (
    <div className="p-8">
      <header className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">{assessment.target}</h1>
          <p className="mt-1 text-sm text-slate-500">
            Assessment {assessment.id} · {assessment.assessmentType}
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
                : "Disconnected (showing demo data)"}
          </span>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="lg:col-span-1">
          <PipelineStageList stages={stages} />
        </div>

        <div className="lg:col-span-1">
          <div className="rounded-lg border border-slate-800 bg-slate-900/50">
            <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
              Tool Execution
            </div>
            <div className="divide-y divide-slate-800/70">
              {mockToolRuns.map((run) => (
                <div key={run.id} className="flex items-center justify-between px-4 py-2.5">
                  <div>
                    <div className="font-mono text-sm text-slate-300">{run.toolName}</div>
                    <div className="text-xs text-slate-500">{run.target}</div>
                  </div>
                  <span
                    className={`text-xs font-medium uppercase tracking-wide ${
                      run.status === "completed"
                        ? "text-emerald-400"
                        : run.status === "running"
                          ? "text-cyan-400"
                          : run.status === "failed"
                            ? "text-rose-400"
                            : "text-slate-500"
                    }`}
                  >
                    {run.status}
                    {run.resultCount !== null ? ` · ${run.resultCount}` : ""}
                  </span>
                </div>
              ))}
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
                    <span className="text-slate-300">{event.type}</span>
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
