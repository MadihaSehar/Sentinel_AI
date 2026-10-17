"use client";

import { useEffect, useState } from "react";
import { api, type ToolRunRaw } from "@/lib/api";
import { formatRelativeTime } from "@/lib/format";
import { StatCard } from "@/components/StatusBadges";

function calculateDuration(startedAt: string, finishedAt: string | null) {
  if (!finishedAt) return null;
  const start = new Date(startedAt).getTime();
  const finish = new Date(finishedAt).getTime();
  const diffSec = Math.max(0, Math.round((finish - start) / 1000));
  if (diffSec < 60) return `${diffSec}s`;
  const mins = Math.floor(diffSec / 60);
  const secs = diffSec % 60;
  return `${mins}m ${secs}s`;
}

function getToolStatusBadge(status: string) {
  switch (status) {
    case "completed":
      return (
        <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-emerald-500/10 text-emerald-400 ring-emerald-500/30">
          completed
        </span>
      );
    case "running":
      return (
        <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-cyan-500/10 text-cyan-400 ring-cyan-500/30 animate-pulse">
          running
        </span>
      );
    case "queued":
      return (
        <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-slate-500/10 text-slate-400 ring-slate-500/30">
          queued
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-rose-500/10 text-rose-400 ring-rose-500/30">
          {status}
        </span>
      );
  }
}

function getToolDotColor(tool: string) {
  switch (tool.toLowerCase()) {
    case "subfinder":
      return "bg-cyan-400";
    case "httpx":
      return "bg-emerald-400";
    case "katana":
      return "bg-amber-400";
    case "nuclei":
      return "bg-rose-400";
    default:
      return "bg-purple-400";
  }
}

export default function ToolRunsPage() {
  const [runs, setRuns] = useState<ToolRunRaw[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const r = await api.listAllToolRuns();
        if (!cancelled) setRuns(r);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load.");
      } finally {
        if (!cancelled) setLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const totalRuns = runs.length;
  const completedRuns = runs.filter((r) => r.status === "completed").length;
  const runningRuns = runs.filter((r) => r.status === "running").length;
  const queuedRuns = runs.filter((r) => r.status === "queued").length;

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Tool Executions</h1>
        <p className="mt-1 text-sm text-slate-500">
          Execution status, run durations, and artifact outputs for security assessment utilities.
        </p>
      </header>

      {error && (
        <div className="mb-6 rounded-md border border-rose-500/30 bg-rose-500/5 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total Tool Runs" value={totalRuns} accent="cyan" />
        <StatCard label="Completed" value={completedRuns} accent="emerald" />
        <StatCard label="Running Now" value={runningRuns} accent="cyan" />
        <StatCard label="Queued in Pipeline" value={queuedRuns} accent="amber" />
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/50">
        <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
          Tool Execution History
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Tool Name</th>
                <th className="px-4 py-3 font-medium">Target Scope</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Started At</th>
                <th className="px-4 py-3 font-medium">Finished At</th>
                <th className="px-4 py-3 font-medium">Duration</th>
                <th className="px-4 py-3 font-medium">Results</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 bg-slate-950">
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-xs text-slate-600">
                    {loaded ? "No tool runs recorded yet." : "Loading…"}
                  </td>
                </tr>
              ) : (
                runs.map((run) => {
                  const duration = calculateDuration(run.started_at, run.finished_at);
                  return (
                    <tr key={run.id} className="hover:bg-slate-900/60 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className={`h-2 w-2 rounded-full ${getToolDotColor(run.tool_name)}`} />
                          <span className="font-mono text-sm font-medium text-slate-200">
                            {run.tool_name}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-300">{run.target}</td>
                      <td className="px-4 py-3">{getToolStatusBadge(run.status)}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {formatRelativeTime(run.started_at)}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {run.finished_at ? formatRelativeTime(run.finished_at) : "—"}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-slate-300">
                        {duration ? (
                          <span>{duration}</span>
                        ) : run.status === "running" ? (
                          <span className="text-cyan-400 animate-pulse">Running...</span>
                        ) : (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {run.result_count !== null ? (
                          <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-cyan-300">
                            {run.result_count} items
                          </span>
                        ) : (
                          <span className="text-xs text-slate-600">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
