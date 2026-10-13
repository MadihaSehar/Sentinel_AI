"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { StatCard } from "@/components/StatusBadges";
import { SeverityBadge } from "@/components/SeverityBadge";
import { formatRelativeTime } from "@/lib/format";
import { api, type AssessmentRaw, type FindingRaw } from "@/lib/api";
import type { Severity } from "@/lib/types";

const RUNNING_STATES = new Set(["running", "queued"]);

export default function DashboardPage() {
  const [assessments, setAssessments] = useState<AssessmentRaw[]>([]);
  const [findings, setFindings] = useState<FindingRaw[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [a, f] = await Promise.all([api.listAssessments(), api.listAllFindings()]);
        if (!cancelled) {
          setAssessments(a);
          setFindings(f);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const running = assessments.filter((a) => RUNNING_STATES.has(a.status)).length;
  const totals = findings.reduce(
    (acc, f) => {
      if (f.severity === "critical") acc.critical += 1;
      else if (f.severity === "high") acc.high += 1;
      else if (f.severity === "medium") acc.medium += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0 }
  );

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Dashboard</h1>
        <p className="mt-1 text-sm text-slate-500">Overview across all authorized assessments.</p>
      </header>

      {error && (
        <div className="mb-6 rounded-md border border-rose-500/30 bg-rose-500/5 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard label="Assessments" value={assessments.length} />
        <StatCard label="Running Now" value={running} accent="cyan" />
        <StatCard label="Critical Findings" value={totals.critical} accent="rose" />
        <StatCard label="High Findings" value={totals.high} accent="orange" />
        <StatCard label="Medium Findings" value={totals.medium} accent="amber" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section className="rounded-lg border border-slate-800 bg-slate-900/50">
          <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
            Assessments
          </div>
          <div className="divide-y divide-slate-800/70">
            {assessments.length === 0 ? (
              <div className="px-4 py-6 text-center text-xs text-slate-600">
                No assessments yet. Start one from New Assessment.
              </div>
            ) : (
              assessments.map((a) => (
                <Link
                  key={a.id}
                  href={`/assessments/${a.id}/live`}
                  className="flex items-center justify-between px-4 py-3 hover:bg-slate-900"
                >
                  <div>
                    <div className="text-sm font-medium text-slate-200">{a.target}</div>
                    <div className="text-xs text-slate-500">
                      {a.assessment_type} · created {formatRelativeTime(a.created_at)}
                    </div>
                  </div>
                  <span
                    className={`rounded px-2 py-0.5 text-xs font-medium ${
                      RUNNING_STATES.has(a.status)
                        ? "bg-cyan-500/10 text-cyan-400"
                        : a.status === "completed"
                          ? "bg-emerald-500/10 text-emerald-400"
                          : "bg-slate-500/10 text-slate-400"
                    }`}
                  >
                    {a.status}
                  </span>
                </Link>
              ))
            )}
          </div>
        </section>

        <section className="rounded-lg border border-slate-800 bg-slate-900/50">
          <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
            Recent Findings
          </div>
          <div className="divide-y divide-slate-800/70">
            {findings.length === 0 ? (
              <div className="px-4 py-6 text-center text-xs text-slate-600">
                No findings yet. They appear here as scans confirm them.
              </div>
            ) : (
              findings.slice(0, 15).map((f) => (
                <div key={f.id} className="flex items-center justify-between px-4 py-3">
                  <div>
                    <div className="text-sm text-slate-200">{f.title}</div>
                    <div className="text-xs text-slate-500">
                      {f.endpoint} · {formatRelativeTime(f.created_at)}
                    </div>
                  </div>
                  <SeverityBadge severity={f.severity as Severity} />
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
