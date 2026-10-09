"use client";

import { useMemo, useState } from "react";
import { SeverityBadge } from "@/components/SeverityBadge";
import { ConfidenceBar, ConsensusBadge } from "@/components/StatusBadges";
import { SEVERITY_ORDER } from "@/lib/format";
import { mockFindings } from "@/lib/mock-data";
import type { ConsensusStatus, Finding } from "@/lib/types";

const STATUS_FILTERS: (ConsensusStatus | "ALL")[] = [
  "ALL",
  "CONFIRMED",
  "REQUIRES_MANUAL_REVIEW",
  "NO_FINDING",
  "INSUFFICIENT_DATA",
];

export default function VulnerabilitiesPage() {
  const [statusFilter, setStatusFilter] = useState<ConsensusStatus | "ALL">("ALL");
  const [selected, setSelected] = useState<Finding | null>(null);

  const findings = useMemo(() => {
    const filtered =
      statusFilter === "ALL" ? mockFindings : mockFindings.filter((f) => f.consensusStatus === statusFilter);
    return [...filtered].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );
  }, [statusFilter]);

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Vulnerabilities</h1>
        <p className="mt-1 text-sm text-slate-500">
          Every row reflects Phase 10&apos;s consensus verdict across providers — not a single
          model&apos;s opinion.
        </p>
      </header>

      <div className="mb-4 flex gap-2">
        {STATUS_FILTERS.map((s) => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={`rounded-md px-3 py-1.5 text-xs font-medium ring-1 transition-colors ${
              statusFilter === s
                ? "bg-cyan-500/10 text-cyan-300 ring-cyan-500/40"
                : "text-slate-400 ring-slate-800 hover:text-slate-200"
            }`}
          >
            {s === "ALL" ? "All" : s.replace(/_/g, " ").toLowerCase()}
          </button>
        ))}
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/70 text-left text-xs uppercase tracking-wider text-slate-500">
              <th className="px-4 py-2.5 font-medium">Finding</th>
              <th className="px-4 py-2.5 font-medium">Severity</th>
              <th className="px-4 py-2.5 font-medium">Endpoint</th>
              <th className="px-4 py-2.5 font-medium">Consensus</th>
              <th className="px-4 py-2.5 font-medium">Confidence</th>
              <th className="px-4 py-2.5 font-medium">Models</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 bg-slate-950">
            {findings.map((f) => (
              <tr
                key={f.id}
                onClick={() => setSelected(f)}
                className="cursor-pointer hover:bg-slate-900/60"
              >
                <td className="px-4 py-3 text-slate-200">{f.title}</td>
                <td className="px-4 py-3">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">
                  {f.method} {f.endpoint}
                </td>
                <td className="px-4 py-3">
                  <ConsensusBadge status={f.consensusStatus} />
                </td>
                <td className="px-4 py-3">
                  <ConfidenceBar confidence={f.confidence} />
                </td>
                <td className="px-4 py-3 text-xs text-slate-500">{f.modelCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <div
          className="fixed inset-0 z-10 flex items-center justify-end bg-black/50"
          onClick={() => setSelected(null)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="h-full w-full max-w-lg overflow-y-auto border-l border-slate-800 bg-slate-950 p-6"
          >
            <div className="mb-4 flex items-start justify-between">
              <div>
                <h2 className="text-lg font-semibold text-slate-100">{selected.title}</h2>
                <div className="mt-1 flex items-center gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <ConsensusBadge status={selected.consensusStatus} />
                </div>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="text-slate-500 hover:text-slate-300"
              >
                ✕
              </button>
            </div>

            <dl className="space-y-4 text-sm">
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">Endpoint</dt>
                <dd className="mt-1 font-mono text-slate-300">
                  {selected.method} {selected.endpoint}
                  {selected.parameter ? ` (param: ${selected.parameter})` : ""}
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">
                  CWE / OWASP
                </dt>
                <dd className="mt-1 text-slate-300">
                  {selected.cwe ?? "—"} / {selected.owasp ?? "—"}
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">
                  Consensus confidence / agreement
                </dt>
                <dd className="mt-1 text-slate-300">
                  {Math.round(selected.confidence * 100)}% confidence ·{" "}
                  {Math.round(selected.agreementScore * 100)}% agreement across{" "}
                  {selected.modelCount} model(s)
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">Evidence</dt>
                <dd className="mt-1 space-y-1">
                  {selected.evidence.map((e, i) => (
                    <div key={i} className="rounded bg-slate-900 px-2.5 py-1.5 text-xs text-slate-400">
                      {e}
                    </div>
                  ))}
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">
                  Recommendation
                </dt>
                <dd className="mt-1 text-slate-300">{selected.recommendation}</dd>
              </div>
            </dl>
          </div>
        </div>
      )}
    </div>
  );
}
