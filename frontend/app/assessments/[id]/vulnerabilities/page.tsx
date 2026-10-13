"use client";

import { useEffect, useMemo, useState } from "react";
import { SeverityBadge } from "@/components/SeverityBadge";
import { ConfidenceBar, ConsensusBadge, StatCard } from "@/components/StatusBadges";
import { SEVERITY_ORDER } from "@/lib/format";
import { api, type FindingRaw } from "@/lib/api";
import type { ConsensusStatus, Finding, Severity } from "@/lib/types";

const STATUS_FILTERS: (ConsensusStatus | "ALL")[] = [
  "ALL",
  "CONFIRMED",
  "REQUIRES_MANUAL_REVIEW",
  "NO_FINDING",
  "INSUFFICIENT_DATA",
];

function toFinding(r: FindingRaw): Finding {
  return {
    id: r.id,
    title: r.title,
    category: r.category,
    cwe: r.cwe,
    owasp: r.owasp,
    severity: r.severity as Severity,
    confidence: r.confidence,
    endpoint: r.endpoint,
    method: r.method,
    parameter: r.parameter,
    evidence: r.evidence,
    affectedAssets: r.affected_assets,
    recommendation: r.recommendation,
    references: r.references,
    consensusStatus: r.consensus_status as ConsensusStatus,
    agreementScore: r.agreement_score,
    modelCount: r.model_count,
    createdAt: r.created_at,
  };
}

export default function VulnerabilitiesPage({ params }: { params: { id: string } }) {
  const { id } = params;
  const [all, setAll] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [statusFilter, setStatusFilter] = useState<ConsensusStatus | "ALL">("ALL");
  const [selected, setSelected] = useState<Finding | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const rows = await api.getFindings(id);
        if (!cancelled) setAll(rows.map(toFinding));
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load.");
      } finally {
        if (!cancelled) setLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    all.forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    return counts;
  }, [all]);

  const findings = useMemo(() => {
    const filtered =
      statusFilter === "ALL" ? all : all.filter((f) => f.consensusStatus === statusFilter);
    return [...filtered].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );
  }, [all, statusFilter]);

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Vulnerabilities</h1>
        <p className="mt-1 text-sm text-slate-500">
          Every finding reflects the consensus verdict across AI provider models (when configured).
        </p>
      </header>

      {error && (
        <div className="mb-6 rounded-md border border-rose-500/30 bg-rose-500/5 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      <div className="mb-8 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        <StatCard label="Critical" value={severityCounts.critical} accent="rose" />
        <StatCard label="High" value={severityCounts.high} accent="orange" />
        <StatCard label="Medium" value={severityCounts.medium} accent="amber" />
        <StatCard label="Low" value={severityCounts.low} accent="cyan" />
        <StatCard label="Info" value={severityCounts.info} />
      </div>

      <div className="mb-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap gap-2">
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
              {s === "ALL" ? "All Statuses" : s.replace(/_/g, " ").toLowerCase()}
            </button>
          ))}
        </div>
        <div className="text-xs text-slate-500">
          Showing {findings.length} of {all.length} findings
        </div>
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/50">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Vulnerability Title</th>
                <th className="px-4 py-3 font-medium">Target Endpoint</th>
                <th className="px-4 py-3 font-medium">Consensus</th>
                <th className="px-4 py-3 font-medium">Confidence</th>
                <th className="px-4 py-3 font-medium">Models</th>
                <th className="px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 bg-slate-950">
              {findings.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-xs text-slate-600">
                    {loaded ? "No findings for this assessment yet." : "Loading…"}
                  </td>
                </tr>
              ) : (
                findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelected(f)}
                    className="cursor-pointer hover:bg-slate-900/60 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-200">
                      <div>{f.title}</div>
                      <div className="text-xs text-slate-500">{f.cwe ?? f.category}</div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">
                      <span className="text-slate-500">{f.method}</span> {f.endpoint}
                    </td>
                    <td className="px-4 py-3">
                      <ConsensusBadge status={f.consensusStatus} />
                    </td>
                    <td className="px-4 py-3">
                      <ConfidenceBar confidence={f.confidence} />
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      <span className="rounded bg-slate-800 px-2 py-0.5 font-medium text-slate-300">
                        {f.modelCount} models
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelected(f);
                        }}
                        className="rounded bg-cyan-500/10 px-2.5 py-1 text-xs font-medium text-cyan-300 ring-1 ring-cyan-500/20 hover:bg-cyan-500/20"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <div
          className="fixed inset-0 z-10 flex items-center justify-end bg-black/60 backdrop-blur-xs"
          onClick={() => setSelected(null)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="h-full w-full max-w-lg overflow-y-auto border-l border-slate-800 bg-slate-950 p-6 shadow-2xl"
          >
            <div className="mb-6 flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-lg font-semibold text-slate-100">{selected.title}</h2>
                <div className="mt-2 flex items-center gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <ConsensusBadge status={selected.consensusStatus} />
                </div>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="rounded p-1 text-slate-400 hover:bg-slate-900 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <dl className="space-y-4 text-sm">
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">Target Endpoint</dt>
                <dd className="mt-1 font-mono text-slate-300">
                  {selected.method} {selected.endpoint}
                  {selected.parameter ? ` (param: ${selected.parameter})` : ""}
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">
                  CWE / OWASP Category
                </dt>
                <dd className="mt-1 text-slate-300">
                  {selected.cwe ?? "—"} / {selected.owasp ?? "—"}
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">Consensus Metrics</dt>
                <dd className="mt-1 text-slate-300">
                  {Math.round(selected.confidence * 100)}% confidence ·{" "}
                  {Math.round(selected.agreementScore * 100)}% agreement score across{" "}
                  {selected.modelCount} AI models
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">Affected Assets</dt>
                <dd className="mt-1 flex flex-wrap gap-1">
                  {selected.affectedAssets.map((asset) => (
                    <span
                      key={asset}
                      className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-300"
                    >
                      {asset}
                    </span>
                  ))}
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">Evidence Log</dt>
                <dd className="mt-1 space-y-1.5">
                  {selected.evidence.map((e, i) => (
                    <div
                      key={i}
                      className="rounded border border-slate-800 bg-slate-900 px-3 py-2 font-mono text-xs text-slate-300"
                    >
                      {e}
                    </div>
                  ))}
                </dd>
              </div>
              <div>
                <dt className="text-xs uppercase tracking-wider text-slate-500">
                  Remediation Recommendation
                </dt>
                <dd className="mt-1 rounded bg-slate-900/60 p-3 text-slate-300">
                  {selected.recommendation}
                </dd>
              </div>
              {selected.references.length > 0 && (
                <div>
                  <dt className="text-xs uppercase tracking-wider text-slate-500">References</dt>
                  <dd className="mt-1 space-y-1">
                    {selected.references.map((ref, idx) => (
                      <a
                        key={idx}
                        href={ref}
                        target="_blank"
                        rel="noreferrer"
                        className="block truncate text-xs text-cyan-400 hover:underline"
                      >
                        {ref}
                      </a>
                    ))}
                  </dd>
                </div>
              )}
            </dl>
          </div>
        </div>
      )}
    </div>
  );
}
