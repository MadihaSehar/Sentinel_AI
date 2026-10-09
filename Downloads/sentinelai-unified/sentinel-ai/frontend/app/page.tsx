import Link from "next/link";
import { StatCard } from "@/components/StatusBadges";
import { SeverityBadge } from "@/components/SeverityBadge";
import { formatRelativeTime } from "@/lib/format";
import { mockAssessments, mockFindings } from "@/lib/mock-data";

export default function DashboardPage() {
  const running = mockAssessments.filter((a) => a.state === "running").length;
  const totals = mockAssessments.reduce(
    (acc, a) => {
      acc.critical += a.findingsCount.critical;
      acc.high += a.findingsCount.high;
      acc.medium += a.findingsCount.medium;
      return acc;
    },
    { critical: 0, high: 0, medium: 0 }
  );

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Dashboard</h1>
        <p className="mt-1 text-sm text-slate-500">
          Overview across all authorized assessments.
        </p>
      </header>

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard label="Assessments" value={mockAssessments.length} />
        <StatCard label="Running Now" value={running} accent="cyan" />
        <StatCard label="Critical Findings" value={totals.critical} accent="rose" />
        <StatCard label="High Findings" value={totals.high} accent="orange" />
        <StatCard label="Medium Findings" value={totals.medium} accent="amber" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section className="rounded-lg border border-slate-800 bg-slate-900/50">
          <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
            Active Assessments
          </div>
          <div className="divide-y divide-slate-800/70">
            {mockAssessments.map((a) => (
              <Link
                key={a.id}
                href={`/assessments/${a.id}/live`}
                className="flex items-center justify-between px-4 py-3 hover:bg-slate-900"
              >
                <div>
                  <div className="text-sm font-medium text-slate-200">{a.target}</div>
                  <div className="text-xs text-slate-500">
                    {a.assessmentType} · started {a.startedAt ? formatRelativeTime(a.startedAt) : "—"}
                  </div>
                </div>
                <span
                  className={`rounded px-2 py-0.5 text-xs font-medium ${
                    a.state === "running"
                      ? "bg-cyan-500/10 text-cyan-400"
                      : a.state === "completed"
                        ? "bg-emerald-500/10 text-emerald-400"
                        : "bg-slate-500/10 text-slate-400"
                  }`}
                >
                  {a.state}
                </span>
              </Link>
            ))}
          </div>
        </section>

        <section className="rounded-lg border border-slate-800 bg-slate-900/50">
          <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
            Recent Findings
          </div>
          <div className="divide-y divide-slate-800/70">
            {mockFindings.map((f) => (
              <div key={f.id} className="flex items-center justify-between px-4 py-3">
                <div>
                  <div className="text-sm text-slate-200">{f.title}</div>
                  <div className="text-xs text-slate-500">
                    {f.endpoint} · {formatRelativeTime(f.createdAt)}
                  </div>
                </div>
                <SeverityBadge severity={f.severity} />
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
