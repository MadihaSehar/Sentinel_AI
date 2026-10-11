import { formatRelativeTime } from "@/lib/format";
import { reportUrl } from "@/lib/api";
import { StatCard } from "@/components/StatusBadges";
import type { Severity } from "@/lib/types";

interface ReportItem {
  id: string;
  title: string;
  assessmentTarget: string;
  createdAt: string;
  format: "HTML" | "PDF" | "JSON";
  findingsCount: Record<Severity, number>;
  status: "completed" | "generating" | "failed";
}

const mockReports: ReportItem[] = [
  {
    id: "r1",
    title: "Security Assessment - example.com",
    assessmentTarget: "example.com",
    createdAt: "2026-10-09T15:22:00Z",
    format: "HTML",
    findingsCount: { critical: 0, high: 2, medium: 4, low: 6, info: 3 },
    status: "completed",
  },
  {
    id: "r2",
    title: "Penetration Test - juice-shop.local",
    assessmentTarget: "juice-shop.local",
    createdAt: "2026-10-08T15:22:00Z",
    format: "PDF",
    findingsCount: { critical: 1, high: 3, medium: 5, low: 2, info: 1 },
    status: "completed",
  },
];

function getFormatBadge(format: string) {
  if (format === "PDF") {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-medium ring-1 bg-rose-500/10 text-rose-400 ring-rose-500/30">
        PDF
      </span>
    );
  }
  if (format === "HTML") {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-medium ring-1 bg-amber-500/10 text-amber-400 ring-amber-500/30">
        HTML
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-medium ring-1 bg-cyan-500/10 text-cyan-400 ring-cyan-500/30">
      {format}
    </span>
  );
}

function MiniSeverityCounts({ counts }: { counts: Record<Severity, number> }) {
  return (
    <div className="flex flex-wrap items-center gap-1.5 font-mono text-xs">
      {counts.critical > 0 && (
        <span className="rounded bg-rose-500/10 px-1.5 py-0.5 font-semibold text-rose-400 ring-1 ring-rose-500/20">
          C: {counts.critical}
        </span>
      )}
      {counts.high > 0 && (
        <span className="rounded bg-orange-500/10 px-1.5 py-0.5 font-semibold text-orange-400 ring-1 ring-orange-500/20">
          H: {counts.high}
        </span>
      )}
      {counts.medium > 0 && (
        <span className="rounded bg-amber-500/10 px-1.5 py-0.5 font-semibold text-amber-400 ring-1 ring-amber-500/20">
          M: {counts.medium}
        </span>
      )}
      {counts.low > 0 && (
        <span className="rounded bg-sky-500/10 px-1.5 py-0.5 font-semibold text-sky-400 ring-1 ring-sky-500/20">
          L: {counts.low}
        </span>
      )}
      {counts.info > 0 && (
        <span className="rounded bg-slate-500/10 px-1.5 py-0.5 font-semibold text-slate-400 ring-1 ring-slate-500/20">
          I: {counts.info}
        </span>
      )}
    </div>
  );
}

export default function ReportsPage() {
  const totalReports = mockReports.length;
  const pdfCount = mockReports.filter((r) => r.format === "PDF").length;
  const htmlCount = mockReports.filter((r) => r.format === "HTML").length;
  const totalFindings = mockReports.reduce(
    (acc, r) =>
      acc +
      Object.values(r.findingsCount).reduce((sum, v) => sum + v, 0),
    0
  );

  return (
    <div className="p-8">
      <header className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Assessment Reports</h1>
          <p className="mt-1 text-sm text-slate-500">
            Exported compliance, executive, and technical vulnerability dossiers.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <a
            href={reportUrl("/reports/sample", "html")}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-md border border-slate-700 bg-slate-800 px-3.5 py-1.5 text-sm font-medium text-slate-200 hover:bg-slate-700 transition-colors"
          >
            View Sample (HTML)
          </a>
          <a
            href={reportUrl("/reports/diff/sample")}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-md border border-slate-700 bg-slate-800 px-3.5 py-1.5 text-sm font-medium text-slate-200 hover:bg-slate-700 transition-colors"
          >
            Sample Diff
          </a>
          <a
            href={reportUrl("/reports/sample", "sarif")}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-md border border-slate-700 bg-slate-800 px-3.5 py-1.5 text-sm font-medium text-slate-200 hover:bg-slate-700 transition-colors"
          >
            SARIF
          </a>
          <a
            href={reportUrl("/reports/sample", "pdf")}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-md bg-cyan-500 px-3.5 py-1.5 text-sm font-medium text-slate-950 hover:bg-cyan-400 transition-colors"
          >
            Download Sample (PDF)
          </a>
        </div>
      </header>

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total Reports" value={totalReports} accent="cyan" />
        <StatCard label="PDF Dossiers" value={pdfCount} accent="rose" />
        <StatCard label="HTML Reports" value={htmlCount} accent="amber" />
        <StatCard label="Documented Findings" value={totalFindings} accent="emerald" />
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/50">
        <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
          Generated Security Reports
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Report Title</th>
                <th className="px-4 py-3 font-medium">Assessment Target</th>
                <th className="px-4 py-3 font-medium">Date Generated</th>
                <th className="px-4 py-3 font-medium">Format</th>
                <th className="px-4 py-3 font-medium">Findings Breakdown</th>
                <th className="px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 bg-slate-950">
              {mockReports.map((report) => (
                <tr key={report.id} className="hover:bg-slate-900/60 transition-colors">
                  <td className="px-4 py-3 font-medium text-slate-200">
                    <div className="flex items-center gap-2">
                      <svg
                        className="h-4 w-4 text-cyan-400 shrink-0"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                        strokeWidth="1.8"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                        />
                      </svg>
                      <span>{report.title}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">
                    {report.assessmentTarget}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400">
                    {formatRelativeTime(report.createdAt)}
                  </td>
                  <td className="px-4 py-3">{getFormatBadge(report.format)}</td>
                  <td className="px-4 py-3">
                    <MiniSeverityCounts counts={report.findingsCount} />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <a
                      href={reportUrl("/reports/sample", report.format === "PDF" ? "pdf" : "html")}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 rounded bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 ring-1 ring-slate-700 hover:bg-slate-700 hover:text-white transition-colors"
                    >
                      <svg
                        className="h-3.5 w-3.5 text-slate-400"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                        strokeWidth="2"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                        />
                      </svg>
                      Download
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
