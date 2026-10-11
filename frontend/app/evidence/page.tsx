import { mockFindings } from "@/lib/mock-data";
import { SeverityBadge } from "@/components/SeverityBadge";
import { ConfidenceBar, StatCard } from "@/components/StatusBadges";

export default function EvidencePage() {
  const flattenedEvidence = mockFindings.flatMap((finding) =>
    finding.evidence.map((evidenceItem, index) => ({
      id: `${finding.id}-ev-${index}`,
      findingTitle: finding.title,
      severity: finding.severity,
      endpoint: `${finding.method} ${finding.endpoint}${finding.parameter ? ` (?${finding.parameter})` : ""}`,
      confidence: finding.confidence,
      evidence: evidenceItem,
      modelCount: finding.modelCount,
    }))
  );

  const totalEvidence = flattenedEvidence.length;
  const verifiedFindings = mockFindings.length;
  const uniqueEndpoints = new Set(mockFindings.map((f) => f.endpoint)).size;

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Vulnerability Evidence</h1>
        <p className="mt-1 text-sm text-slate-500">
          Raw observation records, HTTP response signatures, and proof-of-concept indicators.
        </p>
      </header>

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Evidence Artifacts" value={totalEvidence} accent="cyan" />
        <StatCard label="Associated Findings" value={verifiedFindings} accent="rose" />
        <StatCard label="Affected Endpoints" value={uniqueEndpoints} accent="amber" />
        <StatCard label="Avg Confidence" value="82%" accent="emerald" />
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/50">
        <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
          Discovered Evidence Trail
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Finding Title</th>
                <th className="px-4 py-3 font-medium">Evidence Description</th>
                <th className="px-4 py-3 font-medium">Related Endpoint</th>
                <th className="px-4 py-3 font-medium">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 bg-slate-950">
              {flattenedEvidence.map((item) => (
                <tr key={item.id} className="hover:bg-slate-900/60 transition-colors">
                  <td className="px-4 py-3 align-top">
                    <SeverityBadge severity={item.severity} />
                  </td>
                  <td className="px-4 py-3 font-medium text-slate-200 align-top">
                    {item.findingTitle}
                  </td>
                  <td className="px-4 py-3 align-top">
                    <div className="rounded border border-slate-800 bg-slate-900/80 px-3 py-2 font-mono text-xs text-cyan-300">
                      {item.evidence}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300 align-top">
                    {item.endpoint}
                  </td>
                  <td className="px-4 py-3 align-top">
                    <ConfidenceBar confidence={item.confidence} />
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
