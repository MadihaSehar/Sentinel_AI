import Link from "next/link";
import { mockAssessments } from "@/lib/mock-data";

export default function ProjectsPage() {
  return (
    <div className="p-8">
      <header className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Projects</h1>
          <p className="mt-1 text-sm text-slate-500">Every assessment, across every target.</p>
        </div>
        <Link
          href="/assessments/new"
          className="rounded-md bg-cyan-500 px-3 py-1.5 text-sm font-medium text-slate-950 hover:bg-cyan-400"
        >
          New Assessment
        </Link>
      </header>

      <div className="overflow-hidden rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/70 text-left text-xs uppercase tracking-wider text-slate-500">
              <th className="px-4 py-2.5 font-medium">Target</th>
              <th className="px-4 py-2.5 font-medium">Type</th>
              <th className="px-4 py-2.5 font-medium">State</th>
              <th className="px-4 py-2.5 font-medium">Findings</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 bg-slate-950">
            {mockAssessments.map((a) => (
              <tr key={a.id} className="hover:bg-slate-900/60">
                <td className="px-4 py-3">
                  <Link href={`/assessments/${a.id}/live`} className="text-cyan-400 hover:underline">
                    {a.target}
                  </Link>
                </td>
                <td className="px-4 py-3 text-slate-400">{a.assessmentType}</td>
                <td className="px-4 py-3 text-slate-400">{a.state}</td>
                <td className="px-4 py-3 text-slate-400">
                  {Object.values(a.findingsCount).reduce((a, b) => a + b, 0)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
