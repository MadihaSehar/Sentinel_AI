"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, type AssessmentRaw } from "@/lib/api";

export default function ProjectsPage() {
  const [assessments, setAssessments] = useState<AssessmentRaw[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const a = await api.listAssessments();
        if (!cancelled) setAssessments(a);
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

      {error && (
        <div className="mb-6 rounded-md border border-rose-500/30 bg-rose-500/5 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      <div className="overflow-hidden rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/70 text-left text-xs uppercase tracking-wider text-slate-500">
              <th className="px-4 py-2.5 font-medium">Target</th>
              <th className="px-4 py-2.5 font-medium">Type</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70 bg-slate-950">
            {assessments.length === 0 ? (
              <tr>
                <td colSpan={3} className="px-4 py-6 text-center text-xs text-slate-600">
                  {loaded ? "No assessments yet. Create one to get started." : "Loading…"}
                </td>
              </tr>
            ) : (
              assessments.map((a) => (
                <tr key={a.id} className="hover:bg-slate-900/60">
                  <td className="px-4 py-3">
                    <Link
                      href={`/assessments/${a.id}/live`}
                      className="text-cyan-400 hover:underline"
                    >
                      {a.target}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-slate-400">{a.assessment_type}</td>
                  <td className="px-4 py-3 text-slate-400">{a.status}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
