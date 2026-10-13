"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { AssessmentType } from "@/lib/types";

/**
 * Mirrors section 3's required scope fields exactly: target, scope
 * pattern, assessment type, exclusions, rate limit, concurrency, and an
 * explicit authorization confirmation. The form cannot submit without
 * that checkbox — this is the UI half of the Authorization & Scope
 * Engine section 2's pipeline starts with; the backend must enforce the
 * same gate server-side regardless of what this form sends.
 */
export default function NewAssessmentPage() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [scopePattern, setScopePattern] = useState("");
  const [assessmentType, setAssessmentType] = useState<AssessmentType>("Bug Bounty");
  const [excludedDomains, setExcludedDomains] = useState("");
  const [excludedCidrs, setExcludedCidrs] = useState("");
  const [rateLimit, setRateLimit] = useState(5);
  const [concurrency, setConcurrency] = useState(10);
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = target.trim() !== "" && scopePattern.trim() !== "" && authorized;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      // Creates the assessment under the default project, confirms
      // authorization ("I CONFIRM AUTHORIZATION"), and starts the scan.
      const id = await api.createAndStartScan({
        target: target.trim(),
        assessmentType,
        scopePattern: scopePattern.trim(),
        excludedDomains: excludedDomains.split("\n").map((s) => s.trim()).filter(Boolean),
        excludedCidrs: excludedCidrs.split("\n").map((s) => s.trim()).filter(Boolean),
        rateLimit,
        concurrency,
      });
      router.push(`/assessments/${id}/live`);
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? `${err.status}: ${err.message}`
          : err instanceof Error
            ? err.message
            : "Failed to create assessment.";
      setError(msg);
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">New Assessment</h1>
        <p className="mt-1 text-sm text-slate-500">
          Every field here is enforced by the Scope Enforcement Layer before any active testing begins.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-300">Target</label>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com"
            className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-300">Scope pattern</label>
          <input
            value={scopePattern}
            onChange={(e) => setScopePattern(e.target.value)}
            placeholder="*.example.com"
            className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-300">Assessment type</label>
          <div className="flex gap-2">
            {(["Bug Bounty", "Pentest", "CTF", "Lab"] as AssessmentType[]).map((t) => (
              <button
                type="button"
                key={t}
                onClick={() => setAssessmentType(t)}
                className={`rounded-md px-3 py-1.5 text-sm ring-1 transition-colors ${
                  assessmentType === t
                    ? "bg-cyan-500/10 text-cyan-300 ring-cyan-500/40"
                    : "text-slate-400 ring-slate-800 hover:text-slate-200"
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="mb-1.5 block text-sm font-medium text-slate-300">
              Excluded domains
            </label>
            <textarea
              value={excludedDomains}
              onChange={(e) => setExcludedDomains(e.target.value)}
              placeholder={"admin.example.com"}
              rows={3}
              className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium text-slate-300">
              Excluded CIDRs
            </label>
            <textarea
              value={excludedCidrs}
              onChange={(e) => setExcludedCidrs(e.target.value)}
              placeholder={"10.0.0.0/8"}
              rows={3}
              className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="mb-1.5 block text-sm font-medium text-slate-300">
              Rate limit (req/sec)
            </label>
            <input
              type="number"
              min={1}
              value={rateLimit}
              onChange={(e) => setRateLimit(Number(e.target.value))}
              className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium text-slate-300">Concurrency</label>
            <input
              type="number"
              min={1}
              value={concurrency}
              onChange={(e) => setConcurrency(Number(e.target.value))}
              className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
            />
          </div>
        </div>

        <label className="flex items-start gap-3 rounded-md border border-amber-500/30 bg-amber-500/5 p-3">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
          />
          <span className="text-sm text-slate-300">
            I confirm I am authorized to perform active security testing against this target and
            scope, and that this assessment will not exceed the configured rate limit and scope
            rules.
          </span>
        </label>

        {error && (
          <div className="rounded-md border border-rose-500/30 bg-rose-500/5 px-3 py-2 text-sm text-rose-300">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={!canSubmit || submitting}
          className="w-full rounded-md bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 transition-colors hover:bg-cyan-400 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
        >
          {submitting ? "Creating…" : "Create Assessment"}
        </button>
      </form>
    </div>
  );
}
