"use client";

import { useMemo, useState } from "react";
import { StatCard } from "@/components/StatusBadges";

interface PayloadCategory {
  name: string;
  count: number;
  riskLevel: "critical" | "high" | "medium" | "low";
  description: string;
}

const categories: PayloadCategory[] = [
  {
    name: "XSS",
    count: 127,
    riskLevel: "high",
    description: "Cross-Site Scripting payloads for HTML, attribute, and JavaScript contexts",
  },
  {
    name: "SQL Injection",
    count: 89,
    riskLevel: "critical",
    description: "SQL injection payloads for MySQL, PostgreSQL, MSSQL, Oracle, SQLite",
  },
  {
    name: "Command Injection",
    count: 45,
    riskLevel: "critical",
    description: "OS command injection for Linux and Windows",
  },
  {
    name: "SSRF",
    count: 34,
    riskLevel: "high",
    description: "Server-Side Request Forgery payloads",
  },
  {
    name: "LFI/Path Traversal",
    count: 56,
    riskLevel: "high",
    description: "Local File Inclusion and path traversal payloads",
  },
  {
    name: "SSTI",
    count: 28,
    riskLevel: "high",
    description: "Server-Side Template Injection for Jinja2, Twig, Freemarker",
  },
  {
    name: "XXE",
    count: 19,
    riskLevel: "medium",
    description: "XML External Entity payloads",
  },
  {
    name: "Open Redirect",
    count: 23,
    riskLevel: "medium",
    description: "URL redirect bypass techniques",
  },
  {
    name: "CORS",
    count: 15,
    riskLevel: "medium",
    description: "CORS misconfiguration test payloads",
  },
  {
    name: "JWT",
    count: 21,
    riskLevel: "high",
    description: "JWT attack payloads: none alg, key confusion, claim tampering",
  },
  {
    name: "CSRF",
    count: 18,
    riskLevel: "medium",
    description: "Cross-Site Request Forgery techniques",
  },
  {
    name: "IDOR/BOLA",
    count: 12,
    riskLevel: "high",
    description: "Insecure Direct Object Reference test patterns",
  },
];

function getRiskBadge(risk: "critical" | "high" | "medium" | "low") {
  switch (risk) {
    case "critical":
      return (
        <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-rose-500/10 text-rose-400 ring-rose-500/30">
          critical risk
        </span>
      );
    case "high":
      return (
        <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-orange-500/10 text-orange-400 ring-orange-500/30">
          high risk
        </span>
      );
    case "medium":
      return (
        <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-amber-500/10 text-amber-400 ring-amber-500/30">
          medium risk
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-sky-500/10 text-sky-400 ring-sky-500/30">
          low risk
        </span>
      );
  }
}

export default function PayloadKbPage() {
  const [search, setSearch] = useState("");
  const [selectedRisk, setSelectedRisk] = useState<string>("all");

  const totalPayloads = useMemo(
    () => categories.reduce((acc, cat) => acc + cat.count, 0),
    []
  );
  const criticalCount = categories.filter((c) => c.riskLevel === "critical").length;
  const highCount = categories.filter((c) => c.riskLevel === "high").length;

  const filteredCategories = useMemo(() => {
    return categories.filter((cat) => {
      const matchesSearch =
        cat.name.toLowerCase().includes(search.toLowerCase()) ||
        cat.description.toLowerCase().includes(search.toLowerCase());
      const matchesRisk = selectedRisk === "all" || cat.riskLevel === selectedRisk;
      return matchesSearch && matchesRisk;
    });
  }, [search, selectedRisk]);

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Payload Knowledge Base</h1>
        <p className="mt-1 text-sm text-slate-500">
          Curated corpus of security testing payloads, fuzz vectors, and exploit heuristics.
        </p>
      </header>

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total Payloads" value={totalPayloads} accent="cyan" />
        <StatCard label="Attack Vectors" value={categories.length} accent="emerald" />
        <StatCard label="Critical Vectors" value={criticalCount} accent="rose" />
        <StatCard label="High Vectors" value={highCount} accent="orange" />
      </div>

      {/* Search and Filter bar */}
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="relative flex-1 max-w-md">
          <input
            type="text"
            placeholder="Search payload categories, techniques, keywords..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-md border border-slate-800 bg-slate-900/80 px-3.5 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-hidden focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        <div className="flex flex-wrap gap-2">
          {["all", "critical", "high", "medium"].map((risk) => (
            <button
              key={risk}
              onClick={() => setSelectedRisk(risk)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium ring-1 transition-colors capitalize ${
                selectedRisk === risk
                  ? "bg-cyan-500/10 text-cyan-300 ring-cyan-500/40"
                  : "text-slate-400 ring-slate-800 hover:text-slate-200"
              }`}
            >
              {risk === "all" ? "All Risks" : `${risk} risk`}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {filteredCategories.map((cat) => (
          <div
            key={cat.name}
            className="flex flex-col justify-between rounded-lg border border-slate-800 bg-slate-900/50 p-5 transition-colors hover:border-slate-700"
          >
            <div>
              <div className="flex items-start justify-between gap-2">
                <h3 className="text-base font-semibold text-slate-100">{cat.name}</h3>
                {getRiskBadge(cat.riskLevel)}
              </div>
              <p className="mt-2 text-xs leading-relaxed text-slate-400">
                {cat.description}
              </p>
            </div>

            <div className="mt-5 flex items-center justify-between border-t border-slate-800/80 pt-3">
              <span className="text-xs text-slate-500">Payload Count</span>
              <span className="font-mono text-xs font-semibold text-cyan-400">
                {cat.count} templates
              </span>
            </div>
          </div>
        ))}
      </div>

      {filteredCategories.length === 0 && (
        <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">
          No payload categories match the filter criteria.
        </div>
      )}
    </div>
  );
}
