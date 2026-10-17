"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { getLastAssessmentId } from "@/lib/api";

/**
 * Section 18's page list, in order. Items with `assessmentPath` are scoped to a
 * specific assessment; at render we point them at the most recently created
 * assessment (or New Assessment if there isn't one yet) rather than a
 * hard-coded demo id.
 */
const NAV_SECTIONS: {
  label: string;
  items: { href?: string; assessmentPath?: string; label: string }[];
}[] = [
  {
    label: "Overview",
    items: [
      { href: "/", label: "Dashboard" },
      { href: "/projects", label: "Projects" },
    ],
  },
  {
    label: "Assessment",
    items: [
      { href: "/assessments/new", label: "New Assessment" },
      { assessmentPath: "live", label: "Live Assessment" },
      { assessmentPath: "attack-surface", label: "Attack Surface" },
    ],
  },
  {
    label: "Discovery",
    items: [
      { href: "/assets", label: "Assets" },
      { href: "/subdomains", label: "Subdomains" },
      { href: "/endpoints", label: "Endpoints" },
      { href: "/technologies", label: "Technologies" },
    ],
  },
  {
    label: "Analysis",
    items: [
      { assessmentPath: "vulnerabilities", label: "Vulnerabilities" },
      { href: "/evidence", label: "Evidence" },
      { href: "/ai-analysis", label: "AI Analysis" },
      { href: "/tool-runs", label: "Tool Runs" },
      { href: "/payload-kb", label: "Payload Knowledge Base" },
    ],
  },
  {
    label: "Output",
    items: [
      { href: "/reports", label: "Reports" },
      { href: "/settings", label: "Settings" },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  const [lastId, setLastId] = useState<string | null>(null);

  // Resolve the latest assessment id on the client; re-check on navigation so
  // the links update right after a scan is created.
  useEffect(() => {
    setLastId(getLastAssessmentId());
  }, [pathname]);

  function resolveHref(item: { href?: string; assessmentPath?: string }): string {
    if (item.href) return item.href;
    if (item.assessmentPath) {
      return lastId ? `/assessments/${lastId}/${item.assessmentPath}` : "/assessments/new";
    }
    return "/";
  }

  return (
    <aside className="flex h-screen w-64 shrink-0 flex-col border-r border-slate-800 bg-slate-950">
      <div className="flex items-center gap-2 border-b border-slate-800 px-5 py-4">
        <div className="flex h-7 w-7 items-center justify-center rounded bg-cyan-500/10 text-cyan-400 ring-1 ring-cyan-500/30">
          <svg viewBox="0 0 24 24" fill="none" className="h-4 w-4">
            <path
              d="M12 2 4 5v6c0 5 3.4 8.7 8 9 4.6-.3 8-4 8-9V5l-8-3Z"
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <div>
          <div className="text-sm font-semibold tracking-wide text-slate-100">SentinelAI</div>
          <div className="text-[10px] uppercase tracking-wider text-slate-500">
            Security Platform
          </div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label} className="mb-5">
            <div className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
              {section.label}
            </div>
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const href = resolveHref(item);
                const active = pathname === href;
                return (
                  <Link
                    key={item.label}
                    href={href}
                    className={`block rounded-md px-2.5 py-1.5 text-sm transition-colors ${
                      active
                        ? "bg-cyan-500/10 text-cyan-300 ring-1 ring-cyan-500/20"
                        : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
                    }`}
                  >
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-slate-800 px-4 py-3 text-[11px] text-slate-600">
        Authorized assessments only.
      </div>
    </aside>
  );
}
