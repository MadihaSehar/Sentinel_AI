"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

/** Section 18's page list, in order. Stub pages render "coming soon" until their phase lands. */
const NAV_SECTIONS: { label: string; items: { href: string; label: string }[] }[] = [
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
      { href: "/assessments/a1b2c3/live", label: "Live Assessment" },
      { href: "/assessments/a1b2c3/attack-surface", label: "Attack Surface" },
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
      { href: "/assessments/a1b2c3/vulnerabilities", label: "Vulnerabilities" },
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
                const active = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
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
