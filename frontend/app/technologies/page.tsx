import { ConfidenceBar, StatCard } from "@/components/StatusBadges";

interface TechnologyItem {
  name: string;
  version: string | null;
  category: string;
  hosts: string[];
  confidence: number;
}

const mockTechnologies: TechnologyItem[] = [
  {
    name: "nginx",
    version: "1.24.0",
    category: "Web Server",
    hosts: ["example.com", "api.example.com"],
    confidence: 0.95,
  },
  {
    name: "React",
    version: "18.2",
    category: "JavaScript Framework",
    hosts: ["example.com"],
    confidence: 0.9,
  },
  {
    name: "FastAPI",
    version: "0.115",
    category: "Web Framework",
    hosts: ["api.example.com"],
    confidence: 0.85,
  },
  {
    name: "PostgreSQL",
    version: null,
    category: "Database",
    hosts: ["api.example.com"],
    confidence: 0.7,
  },
  {
    name: "Express",
    version: "4.18",
    category: "Web Framework",
    hosts: ["dev.example.com"],
    confidence: 0.8,
  },
  {
    name: "Cloudflare",
    version: null,
    category: "CDN",
    hosts: ["example.com"],
    confidence: 0.95,
  },
  {
    name: "jQuery",
    version: "3.6.0",
    category: "JavaScript Library",
    hosts: ["example.com"],
    confidence: 0.85,
  },
  {
    name: "Bootstrap",
    version: "5.3",
    category: "CSS Framework",
    hosts: ["example.com", "dev.example.com"],
    confidence: 0.9,
  },
];

function getCategoryColor(category: string) {
  if (category.includes("Server") || category.includes("CDN")) {
    return "bg-cyan-500/10 text-cyan-400 ring-cyan-500/30";
  }
  if (category.includes("Framework")) {
    return "bg-emerald-500/10 text-emerald-400 ring-emerald-500/30";
  }
  if (category.includes("Database")) {
    return "bg-amber-500/10 text-amber-400 ring-amber-500/30";
  }
  return "bg-purple-500/10 text-purple-400 ring-purple-500/30";
}

export default function TechnologiesPage() {
  const total = mockTechnologies.length;
  const versionsCount = mockTechnologies.filter((t) => t.version !== null).length;
  const uniqueCategories = new Set(mockTechnologies.map((t) => t.category)).size;
  const avgConfidence = Math.round(
    (mockTechnologies.reduce((acc, t) => acc + t.confidence, 0) / total) * 100
  );

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Fingerprinted Technologies</h1>
        <p className="mt-1 text-sm text-slate-500">
          Software stacks, frameworks, web servers, and third-party libraries identified across targets.
        </p>
      </header>

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Detected Technologies" value={total} accent="cyan" />
        <StatCard label="Identified Versions" value={versionsCount} accent="emerald" />
        <StatCard label="Tech Categories" value={uniqueCategories} accent="amber" />
        <StatCard label="Avg Confidence" value={`${avgConfidence}%`} accent="cyan" />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {mockTechnologies.map((tech) => (
          <div
            key={tech.name}
            className="flex flex-col justify-between rounded-lg border border-slate-800 bg-slate-900/50 p-5 transition-colors hover:border-slate-700"
          >
            <div>
              <div className="flex items-start justify-between gap-2">
                <h3 className="text-lg font-semibold text-slate-100">{tech.name}</h3>
                <span
                  className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium ring-1 ${getCategoryColor(
                    tech.category
                  )}`}
                >
                  {tech.category}
                </span>
              </div>

              <div className="mt-2 flex items-center gap-2">
                <span className="text-xs text-slate-500">Version:</span>
                <span className="font-mono text-xs text-slate-300">
                  {tech.version ? `v${tech.version}` : "Unspecified"}
                </span>
              </div>

              <div className="mt-3">
                <div className="text-xs text-slate-500 mb-1.5">
                  Affected Hosts ({tech.hosts.length}):
                </div>
                <div className="flex flex-wrap gap-1">
                  {tech.hosts.map((host) => (
                    <span
                      key={host}
                      className="rounded bg-slate-800/80 px-2 py-0.5 font-mono text-[11px] text-slate-400"
                    >
                      {host}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-5 border-t border-slate-800/80 pt-3">
              <div className="text-xs text-slate-500 mb-1">Detection Confidence</div>
              <ConfidenceBar confidence={tech.confidence} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
