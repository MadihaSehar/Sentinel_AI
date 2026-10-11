import { formatRelativeTime } from "@/lib/format";
import { StatCard } from "@/components/StatusBadges";

interface SubdomainItem {
  id: string;
  hostname: string;
  parentDomain: string;
  ipAddresses: string[];
  source: string;
  isAlive: boolean;
  httpStatus: number | null;
  discoveredAt: string;
}

const mockSubdomains: SubdomainItem[] = [
  {
    id: "s1",
    hostname: "api.example.com",
    parentDomain: "example.com",
    ipAddresses: ["93.184.216.35"],
    source: "subfinder",
    isAlive: true,
    httpStatus: 200,
    discoveredAt: "2026-10-09T09:14:00Z",
  },
  {
    id: "s2",
    hostname: "dev.example.com",
    parentDomain: "example.com",
    ipAddresses: ["93.184.216.36"],
    source: "subfinder",
    isAlive: true,
    httpStatus: 403,
    discoveredAt: "2026-10-09T09:14:30Z",
  },
  {
    id: "s3",
    hostname: "staging.example.com",
    parentDomain: "example.com",
    ipAddresses: ["93.184.216.37"],
    source: "dnsx",
    isAlive: false,
    httpStatus: null,
    discoveredAt: "2026-10-09T09:15:00Z",
  },
  {
    id: "s4",
    hostname: "mail.example.com",
    parentDomain: "example.com",
    ipAddresses: ["93.184.216.38"],
    source: "subfinder",
    isAlive: true,
    httpStatus: 200,
    discoveredAt: "2026-10-09T09:15:30Z",
  },
  {
    id: "s5",
    hostname: "admin.example.com",
    parentDomain: "example.com",
    ipAddresses: ["93.184.216.39"],
    source: "dnsx",
    isAlive: true,
    httpStatus: 401,
    discoveredAt: "2026-10-09T09:16:00Z",
  },
];

function getHttpStatusBadge(code: number | null) {
  if (code === null) {
    return <span className="rounded px-2 py-0.5 text-xs font-mono bg-slate-800 text-slate-500">None</span>;
  }
  if (code >= 200 && code < 300) {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-medium ring-1 bg-emerald-500/10 text-emerald-400 ring-emerald-500/30">
        {code}
      </span>
    );
  }
  if (code >= 300 && code < 500) {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-medium ring-1 bg-amber-500/10 text-amber-400 ring-amber-500/30">
        {code}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-medium ring-1 bg-rose-500/10 text-rose-400 ring-rose-500/30">
      {code}
    </span>
  );
}

export default function SubdomainsPage() {
  const total = mockSubdomains.length;
  const aliveCount = mockSubdomains.filter((s) => s.isAlive).length;
  const offlineCount = total - aliveCount;
  const sources = new Set(mockSubdomains.map((s) => s.source)).size;

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Discovered Subdomains</h1>
        <p className="mt-1 text-sm text-slate-500">
          Subdomain enumeration results with passive DNS and active resolution status.
        </p>
      </header>

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Discovered Subdomains" value={total} accent="cyan" />
        <StatCard label="Live Hosts" value={aliveCount} accent="emerald" />
        <StatCard label="Unreachable" value={offlineCount} accent="rose" />
        <StatCard label="Recon Sources" value={sources} accent="amber" />
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/50">
        <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
          Subdomain Records
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Hostname</th>
                <th className="px-4 py-3 font-medium">Parent Domain</th>
                <th className="px-4 py-3 font-medium">IP Address</th>
                <th className="px-4 py-3 font-medium">Source Tool</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">HTTP Status</th>
                <th className="px-4 py-3 font-medium">Discovered</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 bg-slate-950">
              {mockSubdomains.map((sub) => (
                <tr key={sub.id} className="hover:bg-slate-900/60 transition-colors">
                  <td className="px-4 py-3 font-mono text-sm font-medium text-cyan-300">
                    {sub.hostname}
                  </td>
                  <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                    {sub.parentDomain}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">
                    {sub.ipAddresses.join(", ")}
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-300 ring-1 ring-slate-700/60">
                      {sub.source}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`h-2 w-2 rounded-full ${
                          sub.isAlive ? "bg-emerald-400 ring-4 ring-emerald-500/20" : "bg-rose-500 ring-4 ring-rose-500/20"
                        }`}
                      />
                      <span className={`text-xs font-medium ${sub.isAlive ? "text-emerald-400" : "text-rose-400"}`}>
                        {sub.isAlive ? "Alive" : "Unreachable"}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3">{getHttpStatusBadge(sub.httpStatus)}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">
                    {formatRelativeTime(sub.discoveredAt)}
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
