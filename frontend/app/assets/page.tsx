import { mockAssets } from "@/lib/mock-data";
import { formatRelativeTime } from "@/lib/format";
import { StatCard } from "@/components/StatusBadges";

function getStatusBadge(code: number | null) {
  if (code === null) {
    return <span className="rounded px-2 py-0.5 text-xs font-mono bg-slate-800 text-slate-400">N/A</span>;
  }
  if (code >= 200 && code < 300) {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-medium ring-1 bg-emerald-500/10 text-emerald-400 ring-emerald-500/30">
        {code} OK
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

export default function AssetsPage() {
  const totalAssets = mockAssets.length;
  const activeHosts = mockAssets.filter((a) => a.httpStatus !== null && a.httpStatus < 400).length;
  const totalPorts = mockAssets.reduce((acc, a) => acc + a.openPorts.length, 0);
  const uniqueTechs = new Set(mockAssets.flatMap((a) => a.technologies)).size;

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Discovered Assets</h1>
        <p className="mt-1 text-sm text-slate-500">
          Reconnaissance asset inventory discovered across targets and active ranges.
        </p>
      </header>

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total Assets" value={totalAssets} accent="cyan" />
        <StatCard label="Active Hosts" value={activeHosts} accent="emerald" />
        <StatCard label="Discovered Ports" value={totalPorts} accent="amber" />
        <StatCard label="Technologies" value={uniqueTechs} accent="orange" />
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/50">
        <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
          Asset Inventory
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Hostname</th>
                <th className="px-4 py-3 font-medium">IP Addresses</th>
                <th className="px-4 py-3 font-medium">Technologies</th>
                <th className="px-4 py-3 font-medium">Open Ports</th>
                <th className="px-4 py-3 font-medium">HTTP Status</th>
                <th className="px-4 py-3 font-medium">Discovered</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 bg-slate-950">
              {mockAssets.map((asset) => (
                <tr key={asset.id} className="hover:bg-slate-900/60 transition-colors">
                  <td className="px-4 py-3 font-mono text-sm font-medium text-cyan-300">
                    {asset.hostname}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {asset.ipAddresses.map((ip) => (
                        <span
                          key={ip}
                          className="rounded bg-slate-800/90 px-2 py-0.5 font-mono text-xs text-slate-300 ring-1 ring-slate-700/50"
                        >
                          {ip}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {asset.technologies.map((tech) => (
                        <span
                          key={tech}
                          className="rounded-full bg-cyan-500/10 px-2.5 py-0.5 text-xs font-medium text-cyan-300 ring-1 ring-cyan-500/20"
                        >
                          {tech}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1 font-mono text-xs">
                      {asset.openPorts.map((port) => (
                        <span
                          key={port}
                          className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300"
                        >
                          {port}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">{getStatusBadge(asset.httpStatus)}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">
                    {formatRelativeTime(asset.discoveredAt)}
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
