import { mockAssets } from "@/lib/mock-data";

export default function AttackSurfacePage() {
  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Attack Surface</h1>
        <p className="mt-1 text-sm text-slate-500">
          Discovered domains, subdomains, and the technologies/ports observed on each.
        </p>
      </header>

      <div className="space-y-3">
        {mockAssets.map((asset) => (
          <div key={asset.id} className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
            <div className="flex items-center justify-between">
              <div className="font-mono text-sm text-slate-200">{asset.hostname}</div>
              <span
                className={`rounded px-2 py-0.5 text-xs font-medium ${
                  asset.httpStatus && asset.httpStatus < 400
                    ? "bg-emerald-500/10 text-emerald-400"
                    : "bg-amber-500/10 text-amber-400"
                }`}
              >
                HTTP {asset.httpStatus ?? "—"}
              </span>
            </div>
            <div className="mt-2 flex flex-wrap gap-4 text-xs text-slate-500">
              <span>IPs: {asset.ipAddresses.join(", ")}</span>
              <span>Ports: {asset.openPorts.join(", ")}</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {asset.technologies.map((tech) => (
                <span
                  key={tech}
                  className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-400"
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
