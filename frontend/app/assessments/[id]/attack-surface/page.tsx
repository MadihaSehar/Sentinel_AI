"use client";

import { useEffect, useState } from "react";
import { api, type AssetRaw } from "@/lib/api";

export default function AttackSurfacePage({ params }: { params: { id: string } }) {
  const { id } = params;
  const [assets, setAssets] = useState<AssetRaw[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const a = await api.getAssets(id);
        if (!cancelled) setAssets(a);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load.");
      } finally {
        if (!cancelled) setLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Attack Surface</h1>
        <p className="mt-1 text-sm text-slate-500">
          Discovered domains, subdomains, and the technologies/ports observed on each.
        </p>
      </header>

      {error && (
        <div className="mb-6 rounded-md border border-rose-500/30 bg-rose-500/5 px-3 py-2 text-sm text-rose-300">
          {error}
        </div>
      )}

      {assets.length === 0 ? (
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 px-4 py-6 text-center text-xs text-slate-600">
          {loaded ? "No assets discovered yet for this assessment." : "Loading…"}
        </div>
      ) : (
        <div className="space-y-3">
          {assets.map((asset) => (
            <div key={asset.id} className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
              <div className="flex items-center justify-between">
                <div className="font-mono text-sm text-slate-200">{asset.hostname}</div>
                <span
                  className={`rounded px-2 py-0.5 text-xs font-medium ${
                    asset.http_status && asset.http_status < 400
                      ? "bg-emerald-500/10 text-emerald-400"
                      : "bg-amber-500/10 text-amber-400"
                  }`}
                >
                  HTTP {asset.http_status ?? "—"}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap gap-4 text-xs text-slate-500">
                <span>IPs: {asset.ip_addresses.join(", ")}</span>
                <span>Ports: {asset.open_ports.join(", ")}</span>
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
      )}
    </div>
  );
}
