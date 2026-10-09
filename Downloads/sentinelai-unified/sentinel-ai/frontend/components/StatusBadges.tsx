import { CONSENSUS_STYLES, formatConfidence } from "@/lib/format";
import type { ConsensusStatus } from "@/lib/types";

export function ConsensusBadge({ status }: { status: ConsensusStatus }) {
  const style = CONSENSUS_STYLES[status];
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${style.bg} ${style.text}`}>
      {style.label}
    </span>
  );
}

export function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100);
  const color = pct >= 70 ? "bg-emerald-400" : pct >= 40 ? "bg-amber-400" : "bg-slate-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs tabular-nums text-slate-400">{formatConfidence(confidence)}</span>
    </div>
  );
}

export function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: "rose" | "orange" | "amber" | "cyan" | "emerald";
}) {
  const accentMap: Record<string, string> = {
    rose: "text-rose-400",
    orange: "text-orange-400",
    amber: "text-amber-400",
    cyan: "text-cyan-400",
    emerald: "text-emerald-400",
  };
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
      <div className="text-xs uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-1.5 text-2xl font-semibold tabular-nums ${accent ? accentMap[accent] : "text-slate-100"}`}>
        {value}
      </div>
    </div>
  );
}
