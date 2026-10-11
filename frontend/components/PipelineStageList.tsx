import { STAGE_STATUS_STYLES } from "@/lib/format";
import type { PipelineStage } from "@/lib/types";

export function PipelineStageList({ stages }: { stages: PipelineStage[] }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50">
      <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
        Pipeline
      </div>
      <ol className="divide-y divide-slate-800/70">
        {stages.map((stage) => {
          const style = STAGE_STATUS_STYLES[stage.status];
          return (
            <li key={stage.name} className="flex items-center justify-between px-4 py-2.5">
              <div className="flex items-center gap-3">
                <span className={`h-2 w-2 rounded-full ${style.dot}`} />
                <span className="text-sm text-slate-300">{stage.label}</span>
              </div>
              <div className="flex items-center gap-3">
                {stage.status === "running" && stage.progressPercent !== null && (
                  <div className="h-1.5 w-28 overflow-hidden rounded-full bg-slate-800">
                    <div
                      className="h-full bg-cyan-400 transition-all"
                      style={{ width: `${stage.progressPercent}%` }}
                    />
                  </div>
                )}
                <span className={`w-16 text-right text-xs font-medium uppercase tracking-wide ${style.text}`}>
                  {stage.status === "done"
                    ? "✓ done"
                    : stage.status === "skipped"
                      ? "skipped"
                      : stage.status === "error"
                        ? "error"
                        : stage.status === "running"
                          ? `${stage.progressPercent ?? 0}%`
                          : "pending"}
                </span>
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
