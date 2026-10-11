import { ConfidenceBar, ConsensusBadge, StatCard } from "@/components/StatusBadges";
import { formatRelativeTime } from "@/lib/format";
import type { ConsensusStatus } from "@/lib/types";

interface AiDecisionItem {
  id: string;
  action: string;
  target: string;
  reason: string;
  priority: "high" | "medium" | "low";
  confidence: number;
  models: string[];
  consensusStatus: ConsensusStatus;
  createdAt: string;
}

const mockAiDecisions: AiDecisionItem[] = [
  {
    id: "ai1",
    action: "analyze_authorization",
    target: "/api/orders/{id}",
    reason: "Object identifier with sequential pattern detected",
    priority: "high",
    confidence: 0.87,
    models: ["Gemini", "Grok", "DeepSeek"],
    consensusStatus: "CONFIRMED",
    createdAt: "2026-10-09T09:45:00Z",
  },
  {
    id: "ai2",
    action: "analyze_xss",
    target: "/search?q=",
    reason: "Parameter reflected in HTML response body without encoding",
    priority: "high",
    confidence: 0.91,
    models: ["Gemini", "Grok"],
    consensusStatus: "CONFIRMED",
    createdAt: "2026-10-09T09:47:00Z",
  },
  {
    id: "ai3",
    action: "analyze_sqli",
    target: "/api/users?sort=",
    reason: "SQL error signature detected in response",
    priority: "medium",
    confidence: 0.54,
    models: ["Gemini", "DeepSeek"],
    consensusStatus: "REQUIRES_MANUAL_REVIEW",
    createdAt: "2026-10-09T09:50:00Z",
  },
  {
    id: "ai4",
    action: "skip_analysis",
    target: "/static/js/bundle.js",
    reason: "Static asset, no dynamic parameters",
    priority: "low",
    confidence: 0.95,
    models: ["Gemini"],
    consensusStatus: "NO_FINDING",
    createdAt: "2026-10-09T09:51:00Z",
  },
];

function getPriorityBadge(priority: "high" | "medium" | "low") {
  if (priority === "high") {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-rose-500/10 text-rose-400 ring-rose-500/30">
        high
      </span>
    );
  }
  if (priority === "medium") {
    return (
      <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-amber-500/10 text-amber-400 ring-amber-500/30">
        medium
      </span>
    );
  }
  return (
    <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 bg-slate-500/10 text-slate-400 ring-slate-500/30">
      low
    </span>
  );
}

function getModelPill(model: string) {
  let style = "bg-slate-800 text-slate-300 ring-slate-700";
  if (model.toLowerCase().includes("gemini")) {
    style = "bg-cyan-500/10 text-cyan-300 ring-cyan-500/30";
  } else if (model.toLowerCase().includes("grok")) {
    style = "bg-purple-500/10 text-purple-300 ring-purple-500/30";
  } else if (model.toLowerCase().includes("deepseek")) {
    style = "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30";
  }
  return (
    <span
      key={model}
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ${style}`}
    >
      {model}
    </span>
  );
}

export default function AiAnalysisPage() {
  const totalDecisions = mockAiDecisions.length;
  const confirmed = mockAiDecisions.filter((d) => d.consensusStatus === "CONFIRMED").length;
  const needsReview = mockAiDecisions.filter(
    (d) => d.consensusStatus === "REQUIRES_MANUAL_REVIEW"
  ).length;
  const totalModels = 3;

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">AI Decision History</h1>
        <p className="mt-1 text-sm text-slate-500">
          Real-time reasoning logs and multi-LLM consensus evaluations.
        </p>
      </header>

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="AI Decisions" value={totalDecisions} accent="cyan" />
        <StatCard label="Confirmed Findings" value={confirmed} accent="emerald" />
        <StatCard label="Review Required" value={needsReview} accent="amber" />
        <StatCard label="Active LLMs" value={totalModels} accent="cyan" />
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/50">
        <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
          Reasoning & Action Logs
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Target</th>
                <th className="px-4 py-3 font-medium">Reasoning</th>
                <th className="px-4 py-3 font-medium">Priority</th>
                <th className="px-4 py-3 font-medium">Confidence</th>
                <th className="px-4 py-3 font-medium">Participating Models</th>
                <th className="px-4 py-3 font-medium">Consensus Status</th>
                <th className="px-4 py-3 font-medium">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 bg-slate-950">
              {mockAiDecisions.map((decision) => (
                <tr key={decision.id} className="hover:bg-slate-900/60 transition-colors">
                  <td className="px-4 py-3 font-mono text-xs font-semibold text-cyan-300">
                    {decision.action}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">
                    {decision.target}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-300 max-w-xs">
                    {decision.reason}
                  </td>
                  <td className="px-4 py-3">{getPriorityBadge(decision.priority)}</td>
                  <td className="px-4 py-3">
                    <ConfidenceBar confidence={decision.confidence} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {decision.models.map(getModelPill)}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <ConsensusBadge status={decision.consensusStatus} />
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400">
                    {formatRelativeTime(decision.createdAt)}
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
