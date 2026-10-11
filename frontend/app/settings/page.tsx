"use client";

import { useState } from "react";

export default function SettingsPage() {
  const [rateLimit, setRateLimit] = useState(5);
  const [concurrency, setConcurrency] = useState(10);
  const [geminiKey, setGeminiKey] = useState("AIzaSyD9x823-DEMO-KEY-PROD-981");
  const [grokKey, setGrokKey] = useState("xai-908234-DEMO-GROK-KEY-712");
  const [deepseekKey, setDeepseekKey] = useState("sk-ds-92384-DEMO-DEEPSEEK-19");

  return (
    <div className="p-8 max-w-5xl">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">System & Engine Settings</h1>
        <p className="mt-1 text-sm text-slate-500">
          Configure multi-model AI consensus providers, scan throttling limits, and alert triggers.
        </p>
      </header>

      <div className="space-y-6">
        {/* Section 1: AI Providers */}
        <section className="rounded-lg border border-slate-800 bg-slate-900/50 p-6">
          <div className="border-b border-slate-800 pb-3 mb-5">
            <h2 className="text-base font-semibold text-slate-100">AI Provider Configurations</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Multi-LLM reasoning cluster powering the Phase 10 consensus verdict engine.
            </p>
          </div>

          <div className="space-y-5">
            {/* Google Gemini */}
            <div className="rounded-md border border-slate-800/80 bg-slate-950 p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-cyan-400 ring-4 ring-cyan-500/20" />
                  <span className="text-sm font-semibold text-slate-200">Google Gemini</span>
                </div>
                <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-400 ring-1 ring-emerald-500/20">
                  Active Provider
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">
                    API Key
                  </label>
                  <input
                    type="password"
                    value={geminiKey}
                    onChange={(e) => setGeminiKey(e.target.value)}
                    className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-1.5 font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">
                    Model Selection
                  </label>
                  <select
                    defaultValue="gemini-2.5-pro"
                    className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                  >
                    <option value="gemini-2.5-pro">gemini-2.5-pro (Reasoning & Consensus)</option>
                    <option value="gemini-2.5-flash">gemini-2.5-flash (Fast Recon)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* xAI Grok */}
            <div className="rounded-md border border-slate-800/80 bg-slate-950 p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-purple-400 ring-4 ring-purple-500/20" />
                  <span className="text-sm font-semibold text-slate-200">xAI Grok</span>
                </div>
                <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-400 ring-1 ring-emerald-500/20">
                  Active Provider
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">
                    API Key
                  </label>
                  <input
                    type="password"
                    value={grokKey}
                    onChange={(e) => setGrokKey(e.target.value)}
                    className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-1.5 font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">
                    Model Selection
                  </label>
                  <select
                    defaultValue="grok-2"
                    className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                  >
                    <option value="grok-2">grok-2 (Adversarial Heuristics)</option>
                    <option value="grok-beta">grok-beta (Experimental Analysis)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* DeepSeek */}
            <div className="rounded-md border border-slate-800/80 bg-slate-950 p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 ring-4 ring-emerald-500/20" />
                  <span className="text-sm font-semibold text-slate-200">DeepSeek</span>
                </div>
                <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-400 ring-1 ring-emerald-500/20">
                  Active Provider
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">
                    API Key
                  </label>
                  <input
                    type="password"
                    value={deepseekKey}
                    onChange={(e) => setDeepseekKey(e.target.value)}
                    className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-1.5 font-mono text-xs text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">
                    Model Selection
                  </label>
                  <select
                    defaultValue="deepseek-reasoner"
                    className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                  >
                    <option value="deepseek-reasoner">deepseek-reasoner (R1 Chain-of-Thought)</option>
                    <option value="deepseek-chat">deepseek-chat (V3)</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Section 2: Scan Defaults */}
        <section className="rounded-lg border border-slate-800 bg-slate-900/50 p-6">
          <div className="border-b border-slate-800 pb-3 mb-5">
            <h2 className="text-base font-semibold text-slate-100">Scan & Throttling Defaults</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Safety parameters, rate limit bounds, and concurrent execution workers.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-medium">
                <span className="text-slate-300">Rate Limit</span>
                <span className="font-mono text-cyan-400">{rateLimit} req / sec</span>
              </div>
              <input
                type="range"
                min="1"
                max="50"
                value={rateLimit}
                onChange={(e) => setRateLimit(Number(e.target.value))}
                className="w-full accent-cyan-400 cursor-pointer"
              />
              <p className="text-[11px] text-slate-500">
                Prevents target degradation and respects engagement scope boundaries.
              </p>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-medium">
                <span className="text-slate-300">Execution Concurrency</span>
                <span className="font-mono text-cyan-400">{concurrency} workers</span>
              </div>
              <input
                type="range"
                min="1"
                max="30"
                value={concurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
                className="w-full accent-cyan-400 cursor-pointer"
              />
              <p className="text-[11px] text-slate-500">
                Parallel processes for concurrent tool tasks (nuclei, ffuf, katana).
              </p>
            </div>
          </div>
        </section>

        {/* Section 3: Notification Preferences */}
        <section className="rounded-lg border border-slate-800 bg-slate-900/50 p-6">
          <div className="border-b border-slate-800 pb-3 mb-5">
            <h2 className="text-base font-semibold text-slate-100">Notification Preferences</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Real-time alert dispatch thresholds for SOC operations.
            </p>
          </div>

          <div className="space-y-3">
            {[
              {
                id: "notif-crit",
                label: "Critical and High severity finding alerts",
                desc: "Immediate push notification whenever consensus confirms a high or critical vulnerability.",
                defaultChecked: true,
              },
              {
                id: "notif-state",
                label: "Assessment stage progression and completion",
                desc: "Alerts when recon, scanning, or analysis pipelines complete or require intervention.",
                defaultChecked: true,
              },
              {
                id: "notif-fail",
                label: "Tool run execution errors or timeouts",
                desc: "Notification if a security binary encounters exit code failures or rate throttling.",
                defaultChecked: true,
              },
              {
                id: "notif-disagree",
                label: "AI consensus disagreements and manual review flags",
                desc: "Alerts when LLM models disagree on vulnerability legitimacy (REQUIRES_MANUAL_REVIEW).",
                defaultChecked: false,
              },
            ].map((pref) => (
              <label
                key={pref.id}
                htmlFor={pref.id}
                className="flex items-start gap-3 rounded-md p-2.5 hover:bg-slate-900/60 cursor-pointer transition-colors"
              >
                <input
                  id={pref.id}
                  type="checkbox"
                  defaultChecked={pref.defaultChecked}
                  className="mt-0.5 h-4 w-4 rounded border-slate-700 bg-slate-900 text-cyan-500 accent-cyan-500 focus:ring-0"
                />
                <div>
                  <div className="text-xs font-medium text-slate-200">{pref.label}</div>
                  <div className="text-[11px] text-slate-500">{pref.desc}</div>
                </div>
              </label>
            ))}
          </div>
        </section>

        {/* Action Button */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <button
            type="button"
            className="rounded-md border border-slate-800 bg-slate-900 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
          >
            Reset Defaults
          </button>
          <button
            type="button"
            className="rounded-md bg-cyan-500 px-4 py-2 text-xs font-medium text-slate-950 hover:bg-cyan-400"
          >
            Save Configuration
          </button>
        </div>
      </div>
    </div>
  );
}
