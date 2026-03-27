// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { readFile } from "fs/promises";
import { join } from "path";
import { getAllTools, PARALLEL_GROUPS, LIGHT_TOOLS, MEDIUM_TOOLS, CWE_TRIGGERS, LLM_PROVIDERS } from "@/lib/tools-data";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

async function loadSmartConfig(): Promise<string | null> {
  try {
    return await readFile(join(PROJECT_ROOT, "configs", "smart-config.yaml"), "utf-8");
  } catch {
    return null;
  }
}

export default async function SmartScanPage() {
  const smartConfig = await loadSmartConfig();
  const tools = getAllTools();

  // Check env vars for LLM
  const envStatus: Record<string, boolean> = {};
  for (const p of LLM_PROVIDERS) {
    envStatus[p.envVar] = !!process.env[p.envVar];
  }
  const llmAvailable = LLM_PROVIDERS.some((p) => envStatus[p.envVar]);

  // Pipeline stages
  const stages = [
    {
      icon: "🎯",
      name: "Scope",
      desc: "Load target scope (YAML/JSON/Markdown). Filter in-scope/out-of-scope. Extract domains and URLs.",
      status: "ready",
      color: "#4CAF50",
    },
    {
      icon: "🧠",
      name: "Memory Recall",
      desc: "Query Memory OS for past findings on these targets. Provide historical context to the AI analyzer.",
      status: "ready",
      color: "#9C27B0",
    },
    {
      icon: "📊",
      name: "Graph Analysis",
      desc: "Build dependency graph. Compute execution waves. Auto-suggest tools based on CWE triggers.",
      status: "ready",
      color: "#2196F3",
    },
    {
      icon: "🔍",
      name: "Scan Execution",
      desc: "Run selected tools in parallel waves. Profile: light (15), medium (32), full (67).",
      status: "ready",
      color: "#FF9800",
    },
    {
      icon: "🤖",
      name: "LLM Analysis",
      desc: "Analyze findings with AI. Multi-provider fallback. Severity threshold filtering.",
      status: llmAvailable ? "ready" : "no-key",
      color: "#6366f1",
    },
    {
      icon: "📥",
      name: "Memory Ingest",
      desc: "Store scan results in Memory OS for future recall. Dedup by stable hash.",
      status: "ready",
      color: "#00BCD4",
    },
    {
      icon: "💣",
      name: "Payload Generation",
      desc: "Generate targeted payloads based on CWE findings. PATT + curated payload sets.",
      status: "ready",
      color: "#F44336",
    },
  ];

  return (
    <main className="px-6 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Smart Scan</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Intelligent pipeline: Scope → Memory → Graph → Scan → LLM → Ingest → Payloads
        </p>
      </div>

      {/* Pipeline visualization */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5 mb-6">
        <h3 className="font-semibold text-sm mb-4">Pipeline Stages</h3>
        <div className="relative">
          {/* Connector line */}
          <div className="absolute left-[22px] top-8 bottom-8 w-0.5 bg-[var(--border)]" />

          <div className="space-y-4">
            {stages.map((stage, i) => (
              <div key={stage.name} className="flex items-start gap-4 relative">
                {/* Stage number */}
                <div
                  className="w-[44px] h-[44px] rounded-full flex items-center justify-center text-lg flex-shrink-0 relative z-10"
                  style={{ background: `${stage.color}20`, border: `2px solid ${stage.color}` }}
                >
                  {stage.icon}
                </div>
                {/* Content */}
                <div className="flex-1 bg-[var(--bg)] rounded-lg p-4">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-[var(--text-dim)]">Step {i + 1}</span>
                      <h4 className="font-semibold text-sm">{stage.name}</h4>
                    </div>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                        stage.status === "ready"
                          ? "bg-green-900/40 text-green-400"
                          : "bg-yellow-900/40 text-yellow-400"
                      }`}
                    >
                      {stage.status === "ready" ? "ready" : "needs API key"}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--text-muted)]">{stage.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Profile comparison */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5 mb-6">
        <h3 className="font-semibold text-sm mb-4">Scan Profiles</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { name: "Light", tools: LIGHT_TOOLS, color: "#22c55e", desc: "Quick recon + core DAST. ~10 min.", cmd: "make scan-light" },
            { name: "Medium", tools: MEDIUM_TOOLS, color: "#eab308", desc: "Extended coverage. Injection + specialized. ~30 min.", cmd: "make scan-medium" },
            { name: "Full", tools: tools.map((t) => t.name), color: "#ef4444", desc: "All 67 tools. Complete coverage. ~60+ min.", cmd: "make scan-full" },
          ].map((p) => (
            <div key={p.name} className="bg-[var(--bg)] rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-bold" style={{ color: p.color }}>{p.name}</h4>
                <span className="text-2xl font-bold" style={{ color: p.color }}>{p.tools.length}</span>
              </div>
              <p className="text-xs text-[var(--text-muted)] mb-3">{p.desc}</p>
              <code className="block text-[10px] font-mono bg-[var(--card-bg)] rounded px-2 py-1 text-[var(--text-dim)]">
                {p.cmd} TARGET=https://…
              </code>
              <div className="flex flex-wrap gap-1 mt-3">
                {p.tools.slice(0, 8).map((t) => (
                  <span key={t} className="text-[9px] font-mono bg-[var(--card-bg)] text-[var(--text-dim)] px-1.5 py-0.5 rounded">
                    {t}
                  </span>
                ))}
                {p.tools.length > 8 && (
                  <span className="text-[9px] text-[var(--text-dim)]">+{p.tools.length - 8} more</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* CWE auto-triggers */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5 mb-6">
        <h3 className="font-semibold text-sm mb-3">CWE Auto-Triggers</h3>
        <p className="text-xs text-[var(--text-muted)] mb-3">
          When a finding with a matching CWE is detected during the scan, these specialized tools are automatically queued for deeper analysis.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
          {Object.entries(CWE_TRIGGERS).map(([cwe, triggerTools]) => (
            <div key={cwe} className="flex items-center gap-3 bg-[var(--bg)] rounded px-4 py-2.5">
              <span className="font-mono text-xs font-bold text-[var(--accent)]">{cwe}</span>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4 text-[var(--text-dim)]">
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
              <div className="flex gap-1">
                {triggerTools.map((t) => (
                  <span key={t} className="text-xs font-mono bg-yellow-900/30 text-yellow-400 px-2 py-0.5 rounded">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Execution waves */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5 mb-6">
        <h3 className="font-semibold text-sm mb-3">Execution Order</h3>
        <p className="text-xs text-[var(--text-muted)] mb-3">
          Tools within the same wave run in parallel. Each wave waits for its dependencies to complete.
        </p>
        <div className="space-y-3">
          {PARALLEL_GROUPS.map((group, i) => (
            <div key={group.name} className="flex items-start gap-3">
              <div className="w-6 h-6 rounded bg-[var(--accent)]/20 text-[var(--accent)] flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-1">
                {i}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-medium">{group.name}</span>
                  <span className="text-[10px] text-[var(--text-dim)]">
                    {group.tools.length} tools
                    {group.dependsOn.length > 0 && ` · after ${group.dependsOn.join(", ")}`}
                  </span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {group.tools.map((t) => (
                    <span key={t} className="text-[10px] font-mono bg-[var(--bg)] text-[var(--text-muted)] px-2 py-0.5 rounded">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Smart config */}
      {smartConfig && (
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold text-sm mb-3">
            Smart Configuration
            <span className="text-[var(--text-dim)] font-normal ml-2">configs/smart-config.yaml</span>
          </h3>
          <pre className="text-xs font-mono bg-[var(--bg)] rounded p-4 overflow-x-auto max-h-[400px] overflow-y-auto text-[var(--text-muted)]">
            {smartConfig}
          </pre>
        </div>
      )}
    </main>
  );
}
