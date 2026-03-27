// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { LLM_PROVIDERS } from "@/lib/tools-data";
import { readFile } from "fs/promises";
import { join } from "path";
import ProviderTestButton from "@/components/ProviderTestButton";
import Link from "next/link";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

const PROVIDER_ICONS: Record<string, string> = {
  claude: "🟣",
  gpt: "🟢",
  "copilot-pro": "🔵",
  copilot: "⚫",
  mistral: "🟠",
  gemini: "🔴",
};

export default async function LLMPage() {
  // Load LLM config YAML content
  let llmConfigRaw = "";
  try {
    llmConfigRaw = await readFile(join(PROJECT_ROOT, "configs", "llm-config.yaml"), "utf-8");
  } catch { /* skip */ }

  // Check env availability (booleans only — never expose secrets)
  const envStatus: Record<string, boolean> = {};
  for (const p of LLM_PROVIDERS) {
    envStatus[p.envVar] = !!process.env[p.envVar];
  }

  const availableCount = LLM_PROVIDERS.filter((p) => envStatus[p.envVar]).length;

  // Detect default provider (same logic as llm-config.yaml auto mode)
  let autoProvider = "none";
  if (envStatus.COPILOT_JWT) autoProvider = "copilot-pro";
  else if (envStatus.ANTHROPIC_API_KEY) autoProvider = "claude";
  else if (envStatus.OPENAI_API_KEY) autoProvider = "gpt";
  else if (envStatus.MISTRAL_API_KEY) autoProvider = "mistral";
  else if (envStatus.GEMINI_API_KEY) autoProvider = "gemini";
  else if (envStatus.GITHUB_TOKEN) autoProvider = "copilot";

  return (
    <main className="px-6 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">LLM Providers</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Multi-provider AI analysis engine · {availableCount}/{LLM_PROVIDERS.length} providers available
        </p>
        <Link
          href="/ai"
          className="inline-block mt-2 px-4 py-2 bg-purple-600 text-white rounded text-sm font-medium hover:opacity-90"
        >
          Open AI Chat →
        </Link>
      </div>

      {/* KPI */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Total Providers</div>
          <div className="text-2xl font-bold">{LLM_PROVIDERS.length}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-green-400 mb-1">Available</div>
          <div className="text-2xl font-bold text-green-400">{availableCount}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Unavailable</div>
          <div className="text-2xl font-bold text-red-400">{LLM_PROVIDERS.length - availableCount}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--accent)] mb-1">Auto-Selected</div>
          <div className="text-lg font-bold text-[var(--accent)]">{autoProvider}</div>
        </div>
      </div>

      {/* Provider grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        {LLM_PROVIDERS.map((p) => {
          const available = envStatus[p.envVar];
          const isAuto = p.name === autoProvider;
          return (
            <div
              key={p.name}
              className={`bg-[var(--card-bg)] border rounded-lg p-5 transition-all ${
                available
                  ? isAuto
                    ? "border-[var(--accent)] shadow-[0_0_12px_rgba(99,102,241,0.15)]"
                    : "border-green-800"
                  : "border-[var(--border)] opacity-60"
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xl">{PROVIDER_ICONS[p.name] || "🤖"}</span>
                  <h3 className="font-bold">{p.name}</h3>
                </div>
                <div className="flex items-center gap-2">
                  {isAuto && (
                    <span className="text-[10px] px-2 py-0.5 rounded-full bg-[var(--accent)] text-white font-medium">
                      AUTO
                    </span>
                  )}
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      available ? "bg-green-500" : "bg-red-500"
                    }`}
                  />
                </div>
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Model</span>
                  <span className="font-mono text-xs">{p.model}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Env Variable</span>
                  <span className="font-mono text-xs">{p.envVar}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Status</span>
                  <span className={`font-medium ${available ? "text-green-400" : "text-red-400"}`}>
                    {available ? "Configured" : "Missing key"}
                  </span>
                </div>
              </div>
              <ProviderTestButton providerName={p.name} available={available} />
            </div>
          );
        })}
      </div>

      {/* Auto-detection explanation */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
        <h3 className="font-semibold text-sm mb-3">Auto-Detection Priority</h3>
        <p className="text-xs text-[var(--text-muted)] mb-3">
          In <code className="text-[var(--accent)]">auto</code> mode, the engine selects the first available provider in this order:
        </p>
        <div className="flex flex-wrap gap-2">
          {["COPILOT_JWT → copilot-pro", "ANTHROPIC_API_KEY → claude", "OPENAI_API_KEY → gpt",
            "MISTRAL_API_KEY → mistral", "GEMINI_API_KEY → gemini", "GITHUB_TOKEN → copilot"].map((rule, i) => (
            <span key={i} className="text-xs font-mono bg-[var(--bg)] text-[var(--text-muted)] px-3 py-1.5 rounded">
              {i + 1}. {rule}
            </span>
          ))}
        </div>
      </div>

      {/* Raw config display */}
      {llmConfigRaw && (
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold text-sm mb-3">
            LLM Configuration
            <span className="text-[var(--text-dim)] font-normal ml-2">configs/llm-config.yaml</span>
          </h3>
          <pre className="text-xs font-mono bg-[var(--bg)] rounded p-4 overflow-x-auto max-h-[400px] overflow-y-auto text-[var(--text-muted)]">
            {llmConfigRaw}
          </pre>
        </div>
      )}
    </main>
  );
}
