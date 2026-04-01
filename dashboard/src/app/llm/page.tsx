// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback } from "react";
import ProviderCard from "@/components/ProviderCard";
import CopilotAuthButton from "@/components/CopilotAuthButton";
import Link from "next/link";

interface ProviderInfo {
  name: string;
  model: string;
  envVar: string;
  available: boolean;
  source: string;
  models: string[];
}

const PRIORITY_ORDER = ["COPILOT_JWT", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MISTRAL_API_KEY", "GEMINI_API_KEY", "GITHUB_TOKEN"];

export default function LLMPage() {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchProviders = useCallback(async () => {
    try {
      const res = await fetch("/api/llm/providers");
      const data = await res.json();
      setProviders(data.providers || []);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchProviders(); }, [fetchProviders]);

  const availableCount = providers.filter((p) => p.available).length;

  // Auto-detect priority
  let autoProvider = "none";
  for (const envVar of PRIORITY_ORDER) {
    const p = providers.find((pr) => pr.envVar === envVar);
    if (p?.available) {
      autoProvider = p.name;
      break;
    }
  }

  if (loading) {
    return (
      <main className="px-6 py-6">
        <div className="text-sm text-[var(--text-muted)]">Loading providers...</div>
      </main>
    );
  }

  return (
    <main className="px-6 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">LLM Providers</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Multi-provider AI analysis engine · {availableCount}/{providers.length} providers available
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
          <div className="text-2xl font-bold">{providers.length}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-green-400 mb-1">Available</div>
          <div className="text-2xl font-bold text-green-400">{availableCount}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Unavailable</div>
          <div className="text-2xl font-bold text-red-400">{providers.length - availableCount}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--accent)] mb-1">Auto-Selected</div>
          <div className="text-lg font-bold text-[var(--accent)]">{autoProvider}</div>
        </div>
      </div>

      {/* Provider grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        {providers.map((p) => (
          <div key={p.name}>
            <ProviderCard
              name={p.name}
              defaultModel={p.model}
              envVar={p.envVar}
              available={p.available}
              source={p.source}
              isAuto={p.name === autoProvider}
              models={p.models}
              onDisconnect={fetchProviders}
            />
            {p.name === "copilot-pro" && <CopilotAuthButton />}
          </div>
        ))}
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
    </main>
  );
}
