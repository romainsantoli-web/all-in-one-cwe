// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";
import ProviderTestButton from "@/components/ProviderTestButton";

const PROVIDER_ICONS: Record<string, string> = {
  claude: "🟣",
  gpt: "🟢",
  "copilot-pro": "🔵",
  copilot: "⚫",
  mistral: "🟠",
  gemini: "🔴",
};

interface ProviderCardProps {
  name: string;
  defaultModel: string;
  envVar: string;
  available: boolean;
  source: string;
  isAuto: boolean;
  models: string[];
  onDisconnect: () => void;
}

export default function ProviderCard({
  name,
  defaultModel,
  envVar,
  available,
  source,
  isAuto,
  models,
  onDisconnect,
}: ProviderCardProps) {
  const [selectedModel, setSelectedModel] = useState(defaultModel);
  const [disconnecting, setDisconnecting] = useState(false);
  const [testModel, setTestModel] = useState(defaultModel);

  const handleDisconnect = async () => {
    if (!confirm(`Disconnect ${name}? This will remove the saved API key.`)) return;
    setDisconnecting(true);
    try {
      const res = await fetch("/api/llm/providers", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ envVar }),
      });
      if (res.ok) {
        onDisconnect();
      }
    } catch {
      // ignore
    } finally {
      setDisconnecting(false);
    }
  };

  return (
    <div
      className={`bg-[var(--card-bg)] border rounded-lg p-5 transition-all ${
        available
          ? isAuto
            ? "border-[var(--accent)] shadow-[0_0_12px_rgba(99,102,241,0.15)]"
            : "border-green-800"
          : "border-[var(--border)] opacity-60"
      }`}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-xl">{PROVIDER_ICONS[name] || "🤖"}</span>
          <h3 className="font-bold">{name}</h3>
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

      {/* Model selector */}
      <div className="space-y-2 text-sm">
        <div className="flex items-center justify-between">
          <span className="text-[var(--text-muted)]">Model</span>
          {models.length > 1 ? (
            <select
              value={selectedModel}
              onChange={(e) => {
                setSelectedModel(e.target.value);
                setTestModel(e.target.value);
              }}
              className="text-xs bg-[var(--bg)] border border-[var(--border)] rounded px-2 py-1 text-[var(--text)] font-mono max-w-[200px]"
            >
              {models.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          ) : (
            <span className="font-mono text-xs">{defaultModel}</span>
          )}
        </div>
        <div className="flex justify-between">
          <span className="text-[var(--text-muted)]">Env Variable</span>
          <span className="font-mono text-xs">{envVar}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-[var(--text-muted)]">Status</span>
          <span className={`font-medium ${available ? "text-green-400" : "text-red-400"}`}>
            {available ? `Configured (${source})` : "Missing key"}
          </span>
        </div>
      </div>

      {/* Disconnect button */}
      {available && source === "settings" && (
        <div className="mt-3 pt-3 border-t border-[var(--border)]">
          <button
            onClick={handleDisconnect}
            disabled={disconnecting}
            className="px-3 py-1.5 text-xs bg-red-900/20 text-red-400 rounded hover:bg-red-900/30 transition-colors disabled:opacity-50"
          >
            {disconnecting ? "Disconnecting..." : "🔌 Disconnect"}
          </button>
        </div>
      )}

      {/* Test */}
      <ProviderTestButton providerName={name} available={available} />
    </div>
  );
}
