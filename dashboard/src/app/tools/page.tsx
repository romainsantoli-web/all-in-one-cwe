// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { getAllTools, PARALLEL_GROUPS, LIGHT_TOOLS, MEDIUM_TOOLS, CWE_TRIGGERS } from "@/lib/tools-data";
import type { ToolMeta } from "@/lib/tools-data";
import { useState, useEffect } from "react";
import ToolRunner from "@/components/ToolRunner";

export const dynamic = "force-dynamic";

interface CdpStatus { available: boolean; url: string; host?: string; port?: number; launchHint?: string | null }


const GROUP_COLORS: Record<string, string> = {
  recon: "#4CAF50",
  dast: "#2196F3",
  injection: "#FF9800",
  specialized: "#9C27B0",
  "python-scanners": "#F44336",
  "code-analysis": "#00BCD4",
  conditional: "#795548",
  "waf-bypass": "#607D8B",
  "web-advanced": "#E91E63",
  iac: "#3F51B5",
  "api-fuzzing": "#CDDC39",
  "waf-evasion": "#FF5722",
  "business-logic": "#FFC107",
  discovery: "#8BC34A",
  "oauth-session": "#673AB7",
  "cdp-scanners": "#FF4081",
};

const REQUIRES_ICONS: Record<string, string> = {
  domain: "🌐",
  target: "🎯",
  code: "💻",
  repo: "📦",
  image: "🐳",
  binary: "⚙️",
  bin_dir: "📁",
};

function ToolCard({ tool, inLight, inMedium, onRun }: { tool: ToolMeta; inLight: boolean; inMedium: boolean; onRun: (name: string) => void }) {
  const color = GROUP_COLORS[tool.group] || "#666";
  const badges: string[] = [];
  if (inLight) badges.push("light");
  if (inMedium && !inLight) badges.push("medium");
  if (!inLight && !inMedium) badges.push("full");

  return (
    <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 hover:border-[var(--border-hover)] transition-all">
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-lg">{REQUIRES_ICONS[tool.requires || ""] || "🔧"}</span>
          <h3 className="font-semibold text-sm">{tool.name}</h3>
        </div>
        <span
          className="text-[10px] font-mono px-2 py-0.5 rounded-full"
          style={{ background: `${color}30`, color }}
        >
          {tool.group}
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5 mt-2">
        {badges.map((b) => (
          <span
            key={b}
            className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
              b === "light" ? "bg-green-900/40 text-green-400" :
              b === "medium" ? "bg-yellow-900/40 text-yellow-400" :
              "bg-gray-800 text-gray-400"
            }`}
          >
            {b}
          </span>
        ))}
        {tool.requires && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-900/30 text-blue-400">
            {tool.requires}
          </span>
        )}
        {tool.sequential && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900/30 text-red-400">
            sequential
          </span>
        )}
        {tool.envRequires?.map((e) => (
          <span key={e} className="text-[10px] px-1.5 py-0.5 rounded bg-purple-900/30 text-purple-400">
            {e}
          </span>
        ))}
      </div>
      {(tool.requires === "target") && (
        <button
          onClick={() => onRun(tool.name)}
          className="mt-3 w-full py-1.5 text-xs font-medium rounded bg-[var(--accent)]/20 text-[var(--accent)] hover:bg-[var(--accent)]/30 transition-colors"
        >
          ▶ Run
        </button>
      )}
    </div>
  );
}

export default function ToolsPage() {
  const [runningTool, setRunningTool] = useState<string | null>(null);
  const [cdpStatus, setCdpStatus] = useState<CdpStatus | null>(null);
  const tools = getAllTools();
  const lightSet = new Set(LIGHT_TOOLS);
  const mediumSet = new Set(MEDIUM_TOOLS);

  useEffect(() => {
    fetch("/api/cdp/status")
      .then((r) => r.json())
      .then((data: CdpStatus) => setCdpStatus(data))
      .catch(() => setCdpStatus({ available: false, url: "ws://localhost:9222" }));
  }, []);

  // Group tools by parallel group
  const grouped: Record<string, ToolMeta[]> = {};
  for (const t of tools) {
    if (!grouped[t.group]) grouped[t.group] = [];
    grouped[t.group].push(t);
  }

  // Stats
  const requiresCounts: Record<string, number> = {};
  for (const t of tools) {
    const r = t.requires || "none";
    requiresCounts[r] = (requiresCounts[r] || 0) + 1;
  }

  // CWE triggers flat count
  const triggerCount = Object.values(CWE_TRIGGERS).reduce((sum, arr) => sum + arr.length, 0);

  return (
    <main className="px-6 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Tools Catalog</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          {tools.length} tools across {PARALLEL_GROUPS.length} parallel groups · {triggerCount} CWE conditional triggers
        </p>
      </div>

      {/* Profile stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Total Tools</div>
          <div className="text-2xl font-bold">{tools.length}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-green-400 mb-1">Light Profile</div>
          <div className="text-2xl font-bold text-green-400">{LIGHT_TOOLS.length}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-yellow-400 mb-1">Medium Profile</div>
          <div className="text-2xl font-bold text-yellow-400">{MEDIUM_TOOLS.length}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">CWE Triggers</div>
          <div className="text-2xl font-bold">{Object.keys(CWE_TRIGGERS).length}</div>
        </div>
      </div>

      {/* Input requirements breakdown */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
        <h3 className="font-semibold text-sm mb-3">Input Requirements</h3>
        <div className="flex flex-wrap gap-3">
          {Object.entries(requiresCounts)
            .sort((a, b) => b[1] - a[1])
            .map(([req, count]) => (
              <div key={req} className="flex items-center gap-2 text-sm">
                <span>{REQUIRES_ICONS[req] || "❓"}</span>
                <span className="text-[var(--text-muted)]">{req}</span>
                <span className="font-bold">{count}</span>
              </div>
            ))}
        </div>
      </div>

      {/* CWE Triggers */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
        <h3 className="font-semibold text-sm mb-3">CWE Conditional Triggers</h3>
        <p className="text-xs text-[var(--text-muted)] mb-3">
          When a CWE is detected, these specialized tools are automatically triggered for deeper analysis.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
          {Object.entries(CWE_TRIGGERS).map(([cwe, tools]) => (
            <div key={cwe} className="flex items-center gap-2 text-sm bg-[var(--bg)] rounded px-3 py-2">
              <span className="font-mono text-[var(--accent)] text-xs">{cwe}</span>
              <span className="text-[var(--text-dim)]">→</span>
              {tools.map((t) => (
                <span key={t} className="font-mono text-xs text-[var(--text)]">{t}</span>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* CDP Browser Status */}
      <div className={`border rounded-lg p-4 mb-6 ${cdpStatus?.available ? "bg-green-900/10 border-green-800/30" : "bg-[var(--card-bg)] border-[var(--border)]"}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-lg">🌐</span>
            <div>
              <h3 className="font-semibold text-sm">Chrome DevTools Protocol (CDP)</h3>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                Required for cdp-token-extractor, cdp-checkout-interceptor, cdp-credential-scanner
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className={`inline-block w-2.5 h-2.5 rounded-full ${cdpStatus?.available ? "bg-green-400 animate-pulse" : "bg-red-400"}`} />
            <span className={`text-xs font-medium ${cdpStatus?.available ? "text-green-400" : "text-red-400"}`}>
              {cdpStatus === null ? "Checking..." : cdpStatus.available ? "Connected" : "Not available"}
            </span>
          </div>
        </div>
        {cdpStatus && !cdpStatus.available && cdpStatus.launchHint && (
          <div className="mt-3 p-2 bg-[var(--bg)] rounded">
            <p className="text-xs text-[var(--text-muted)] mb-1">Launch Chrome headless to enable CDP tools:</p>
            <code className="text-xs text-[var(--accent)] font-mono break-all">{cdpStatus.launchHint}</code>
          </div>
        )}
        {cdpStatus?.available && (
          <p className="mt-2 text-xs text-green-300/70">Connected to {cdpStatus.url}</p>
        )}
      </div>

      {/* Tools by group */}
      {PARALLEL_GROUPS.map((group) => {
        const groupTools = grouped[group.name] || [];
        const color = GROUP_COLORS[group.name] || "#666";
        return (
          <div key={group.name} className="mb-6">
            <div className="flex items-center gap-3 mb-3">
              <h2 className="font-bold text-lg" style={{ color }}>
                {group.name}
              </h2>
              <span className="text-xs text-[var(--text-muted)]">
                {groupTools.length} tools
              </span>
              {group.dependsOn.length > 0 && (
                <span className="text-xs text-[var(--text-dim)]">
                  depends on: {group.dependsOn.join(", ")}
                </span>
              )}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {groupTools.map((tool) => (
                <ToolCard
                  key={tool.name}
                  tool={tool}
                  inLight={lightSet.has(tool.name)}
                  inMedium={mediumSet.has(tool.name)}
                  onRun={setRunningTool}
                />
              ))}
            </div>
          </div>
        );
      })}

      {/* Tool Runner overlay */}
      {runningTool && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-6">
          <div className="w-full max-w-md">
            <ToolRunner toolName={runningTool} onClose={() => setRunningTool(null)} />
          </div>
        </div>
      )}
    </main>
  );
}
