// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useCallback } from "react";

export const dynamic = "force-dynamic";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Finding {
  title: string;
  severity: string;
  description: string;
  evidence?: string;
  impact?: string;
  steps?: string[];
}

interface ToolResult {
  ok: boolean;
  tool: string;
  output: string;
  stderr?: string;
  error?: string;
  report?: { findings: Finding[] } | null;
}

type ActiveTool = "disasm-analyzer" | "pwn-toolkit" | "privesc-scanner";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TOOLS: {
  id: ActiveTool;
  label: string;
  icon: string;
  desc: string;
  modes: string[];
  extraFields?: string[];
}[] = [
  {
    id: "disasm-analyzer",
    label: "Binary Analysis",
    icon: "⚙️",
    desc: "Reverse engineering: checksec, ELF/PE parsing, function listing, disassembly, format string detection",
    modes: ["auto", "checksec", "strings", "functions", "disasm", "libraries"],
    extraFields: ["function"],
  },
  {
    id: "pwn-toolkit",
    label: "Pwn Toolkit",
    icon: "💥",
    desc: "Binary exploitation: cyclic pattern generation, ROP gadget search, one_gadget, shellcode catalog",
    modes: ["auto", "cyclic", "gadgets", "one-gadget", "shellcodes", "offset"],
    extraFields: ["length", "find"],
  },
  {
    id: "privesc-scanner",
    label: "Privesc Scanner",
    icon: "👑",
    desc: "Linux privilege escalation: SUID/GTFOBins, capabilities, cron jobs, sudo, writable paths, container escape, kernel exploits",
    modes: ["auto", "suid", "caps", "cron", "sudo", "paths", "files", "container", "kernel"],
  },
];

const SEV_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F59E0B",
  medium: "#3B82F6",
  low: "#10B981",
  info: "#6B7280",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function ReversingPage() {
  const [activeTool, setActiveTool] = useState<ActiveTool>("disasm-analyzer");
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("auto");
  const [fnName, setFnName] = useState("main");
  const [pwnLength, setPwnLength] = useState("200");
  const [pwnFind, setPwnFind] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ToolResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const currentTool = TOOLS.find((t) => t.id === activeTool)!;

  const runTool = useCallback(async () => {
    if (!target && activeTool !== "privesc-scanner") {
      setError("Provide a target binary path");
      return;
    }

    setRunning(true);
    setError(null);
    setResult(null);

    try {
      const body: Record<string, unknown> = { tool: activeTool, mode };
      if (target) body.target = target;

      if (activeTool === "disasm-analyzer" && fnName) body.function = fnName;
      if (activeTool === "pwn-toolkit") {
        if (pwnLength) body.length = parseInt(pwnLength, 10) || 200;
        if (pwnFind) body.find = pwnFind;
      }

      const res = await fetch("/api/reversing", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data: ToolResult = await res.json();
      if (!res.ok) {
        setError(data.error || `HTTP ${res.status}`);
      } else {
        setResult(data);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Network error");
    } finally {
      setRunning(false);
    }
  }, [activeTool, target, mode, fnName, pwnLength, pwnFind]);

  const findings = result?.report?.findings || [];

  return (
    <main className="px-6 py-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Reversing & Exploitation</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          CTF binary analysis — reverse engineering, exploitation toolkit, privilege escalation
        </p>
      </div>

      {/* Tool selector tabs */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {TOOLS.map((tool) => (
          <button
            key={tool.id}
            onClick={() => {
              setActiveTool(tool.id);
              setMode("auto");
              setResult(null);
              setError(null);
            }}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTool === tool.id
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--card-bg)] border border-[var(--border)] text-[var(--text-muted)] hover:border-[var(--accent)]"
            }`}
          >
            {tool.icon} {tool.label}
          </button>
        ))}
      </div>

      {/* Tool description */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
        <div className="flex items-center gap-3 mb-2">
          <span className="text-2xl">{currentTool.icon}</span>
          <div>
            <h3 className="font-semibold text-sm">{currentTool.label}</h3>
            <p className="text-xs text-[var(--text-muted)]">{currentTool.desc}</p>
          </div>
        </div>
      </div>

      {/* Input form */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-xs font-medium text-[var(--text-muted)] mb-1">
              {activeTool === "privesc-scanner" ? "Target Host (optional)" : "Target Binary Path"}
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={
                activeTool === "privesc-scanner"
                  ? "localhost (leave empty for local)"
                  : "/path/to/binary"
              }
              className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded text-sm focus:outline-none focus:border-[var(--accent)]"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[var(--text-muted)] mb-1">
              Mode
            </label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded text-sm focus:outline-none focus:border-[var(--accent)]"
            >
              {currentTool.modes.map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Extra fields per tool */}
        {activeTool === "disasm-analyzer" && (
          <div className="mb-4">
            <label className="block text-xs font-medium text-[var(--text-muted)] mb-1">
              Function Name (for disasm mode)
            </label>
            <input
              type="text"
              value={fnName}
              onChange={(e) => setFnName(e.target.value)}
              placeholder="main"
              className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded text-sm font-mono focus:outline-none focus:border-[var(--accent)]"
            />
          </div>
        )}

        {activeTool === "pwn-toolkit" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-xs font-medium text-[var(--text-muted)] mb-1">
                Pattern Length (cyclic mode)
              </label>
              <input
                type="number"
                value={pwnLength}
                onChange={(e) => setPwnLength(e.target.value)}
                placeholder="200"
                className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded text-sm font-mono focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[var(--text-muted)] mb-1">
                Find Offset (hex/string)
              </label>
              <input
                type="text"
                value={pwnFind}
                onChange={(e) => setPwnFind(e.target.value)}
                placeholder="0x41414141"
                className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded text-sm font-mono focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
          </div>
        )}

        <button
          onClick={runTool}
          disabled={running}
          className="px-5 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 disabled:opacity-50 transition-opacity"
        >
          {running ? "Analyzing..." : `Run ${currentTool.label}`}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 mb-6">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Findings */}
          {findings.length > 0 && (
            <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
              <h3 className="font-semibold text-sm mb-4">
                Findings ({findings.length})
              </h3>
              <div className="space-y-3">
                {findings.map((f, i) => (
                  <div
                    key={i}
                    className="bg-[var(--bg)] rounded-lg p-4 border-l-4"
                    style={{ borderColor: SEV_COLORS[f.severity?.toLowerCase()] || SEV_COLORS.info }}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <h4 className="font-medium text-sm">{f.title}</h4>
                      <span
                        className="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase"
                        style={{
                          color: SEV_COLORS[f.severity?.toLowerCase()] || SEV_COLORS.info,
                          background: `${SEV_COLORS[f.severity?.toLowerCase()] || SEV_COLORS.info}20`,
                        }}
                      >
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-xs text-[var(--text-muted)] mb-2">{f.description}</p>
                    {f.evidence && (
                      <pre className="text-[10px] font-mono bg-black/30 rounded p-2 overflow-x-auto whitespace-pre-wrap max-h-40">
                        {f.evidence}
                      </pre>
                    )}
                    {f.impact && (
                      <p className="text-xs text-[var(--text-dim)] mt-2">
                        <strong>Impact:</strong> {f.impact}
                      </p>
                    )}
                    {f.steps && f.steps.length > 0 && (
                      <ol className="text-xs text-[var(--text-dim)] mt-2 list-decimal list-inside space-y-0.5">
                        {f.steps.map((s, j) => <li key={j}>{s}</li>)}
                      </ol>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Raw output */}
          <details className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg">
            <summary className="px-5 py-3 text-sm font-medium cursor-pointer hover:text-[var(--accent)]">
              Raw Output
            </summary>
            <pre className="px-5 pb-4 text-[11px] font-mono text-[var(--text-muted)] overflow-x-auto whitespace-pre-wrap max-h-96">
              {result.output}
            </pre>
          </details>

          {result.stderr && (
            <details className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg">
              <summary className="px-5 py-3 text-sm font-medium cursor-pointer text-yellow-400">
                Stderr
              </summary>
              <pre className="px-5 pb-4 text-[11px] font-mono text-yellow-300/70 overflow-x-auto whitespace-pre-wrap max-h-60">
                {result.stderr}
              </pre>
            </details>
          )}
        </div>
      )}
    </main>
  );
}
