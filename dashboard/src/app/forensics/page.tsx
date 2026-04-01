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

type ActiveTool = "crypto-analyzer" | "steg-analyzer" | "pcap-analyzer" | "forensic-toolkit";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TOOLS: { id: ActiveTool; label: string; icon: string; desc: string; modes: string[] }[] = [
  {
    id: "crypto-analyzer",
    label: "Crypto Analyzer",
    icon: "🔐",
    desc: "Hash identification, encoding chains, frequency analysis, Caesar/XOR bruteforce, RSA weakness detection",
    modes: ["auto", "identify", "decode", "analyze", "caesar", "xor", "rsa"],
  },
  {
    id: "steg-analyzer",
    label: "Steg Analyzer",
    icon: "🖼️",
    desc: "Steganography detection: magic bytes, strings extraction, appended data, embedded files, entropy analysis",
    modes: ["auto", "magic", "strings", "embedded", "entropy", "exif"],
  },
  {
    id: "pcap-analyzer",
    label: "PCAP Analyzer",
    icon: "📡",
    desc: "Network forensics: protocol distribution, credential sniffing, DNS exfiltration, HTTP extraction",
    modes: ["auto", "credentials", "dns", "http"],
  },
  {
    id: "forensic-toolkit",
    label: "Forensic Toolkit",
    icon: "🔬",
    desc: "Digital forensics: file metadata, timestomping detection, string search, file carving, Volatility memory analysis",
    modes: ["auto", "metadata", "strings", "carve", "volatility"],
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

export default function ForensicsPage() {
  const [activeTool, setActiveTool] = useState<ActiveTool>("crypto-analyzer");
  const [target, setTarget] = useState("");
  const [input, setInput] = useState("");
  const [mode, setMode] = useState("auto");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ToolResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const currentTool = TOOLS.find((t) => t.id === activeTool)!;

  const runTool = useCallback(async () => {
    if (!target && !input) {
      setError("Provide a target file path or direct input");
      return;
    }

    setRunning(true);
    setError(null);
    setResult(null);

    try {
      const body: Record<string, string> = { tool: activeTool, mode };
      if (target) body.target = target;
      if (input && activeTool === "crypto-analyzer") body.input = input;

      const res = await fetch("/api/forensics", {
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
  }, [activeTool, target, input, mode]);

  const findings = result?.report?.findings || [];

  return (
    <main className="px-6 py-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Forensics & Crypto</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          CTF forensics toolkit — cryptanalysis, steganography, network captures, digital forensics
        </p>
      </div>

      {/* Tool selector tabs */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {TOOLS.map((tool) => (
          <button
            key={tool.id}
            onClick={() => { setActiveTool(tool.id); setMode("auto"); setResult(null); setError(null); }}
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
              Target File Path
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="/path/to/file.bin"
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

        {/* Direct input (crypto only) */}
        {activeTool === "crypto-analyzer" && (
          <div className="mb-4">
            <label className="block text-xs font-medium text-[var(--text-muted)] mb-1">
              Direct Input (hash, ciphertext, encoded string)
            </label>
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="e.g. 5d41402abc4b2a76b9719d911017c592  or  aGVsbG8gd29ybGQ="
              rows={3}
              className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded text-sm font-mono focus:outline-none focus:border-[var(--accent)]"
            />
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
