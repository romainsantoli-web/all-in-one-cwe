// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useCallback } from "react";

interface SmartAnalyzeFinding {
  title: string;
  severity: string;
  cwe_id?: string;
  cwe?: string;
  description?: string;
  evidence?: string;
  url?: string;
  endpoint?: string;
  tool: string;
}

type Phase = "idle" | "suggesting" | "confirming" | "executing" | "summarizing" | "done" | "error";

interface SSEEvent {
  event: string;
  tools?: string[];
  reasoning?: string;
  tool?: string;
  output?: string;
  text?: string;
  message?: string;
  phase?: string;
  cwe?: string;
  target?: string;
  [key: string]: unknown;
}

export default function SmartAnalyzeButton({
  finding,
  target,
}: {
  finding: SmartAnalyzeFinding;
  target?: string;
}) {
  const [phase, setPhase] = useState<Phase>("idle");
  const [suggestedTools, setSuggestedTools] = useState<string[]>([]);
  const [reasoning, setReasoning] = useState("");
  const [selectedTools, setSelectedTools] = useState<Set<string>>(new Set());
  const [toolResults, setToolResults] = useState<Array<{ tool: string; output: string }>>([]);
  const [summary, setSummary] = useState("");
  const [error, setError] = useState("");
  const [currentTool, setCurrentTool] = useState("");

  const resolvedTarget = target || finding.url || finding.endpoint || "";

  const parseSSE = useCallback(async (res: Response, onEvent: (evt: SSEEvent) => void) => {
    if (!res.body) return;
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (line.startsWith("data: ")) {
          const data = line.slice(6);
          if (data === "[DONE]") return;
          try {
            onEvent(JSON.parse(data) as SSEEvent);
          } catch { /* skip malformed */ }
        }
      }
    }
  }, []);

  const startSuggest = async () => {
    if (!resolvedTarget) {
      setError("No target URL available for this finding");
      setPhase("error");
      return;
    }

    setPhase("suggesting");
    setError("");
    setSuggestedTools([]);
    setReasoning("");
    setToolResults([]);
    setSummary("");

    try {
      const res = await fetch("/api/llm/smart-analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding: {
            title: finding.title,
            severity: finding.severity,
            cwe: finding.cwe_id || finding.cwe,
            description: finding.description,
            evidence: finding.evidence,
            url: finding.url || finding.endpoint,
            tool: finding.tool,
          },
          target: resolvedTarget,
          phase: "suggest",
        }),
      });

      if (!res.ok) {
        const errBody = await res.text();
        throw new Error(`HTTP ${res.status}: ${errBody}`);
      }

      await parseSSE(res, (evt) => {
        if (evt.event === "suggestions" && evt.tools) {
          setSuggestedTools(evt.tools);
          setSelectedTools(new Set(evt.tools));
          if (evt.reasoning) setReasoning(evt.reasoning);
          setPhase("confirming");
        } else if (evt.event === "error") {
          setError(evt.message ?? "Unknown error");
          setPhase("error");
        }
      });
    } catch (err: unknown) {
      setError((err as Error).message);
      setPhase("error");
    }
  };

  const executeTools = async () => {
    const tools = Array.from(selectedTools);
    if (tools.length === 0) return;

    setPhase("executing");
    setToolResults([]);
    setSummary("");
    setCurrentTool("");

    try {
      const res = await fetch("/api/llm/smart-analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding: {
            title: finding.title,
            severity: finding.severity,
            cwe: finding.cwe_id || finding.cwe,
            description: finding.description,
            url: finding.url || finding.endpoint,
            tool: finding.tool,
          },
          target: resolvedTarget,
          phase: "execute",
          confirmedTools: tools,
        }),
      });

      if (!res.ok) {
        const errBody = await res.text();
        throw new Error(`HTTP ${res.status}: ${errBody}`);
      }

      await parseSSE(res, (evt) => {
        if (evt.event === "tool_start" && evt.tool) {
          setCurrentTool(evt.tool);
        } else if (evt.event === "tool_result" && evt.tool) {
          setToolResults((prev) => [...prev, { tool: evt.tool!, output: evt.output ?? "" }]);
          setCurrentTool("");
        } else if (evt.event === "phase" && evt.phase === "summarize") {
          setPhase("summarizing");
        } else if (evt.event === "summary" && evt.text) {
          setSummary(evt.text);
          setPhase("done");
        } else if (evt.event === "error") {
          setError(evt.message ?? "Unknown error");
          setPhase("error");
        }
      });
    } catch (err: unknown) {
      setError((err as Error).message);
      setPhase("error");
    }
  };

  const toggleTool = (tool: string) => {
    setSelectedTools((prev) => {
      const next = new Set(prev);
      if (next.has(tool)) next.delete(tool);
      else next.add(tool);
      return next;
    });
  };

  const reset = () => {
    setPhase("idle");
    setSuggestedTools([]);
    setReasoning("");
    setSelectedTools(new Set());
    setToolResults([]);
    setSummary("");
    setError("");
    setCurrentTool("");
  };

  // --- IDLE ---
  if (phase === "idle") {
    return (
      <button
        onClick={startSuggest}
        disabled={!resolvedTarget}
        className="px-3 py-1.5 text-xs font-medium rounded bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        title={resolvedTarget ? "AI analyzes finding and suggests tools to investigate" : "No target URL available"}
      >
        ⚡ Smart Analyze
      </button>
    );
  }

  // --- SUGGESTING ---
  if (phase === "suggesting") {
    return (
      <div className="mt-3 p-3 rounded border border-amber-800/30 bg-amber-900/10">
        <div className="flex items-center gap-2">
          <div className="animate-spin h-4 w-4 border-2 border-amber-400 border-t-transparent rounded-full" />
          <span className="text-xs text-amber-400">AI is analyzing the finding and suggesting tools...</span>
        </div>
      </div>
    );
  }

  // --- CONFIRMING ---
  if (phase === "confirming") {
    return (
      <div className="mt-3 p-3 rounded border border-amber-800/30 bg-amber-900/10 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-amber-400">⚡ Smart Analyze — Tool Suggestions</span>
          <button onClick={reset} className="text-xs text-[var(--text-muted)] hover:text-[var(--text)]">✕</button>
        </div>
        {reasoning && <p className="text-xs text-[var(--text-muted)]">{reasoning}</p>}
        <div className="flex flex-wrap gap-2">
          {suggestedTools.map((tool) => (
            <label key={tool} className="flex items-center gap-1.5 text-xs cursor-pointer">
              <input
                type="checkbox"
                checked={selectedTools.has(tool)}
                onChange={() => toggleTool(tool)}
                className="accent-amber-500"
              />
              <span className={selectedTools.has(tool) ? "text-amber-300" : "text-[var(--text-muted)]"}>
                {tool}
              </span>
            </label>
          ))}
        </div>
        <div className="flex gap-2">
          <button
            onClick={executeTools}
            disabled={selectedTools.size === 0}
            className="px-3 py-1 text-xs font-medium rounded bg-amber-600 hover:bg-amber-500 text-white disabled:opacity-50 transition-all"
          >
            Run {selectedTools.size} tool{selectedTools.size !== 1 ? "s" : ""} on {new URL(resolvedTarget).hostname}
          </button>
          <button onClick={reset} className="px-3 py-1 text-xs rounded border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text)]">
            Cancel
          </button>
        </div>
      </div>
    );
  }

  // --- EXECUTING ---
  if (phase === "executing" || phase === "summarizing") {
    return (
      <div className="mt-3 p-3 rounded border border-amber-800/30 bg-amber-900/10 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-amber-400">
            {phase === "executing" ? "⚡ Running tools..." : "🤖 AI summarizing results..."}
          </span>
          <span className="text-xs text-[var(--text-muted)]">
            {toolResults.length}/{selectedTools.size} complete
          </span>
        </div>
        {currentTool && (
          <div className="flex items-center gap-2">
            <div className="animate-spin h-3 w-3 border-2 border-amber-400 border-t-transparent rounded-full" />
            <span className="text-xs text-[var(--text-muted)]">Running {currentTool}...</span>
          </div>
        )}
        {/* Progress bar */}
        <div className="w-full h-1.5 bg-[var(--border)] rounded-full overflow-hidden">
          <div
            className="h-full bg-amber-500 transition-all duration-500"
            style={{ width: `${selectedTools.size > 0 ? (toolResults.length / selectedTools.size) * 100 : 0}%` }}
          />
        </div>
        {toolResults.map((r) => (
          <details key={r.tool} className="text-xs">
            <summary className="cursor-pointer text-green-400">✓ {r.tool}</summary>
            <pre className="mt-1 p-2 bg-[var(--card-bg)] rounded text-[var(--text-muted)] overflow-x-auto max-h-32 overflow-y-auto">
              {r.output.slice(0, 1000) || "No output"}
            </pre>
          </details>
        ))}
        {phase === "summarizing" && (
          <div className="flex items-center gap-2">
            <div className="animate-spin h-3 w-3 border-2 border-purple-400 border-t-transparent rounded-full" />
            <span className="text-xs text-purple-400">AI analyzing combined results...</span>
          </div>
        )}
      </div>
    );
  }

  // --- DONE ---
  if (phase === "done") {
    return (
      <div className="mt-3 p-3 rounded border border-green-800/30 bg-green-900/10 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-green-400">⚡ Smart Analyze Complete</span>
          <button onClick={reset} className="text-xs text-[var(--text-muted)] hover:text-[var(--text)]">✕</button>
        </div>
        {/* Tool results collapsible */}
        {toolResults.map((r) => (
          <details key={r.tool} className="text-xs">
            <summary className="cursor-pointer text-[var(--text-muted)]">📦 {r.tool} output</summary>
            <pre className="mt-1 p-2 bg-[var(--card-bg)] rounded text-[var(--text-muted)] overflow-x-auto max-h-32 overflow-y-auto">
              {r.output.slice(0, 2000)}
            </pre>
          </details>
        ))}
        {/* AI Summary */}
        <div className="border-t border-[var(--border)] pt-2">
          <strong className="text-xs text-purple-400">🤖 AI Analysis Summary</strong>
          <div className="mt-1 text-sm whitespace-pre-wrap text-[var(--text)]">
            {summary}
          </div>
        </div>
        <button onClick={reset} className="text-xs text-[var(--text-muted)] hover:text-[var(--text)] underline">
          Run again
        </button>
      </div>
    );
  }

  // --- ERROR ---
  return (
    <div className="mt-3 p-3 rounded border border-red-800/30 bg-red-900/10 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-red-400">⚡ Smart Analyze Error</span>
        <button onClick={reset} className="text-xs text-[var(--text-muted)] hover:text-[var(--text)]">✕</button>
      </div>
      <p className="text-xs text-red-300">{error}</p>
      <button onClick={startSuggest} className="text-xs text-amber-400 hover:text-amber-300 underline">
        Retry
      </button>
    </div>
  );
}
