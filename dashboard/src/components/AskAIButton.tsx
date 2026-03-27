// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";

interface AskAIButtonProps {
  finding: {
    title: string;
    severity: string;
    cwe_id?: string;
    cwe?: string;
    description?: string;
    evidence?: string;
    url?: string;
    endpoint?: string;
    tool: string;
  };
}

export default function AskAIButton({ finding }: AskAIButtonProps) {
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const askAI = async () => {
    setLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const res = await fetch("/api/llm/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findings: [{
            title: finding.title,
            severity: finding.severity,
            cwe: finding.cwe_id || finding.cwe || undefined,
            description: finding.description || undefined,
          }],
          prompt: `Explain this vulnerability, assess its real-world impact, and provide specific remediation steps. Finding: ${finding.title} (${finding.severity}) at ${finding.url || finding.endpoint || "unknown endpoint"} found by ${finding.tool}.`,
        }),
      });
      if (!res.ok || !res.body) {
        throw new Error(`HTTP ${res.status}`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let text = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        for (const line of chunk.split("\n")) {
          if (line.startsWith("data: ")) {
            const data = line.slice(6);
            if (data === "[DONE]") break;
            try {
              const parsed = JSON.parse(data);
              if (parsed.chunk) text += parsed.chunk;
            } catch {
              text += data;
            }
          }
        }
        setAnalysis(text);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  if (analysis) {
    return (
      <div className="mt-3">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-xs font-medium text-purple-400">AI Analysis</span>
          <button
            onClick={() => setAnalysis(null)}
            className="text-xs text-[var(--text-muted)] hover:text-[var(--text)] underline"
          >
            dismiss
          </button>
        </div>
        <div className="bg-[var(--bg)] rounded p-3 text-xs whitespace-pre-wrap">{analysis}</div>
      </div>
    );
  }

  return (
    <div className="mt-3">
      <button
        onClick={askAI}
        disabled={loading}
        className="px-3 py-1 text-xs bg-purple-600 text-white rounded hover:opacity-90 disabled:opacity-50 flex items-center gap-1"
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
        </svg>
        {loading ? "Analyzing..." : "Ask AI"}
      </button>
      {error && <p className="text-xs text-red-400 mt-1">{error}</p>}
    </div>
  );
}
