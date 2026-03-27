// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";

interface ProviderTestProps {
  providerName: string;
  available: boolean;
}

export default function ProviderTestButton({ providerName, available }: ProviderTestProps) {
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const testProvider = async () => {
    if (!available) return;
    setTesting(true);
    setResult(null);
    setError(null);

    try {
      const res = await fetch("/api/llm/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: providerName,
          messages: [{ role: "user", content: "Reply with exactly: OK" }],
        }),
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      if (!res.body) {
        throw new Error("No response body");
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
              if (parsed.error) throw new Error(parsed.error);
            } catch (e) {
              if (e instanceof Error && e.message !== "Unexpected end of JSON input") {
                if (e.message.startsWith("Tool") || e.message.startsWith("HTTP")) throw e;
              }
              if (data !== "[DONE]") text += data;
            }
          }
        }
      }
      setResult(text.trim() || "No response");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="mt-3 pt-3 border-t border-[var(--border)]">
      <button
        onClick={testProvider}
        disabled={!available || testing}
        className="px-3 py-1.5 text-xs bg-[var(--accent)] text-white rounded hover:opacity-90 disabled:opacity-50"
      >
        {testing ? "Testing..." : "Test Provider"}
      </button>
      {result && (
        <span className="ml-2 text-xs text-green-400">Response: {result.slice(0, 80)}</span>
      )}
      {error && (
        <span className="ml-2 text-xs text-red-400">{error.slice(0, 100)}</span>
      )}
    </div>
  );
}
