// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useRef, useEffect, useCallback } from "react";

interface ChatMsg {
  role: "user" | "assistant";
  content: string;
}

export default function LLMChat() {
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [provider, setProvider] = useState("auto");
  const [providers, setProviders] = useState<Array<{ name: string; model: string; available: boolean }>>([]);
  const bottomRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    fetch("/api/llm/providers")
      .then((r) => r.json())
      .then((d) => setProviders(d.providers || []))
      .catch(() => {});
  }, []);

  const scrollToBottom = useCallback(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(scrollToBottom, [messages, scrollToBottom]);

  const send = async () => {
    const trimmed = input.trim();
    if (!trimmed || streaming) return;

    const userMsg: ChatMsg = { role: "user", content: trimmed };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setStreaming(true);

    const assistantMsg: ChatMsg = { role: "assistant", content: "" };
    setMessages([...newMessages, assistantMsg]);

    try {
      abortRef.current = new AbortController();
      const selectedProvider = provider === "auto" 
        ? providers.find((p) => p.available)?.name 
        : provider;

      const res = await fetch("/api/llm/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
          provider: selectedProvider,
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Request failed" }));
        setMessages((prev) => [
          ...prev.slice(0, -1),
          { role: "assistant", content: `⚠️ Error: ${err.error}` },
        ]);
        setStreaming(false);
        return;
      }

      const reader = res.body?.getReader();
      const decoder = new TextDecoder();
      let fullText = "";

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value, { stream: true });
          // Parse SSE lines
          const lines = chunk.split("\n");
          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const data = line.slice(6);
            if (data === "[DONE]") continue;
            try {
              const parsed = JSON.parse(data);
              if (parsed.chunk) fullText += parsed.chunk;
              else if (parsed.error) fullText += `\n⚠️ ${parsed.error}`;
            } catch {
              fullText += data;
            }
          }
          setMessages((prev) => [
            ...prev.slice(0, -1),
            { role: "assistant", content: fullText },
          ]);
        }
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        setMessages((prev) => [
          ...prev.slice(0, -1),
          { role: "assistant", content: `⚠️ Error: ${(err as Error).message}` },
        ]);
      }
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  const stop = () => abortRef.current?.abort();

  return (
    <div className="flex flex-col h-full">
      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-4 p-4">
        {messages.length === 0 && (
          <div className="text-center text-[var(--text-dim)] py-12">
            <div className="text-4xl mb-4">🛡️</div>
            <p className="text-lg font-semibold mb-2">Security AI Assistant</p>
            <p className="text-sm max-w-md mx-auto">
              Ask about vulnerabilities, CWEs, exploitation techniques, or paste findings for analysis.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-6 max-w-lg mx-auto">
              {[
                "Explain CWE-918 (SSRF) and how to test for it",
                "Write a remediation plan for SQL injection findings",
                "What tools should I run for API security testing?",
                "Analyze this finding and rate its severity",
              ].map((suggestion) => (
                <button
                  key={suggestion}
                  onClick={() => setInput(suggestion)}
                  className="text-left text-xs p-3 rounded-lg border border-[var(--border)] hover:border-[var(--border-hover)] bg-[var(--card-bg)] transition-colors"
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
          >
            <div
              className={`max-w-[80%] rounded-lg px-4 py-3 text-sm ${
                msg.role === "user"
                  ? "bg-[var(--accent)] text-white"
                  : "bg-[var(--card-bg)] border border-[var(--border)]"
              }`}
            >
              <div className="whitespace-pre-wrap">{msg.content || (streaming && i === messages.length - 1 ? "..." : "")}</div>
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Input bar */}
      <div className="border-t border-[var(--border)] p-4 bg-[var(--card-bg)]">
        <div className="flex items-center gap-2 mb-2">
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="text-xs bg-[var(--bg)] border border-[var(--border)] rounded px-2 py-1 text-[var(--text)]"
          >
            <option value="auto">Auto (best available)</option>
            {providers.map((p) => (
              <option key={p.name} value={p.name} disabled={!p.available}>
                {p.name} — {p.model} {p.available ? "✓" : "✗"}
              </option>
            ))}
          </select>
          {streaming && (
            <button onClick={stop} className="text-xs text-red-400 hover:text-red-300">
              ⏹ Stop
            </button>
          )}
        </div>
        <div className="flex gap-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about security, paste findings, or request analysis..."
            rows={2}
            className="flex-1 bg-[var(--bg)] border border-[var(--border)] rounded-lg p-3 text-sm text-[var(--text)] placeholder:text-[var(--text-dim)] resize-none focus:outline-none focus:border-[var(--accent)]"
          />
          <button
            onClick={send}
            disabled={streaming || !input.trim()}
            className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium disabled:opacity-50 hover:opacity-90 transition-opacity self-end"
          >
            Send
          </button>
        </div>
      </div>
    </div>
  );
}
