// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useRef, useEffect, useCallback } from "react";

interface ChatMsg {
  role: "user" | "assistant" | "tool" | "plan";
  content: string;
  toolName?: string;
  toolArgs?: Record<string, unknown>;
  toolResult?: string;
  isThinking?: boolean;
  planTasks?: Array<{ id: number; title: string; status: string; result?: string }>;
  provider?: string;
  model?: string;
}

interface ProviderInfo {
  name: string;
  model: string;
  available: boolean;
  models: string[];
}

interface ConversationSummary {
  id: string;
  title: string;
  updatedAt: string;
  messageCount: number;
  provider?: string | null;
  model?: string | null;
}

const PROVIDER_ICONS: Record<string, string> = {
  claude: "🟣",
  gpt: "🟢",
  "copilot-pro": "🔵",
  copilot: "⚫",
  mistral: "🟠",
  gemini: "🔴",
};

export default function LLMChat() {
  const [messages, setMessages] = useState<ChatMsg[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [provider, setProvider] = useState("auto");
  const [model, setModel] = useState("");
  const [agentic, setAgentic] = useState(false);
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const bottomRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  // --- Conversation sidebar state ---
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [activeConvId, setActiveConvId] = useState<string | null>(null);
  const [convLoading, setConvLoading] = useState(false);

  // --- Terminal preview state ---
  const [terminals, setTerminals] = useState<Array<{ id: string; tool?: string; status: string }>>([]);

  // Load conversations list
  const loadConversations = useCallback(() => {
    fetch("/api/llm/conversations")
      .then((r) => r.json())
      .then((d) => setConversations(d.conversations || []))
      .catch(() => {});
  }, []);

  // Load terminal status for preview
  useEffect(() => {
    const poll = () =>
      fetch("/api/terminals")
        .then((r) => r.json())
        .then((d) => setTerminals(d.sessions || []))
        .catch(() => {});
    poll();
    const iv = setInterval(poll, 5000);
    return () => clearInterval(iv);
  }, []);

  useEffect(() => {
    loadConversations();
  }, [loadConversations]);

  // Save conversation on message change (debounced)
  useEffect(() => {
    if (messages.length < 2 || streaming) return;
    const timer = setTimeout(() => {
      const id = activeConvId || `conv-${Date.now()}`;
      if (!activeConvId) setActiveConvId(id);
      const firstUserMsg = messages.find((m) => m.role === "user");
      const title = firstUserMsg?.content.slice(0, 80) || "New conversation";
      fetch("/api/llm/conversations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, title, messages, provider, model }),
      })
        .then(() => loadConversations())
        .catch(() => {});
    }, 2000);
    return () => clearTimeout(timer);
  }, [messages, streaming, activeConvId, provider, model, loadConversations]);

  // Load a specific conversation
  const loadConversation = async (id: string) => {
    setConvLoading(true);
    try {
      const r = await fetch(`/api/llm/conversations?id=${encodeURIComponent(id)}`);
      const d = await r.json();
      if (d.messages) {
        setMessages(d.messages);
        setActiveConvId(id);
        if (d.provider) setProvider(d.provider);
        if (d.model) setModel(d.model);
      }
    } catch { /* noop */ }
    setConvLoading(false);
  };

  // New conversation
  const newConversation = () => {
    setMessages([]);
    setActiveConvId(null);
  };

  // Delete conversation
  const deleteConversation = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await fetch("/api/llm/conversations", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      if (activeConvId === id) newConversation();
      loadConversations();
    } catch { /* noop */ }
  };

  useEffect(() => {
    fetch("/api/llm/providers")
      .then((r) => r.json())
      .then((d) => {
        const list: ProviderInfo[] = d.providers || [];
        setProviders(list);
        // Default model from auto provider
        const autoP = list.find((p) => p.available);
        if (autoP) setModel(autoP.model);
      })
      .catch(() => {});
  }, []);

  // Update model when provider changes
  useEffect(() => {
    if (provider === "auto") {
      const autoP = providers.find((p) => p.available);
      if (autoP) setModel(autoP.model);
    } else {
      const p = providers.find((pr) => pr.name === provider);
      if (p) setModel(p.model);
    }
  }, [provider, providers]);

  const currentProvider = provider === "auto"
    ? providers.find((p) => p.available)
    : providers.find((p) => p.name === provider);

  const currentModels = currentProvider?.models || [];

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

    const resolvedProvider = provider === "auto"
      ? providers.find((p) => p.available)?.name || provider
      : provider;

    const assistantMsg: ChatMsg = {
      role: "assistant",
      content: "",
      provider: resolvedProvider,
      model: model,
    };
    setMessages([...newMessages, assistantMsg]);

    try {
      abortRef.current = new AbortController();
      const selectedProvider = resolvedProvider;

      const convId = activeConvId || `conv-${Date.now()}`;
      if (!activeConvId) setActiveConvId(convId);

      const res = await fetch("/api/llm/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: newMessages
            .filter((m) => m.role === "user" || m.role === "assistant")
            .map((m) => ({ role: m.role, content: m.content })),
          provider: selectedProvider,
          model: model || undefined,
          agentic,
          conversationId: convId,
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
      const toolEvents: ChatMsg[] = [];

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = decoder.decode(value, { stream: true });
          const lines = chunk.split("\n");
          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const data = line.slice(6);
            if (data === "[DONE]") continue;
            try {
              const parsed = JSON.parse(data);

              if (parsed.event === "thinking") {
                // Update assistant message to show thinking indicator
                setMessages((prev) => [
                  ...prev.slice(0, -(1 + toolEvents.length)),
                  ...toolEvents,
                  { role: "assistant", content: fullText, isThinking: true },
                ]);
                continue;
              }

              if (parsed.event === "tool_call") {
                if (parsed.tool === "update_plan") {
                  // Plan updates get their own card — supersede any prior plan card
                  const planMsg: ChatMsg = {
                    role: "plan",
                    content: "Updating plan...",
                    toolName: "update_plan",
                    toolArgs: parsed.arguments,
                    planTasks: parsed.arguments?.tasks || [],
                  };
                  // Remove previous plan card if exists and add the new one
                  const existingPlanIdx = toolEvents.findIndex((e) => e.role === "plan");
                  if (existingPlanIdx >= 0) {
                    toolEvents[existingPlanIdx] = planMsg;
                  } else {
                    toolEvents.push(planMsg);
                  }
                } else {
                  const toolMsg: ChatMsg = {
                    role: "tool",
                    content: `Calling **${parsed.tool}**...`,
                    toolName: parsed.tool,
                    toolArgs: parsed.arguments,
                  };
                  toolEvents.push(toolMsg);
                }
                setMessages((prev) => [
                  ...prev.slice(0, -(1 + toolEvents.length - 1)),
                  ...toolEvents,
                  { role: "assistant", content: fullText },
                ]);
                continue;
              }

              if (parsed.event === "tool_result") {
                // Update the last matching tool event with the result
                if (parsed.tool === "update_plan") {
                  const planIdx = toolEvents.findIndex((e) => e.role === "plan");
                  if (planIdx >= 0) {
                    try {
                      const planData = JSON.parse(parsed.result);
                      toolEvents[planIdx].planTasks = planData.tasks || [];
                      toolEvents[planIdx].content = planData.progress || "Plan updated";
                    } catch {
                      toolEvents[planIdx].content = "Plan updated";
                    }
                  }
                } else {
                  const lastTool = toolEvents[toolEvents.length - 1];
                  if (lastTool && lastTool.role === "tool") {
                    lastTool.content = `**${parsed.tool}** completed (${parsed.elapsed_ms}ms)`;
                    lastTool.toolResult = parsed.result;
                  }
                }
                setMessages((prev) => [
                  ...prev.slice(0, -(1 + toolEvents.length)),
                  ...toolEvents,
                  { role: "assistant", content: fullText },
                ]);
                continue;
              }

              if (parsed.event === "error") {
                fullText += `\n⚠️ ${parsed.message}`;
              } else if (parsed.event === "max_steps_reached") {
                fullText += "\n\n⚠️ *Max agent steps reached — summarizing...*\n\n";
              } else if (parsed.chunk) {
                fullText += parsed.chunk;
              } else if (parsed.error) {
                fullText += `\n⚠️ ${parsed.error}`;
              }
            } catch {
              fullText += data;
            }
          }
          setMessages((prev) => [
            ...prev.slice(0, -(1 + toolEvents.length)),
            ...toolEvents,
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
    <div className="flex h-full">
      {/* ===== Conversation Sidebar ===== */}
      {sidebarOpen && (
        <div className="chat-sidebar">
          <div className="chat-sidebar-header">
            <span className="text-xs font-semibold text-[var(--text-muted)]">CONVERSATIONS</span>
            <button
              onClick={newConversation}
              title="New conversation"
              className="text-xs px-2 py-1 rounded bg-[var(--accent)] text-white hover:opacity-90"
            >
              + New
            </button>
          </div>
          <div className="chat-sidebar-list">
            {convLoading && (
              <div className="text-xs text-[var(--text-dim)] p-3 text-center">Loading...</div>
            )}
            {conversations.map((c) => (
              <div
                key={c.id}
                onClick={() => loadConversation(c.id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && loadConversation(c.id)}
                className={`chat-sidebar-item ${c.id === activeConvId ? "active" : ""}`}
              >
                <div className="flex-1 min-w-0">
                  <div className="truncate text-xs">{c.title}</div>
                  <div className="text-[10px] text-[var(--text-dim)] mt-0.5 flex items-center gap-1">
                    {c.model && <span className="truncate">{c.model.split("/").pop()}</span>}
                    <span>· {c.messageCount} msgs</span>
                  </div>
                </div>
                <button
                  onClick={(e) => deleteConversation(c.id, e)}
                  className="text-[var(--text-dim)] hover:text-red-400 text-xs px-1 flex-shrink-0"
                  title="Delete"
                >
                  ✕
                </button>
              </div>
            ))}
            {conversations.length === 0 && !convLoading && (
              <div className="text-xs text-[var(--text-dim)] p-3 text-center">No conversations yet</div>
            )}
          </div>
          {/* Terminal preview */}
          {terminals.filter((t) => t.status === "running").length > 0 && (
            <div className="chat-sidebar-terminals">
              <div className="text-[10px] font-semibold text-[var(--text-dim)] px-3 py-1">
                ACTIVE TERMINALS
              </div>
              {terminals
                .filter((t) => t.status === "running")
                .slice(0, 3)
                .map((t) => (
                  <div key={t.id} className="chat-terminal-badge">
                    <span className="chat-terminal-dot" />
                    <span className="truncate">{t.tool || t.id.slice(0, 8)}</span>
                  </div>
                ))}
            </div>
          )}
        </div>
      )}

      {/* ===== Main Chat Area ===== */}
      <div className="flex flex-col flex-1 min-w-0">
        {/* Top bar with sidebar toggle */}
        <div className="flex items-center gap-2 px-4 py-2 border-b border-[var(--border)] bg-[var(--card-bg)]">
          <button
            onClick={() => setSidebarOpen((o) => !o)}
            title={sidebarOpen ? "Hide sidebar" : "Show conversations"}
            className="text-sm px-2 py-1 rounded hover:bg-[var(--bg)] text-[var(--text-muted)] transition-colors"
          >
            {sidebarOpen ? "◀" : "☰"}
          </button>
          <span className="text-xs text-[var(--text-dim)]">
            {activeConvId ? conversations.find((c) => c.id === activeConvId)?.title || "Chat" : "New Chat"}
          </span>
          {streaming && (
            <div className="ml-auto flex items-center gap-1.5">
              <span className="chat-thinking-dots"><span /><span /><span /></span>
              <span className="text-[10px] text-[var(--text-muted)]">Generating...</span>
            </div>
          )}
        </div>

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
            <div key={i}>
              {msg.role === "plan" ? (
                /* Task plan card */
                <div className="flex justify-start">
                  <div className="max-w-[85%] rounded-lg px-4 py-3 text-sm bg-[var(--bg)] border border-blue-600/30">
                    <div className="flex items-center gap-2 text-blue-400 text-xs font-semibold mb-2">
                      <span>📋</span>
                      <span>Task Plan</span>
                      <span className="text-[var(--text-dim)] font-normal ml-auto">{msg.content}</span>
                    </div>
                    {msg.planTasks && msg.planTasks.length > 0 && (
                      <div className="space-y-1">
                        {msg.planTasks.map((task) => (
                          <div key={task.id} className="flex items-start gap-2 text-xs">
                            <span className="mt-0.5 flex-shrink-0">
                              {task.status === "done" ? "✅" :
                               task.status === "in-progress" ? "🔄" :
                               task.status === "failed" ? "❌" : "⬜"}
                            </span>
                            <span className={task.status === "done" ? "text-green-400" :
                                             task.status === "in-progress" ? "text-yellow-400" :
                                             task.status === "failed" ? "text-red-400" :
                                             "text-[var(--text-muted)]"}>
                              <span className="font-medium">{task.id}.</span> {task.title}
                              {task.result && (
                                <span className="text-[var(--text-dim)] ml-1">— {task.result}</span>
                              )}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ) : msg.role === "tool" ? (
                /* Tool call card — VS Code style */
                <div className="flex justify-start">
                  <div className="max-w-[80%] rounded-lg px-4 py-2 text-sm bg-[var(--bg)] border border-yellow-600/30">
                    <div className="flex items-center gap-2 text-yellow-500 text-xs font-medium mb-1">
                      <span className="chat-tool-icon">⚙</span>
                      <span>{msg.content}</span>
                      {msg.toolResult && <span className="text-green-500 ml-auto">✓</span>}
                    </div>
                    {msg.toolArgs && (
                      <details className="mt-1">
                        <summary className="text-[10px] text-[var(--text-dim)] cursor-pointer hover:text-[var(--text)]">
                          Parameters
                        </summary>
                        <pre className="text-[10px] text-[var(--text-dim)] overflow-x-auto max-h-20 mt-1 bg-[var(--card-bg)] rounded p-2">
                          {JSON.stringify(msg.toolArgs, null, 2)}
                        </pre>
                      </details>
                    )}
                    {msg.toolResult && (
                      <details className="mt-1">
                        <summary className="text-[10px] text-[var(--text-muted)] cursor-pointer hover:text-[var(--text)]">
                          Output ({(msg.toolResult.length / 1024).toFixed(1)}KB)
                        </summary>
                        <pre className="text-[10px] text-[var(--text-dim)] overflow-x-auto max-h-40 mt-1 whitespace-pre-wrap bg-[var(--card-bg)] rounded p-2">
                          {msg.toolResult.slice(0, 3000)}
                        </pre>
                      </details>
                    )}
                  </div>
                </div>
              ) : (
                /* Normal message (user/assistant) */
                <div className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                  <div
                    className={`max-w-[80%] rounded-lg px-4 py-3 text-sm ${
                      msg.role === "user"
                        ? "bg-[var(--accent)] text-white"
                        : "bg-[var(--card-bg)] border border-[var(--border)]"
                    }`}
                  >
                    {/* VS Code-style thinking indicator */}
                    {msg.isThinking && streaming && (
                      <div className="flex items-center gap-2 text-[var(--text-muted)] text-xs mb-2">
                        <span className="chat-thinking-dots"><span /><span /><span /></span>
                        <span>Thinking...</span>
                      </div>
                    )}
                    <div className="whitespace-pre-wrap">
                      {msg.content || (streaming && i === messages.length - 1
                        ? <span className="chat-thinking-dots"><span /><span /><span /></span>
                        : "")}
                    </div>
                    {/* Model badge — VS Code style */}
                    {msg.role === "assistant" && msg.content && !msg.isThinking && (
                      <div className="chat-model-badge">
                        {msg.provider && <span>{PROVIDER_ICONS[msg.provider] || "🤖"}</span>}
                        <span>{msg.model?.split("/").pop() || msg.provider || "auto"}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
          <div ref={bottomRef} />
        </div>

        {/* Input bar */}
        <div className="border-t border-[var(--border)] p-4 bg-[var(--card-bg)]">
          {/* Provider + Model selectors */}
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            {/* Provider selector */}
            <div className="flex items-center gap-1 bg-[var(--bg)] border border-[var(--border)] rounded px-1">
              <button
                onClick={() => setProvider("auto")}
                className={`px-2 py-1 text-xs rounded transition-colors ${
                  provider === "auto"
                    ? "bg-[var(--accent)] text-white"
                    : "text-[var(--text-muted)] hover:text-[var(--text)]"
                }`}
              >
                Auto
              </button>
              {providers.map((p) => (
                <button
                  key={p.name}
                  onClick={() => p.available && setProvider(p.name)}
                  disabled={!p.available}
                  title={`${p.name}${p.available ? "" : " (not configured)"}`}
                  className={`flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors ${
                    provider === p.name
                      ? "bg-[var(--accent)] text-white"
                      : p.available
                      ? "text-[var(--text-muted)] hover:text-[var(--text)]"
                      : "text-[var(--text-dim)] opacity-40 cursor-not-allowed"
                  }`}
                >
                  <span className="text-sm">{PROVIDER_ICONS[p.name] || "🤖"}</span>
                  <span className="hidden sm:inline">{p.name}</span>
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      p.available ? "bg-green-500" : "bg-red-500"
                    }`}
                  />
                </button>
              ))}
            </div>

            {/* Model selector */}
            {currentModels.length > 0 && (
              <select
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="text-xs bg-[var(--bg)] border border-[var(--border)] rounded px-2 py-1.5 text-[var(--text)] font-mono max-w-[220px]"
              >
                {currentModels.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            )}

            {/* Agentic toggle */}
            <button
              onClick={() => setAgentic((a) => !a)}
              title={agentic ? "Agentic mode ON — LLM can use tools & shell" : "Agentic mode OFF — chat only"}
              className={`flex items-center gap-1 px-2 py-1 text-xs rounded border transition-colors ${
                agentic
                  ? "bg-yellow-600/20 border-yellow-600/50 text-yellow-400"
                  : "border-[var(--border)] text-[var(--text-dim)] hover:text-[var(--text)]"
              }`}
            >
              <span>{agentic ? "⚡" : "💬"}</span>
              <span>{agentic ? "Agent" : "Chat"}</span>
            </button>

            {streaming && (
              <button onClick={stop} className="text-xs text-red-400 hover:text-red-300 ml-auto">
                ⏹ Stop
              </button>
            )}
          </div>

          <div className="flex gap-2">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={agentic ? "Describe your security task — the agent will plan and execute..." : "Ask about security, paste findings, or request analysis..."}
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
    </div>
  );
}
