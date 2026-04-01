// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import TerminalPanel from "@/components/TerminalPanel";
import InteractiveTerminal from "@/components/InteractiveTerminal";
import AdbCaptureTerminal from "@/components/AdbCaptureTerminal";
import type { AdbCaptureConfig } from "@/components/TerminalBubble";

/* ---------- types ---------- */

interface TerminalInfo {
  id: string;
  tool: string | null;
  tools: string[];
  target: string;
  status: string;
  pid: number | null;
  createdAt: string;
  updatedAt: string;
  findings: number;
  error: string | null;
}

interface AISession {
  id: string;
  provider: string;
  label: string;
  status: string;
  createdAt: string;
  pid: number | null;
  exitCode: number | null;
  error: string | null;
}

interface ProviderInfo {
  id: string;
  label: string;
  command: string;
  available: boolean;
}

interface BridgeStatus {
  configured: boolean;
  tokenCached: boolean;
  tokenExpiresAt: string | null;
  targets: Array<{ id: string; label: string; model: string; provider: string }>;
}

type SidebarTab = "terminals" | "connect";

/* Selected item: either a scan terminal or an AI session */
interface SelectedItem {
  type: "scan" | "ai";
  id: string;
}

interface TerminalOverlayProps {
  isOpen: boolean;
  onClose: () => void;
  adbCapture?: AdbCaptureConfig | null;
}

export default function TerminalOverlay({ isOpen, onClose, adbCapture }: TerminalOverlayProps) {
  const [terminals, setTerminals] = useState<TerminalInfo[]>([]);
  const [aiSessions, setAiSessions] = useState<AISession[]>([]);
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [bridge, setBridge] = useState<BridgeStatus | null>(null);
  const [selected, setSelected] = useState<SelectedItem | null>(null);
  const [sidebarTab, setSidebarTab] = useState<SidebarTab>("terminals");
  const [message, setMessage] = useState<string | null>(null);
  const [launching, setLaunching] = useState<string | null>(null);
  const [bridgeTesting, setBridgeTesting] = useState(false);
  const overlayRef = useRef<HTMLDivElement>(null);

  /* ---------- data fetching ---------- */

  const fetchTerminals = useCallback(async () => {
    try {
      const res = await fetch("/api/terminals");
      const data = await res.json();
      setTerminals((data.terminals || []) as TerminalInfo[]);
    } catch { /* ignore */ }
  }, []);

  const fetchAiSessions = useCallback(async () => {
    try {
      const res = await fetch("/api/terminals/ai-session");
      const data = await res.json();
      setAiSessions((data.sessions || []) as AISession[]);
      setProviders((data.providers || []) as ProviderInfo[]);
      if (data.bridge) setBridge(data.bridge as BridgeStatus);
    } catch { /* ignore */ }
  }, []);

  const fetchAll = useCallback(async () => {
    await Promise.all([fetchTerminals(), fetchAiSessions()]);
  }, [fetchTerminals, fetchAiSessions]);

  useEffect(() => {
    if (!isOpen) return;
    fetchAll();
    const interval = setInterval(fetchAll, 2000);
    return () => clearInterval(interval);
  }, [isOpen, fetchAll]);

  // Auto-select first running item if nothing selected
  useEffect(() => {
    if (selected) {
      // Verify selection still exists
      if (selected.type === "scan") {
        if (terminals.find((t) => t.id === selected.id)) return;
      } else {
        if (aiSessions.find((s) => s.id === selected.id)) return;
      }
    }
    // Pick first running AI session, then scan terminal, then first of anything
    const runningAi = aiSessions.find((s) => s.status === "running");
    if (runningAi) { setSelected({ type: "ai", id: runningAi.id }); return; }
    const runningScan = terminals.find((t) => t.status === "running");
    if (runningScan) { setSelected({ type: "scan", id: runningScan.id }); return; }
    if (aiSessions.length > 0) { setSelected({ type: "ai", id: aiSessions[0].id }); return; }
    if (terminals.length > 0) { setSelected({ type: "scan", id: terminals[0].id }); return; }
    setSelected(null);
  }, [terminals, aiSessions, selected]);

  // Close on Escape
  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  /* ---------- actions ---------- */

  const killJob = async (jobId: string) => {
    try {
      const res = await fetch("/api/terminals", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jobId }),
      });
      if (res.ok) {
        setMessage(`Killed ${jobId.slice(0, 8)}`);
        await fetchTerminals();
      } else {
        const err = await res.json();
        setMessage(err.error || "Kill failed");
      }
    } catch {
      setMessage("Network error");
    }
    setTimeout(() => setMessage(null), 2500);
  };

  const killAiSession = async (sessionId: string) => {
    try {
      const res = await fetch("/api/terminals/ai-session", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId }),
      });
      if (res.ok) {
        setMessage(`Killed ${sessionId.slice(0, 8)}`);
        await fetchAiSessions();
      } else {
        const err = await res.json();
        setMessage(err.error || "Kill failed");
      }
    } catch {
      setMessage("Network error");
    }
    setTimeout(() => setMessage(null), 2500);
  };

  const removeSession = async (itemType: "ai" | "scan", itemId: string) => {
    try {
      if (itemType === "ai") {
        const res = await fetch("/api/terminals/ai-session", {
          method: "DELETE",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sessionId: itemId, remove: true }),
        });
        if (res.ok) {
          if (selected?.id === itemId) setSelected(null);
          await fetchAiSessions();
        }
      } else {
        await killJob(itemId);
      }
    } catch { /* ignore */ }
  };

  const killAll = async () => {
    const runningScans = terminals.filter((t) => t.status === "running");
    const runningAi = aiSessions.filter((s) => s.status === "running");
    for (const t of runningScans) await killJob(t.id);
    for (const s of runningAi) await killAiSession(s.id);
  };

  const launchAiSession = async (providerId: string, useBridge = false) => {
    setLaunching(providerId + (useBridge ? "-bridge" : ""));
    try {
      const res = await fetch("/api/terminals/ai-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: providerId, useBridge }),
      });
      const data = await res.json();
      if (res.ok && data.session) {
        setSelected({ type: "ai", id: data.session.id });
        setSidebarTab("terminals");
        await fetchAiSessions();
        const suffix = data.bridged ? " (via Copilot)" : "";
        setMessage(`${data.session.label}${suffix} started`);
      } else {
        setMessage(data.error || "Failed to launch");
      }
    } catch {
      setMessage("Network error");
    }
    setLaunching(null);
    setTimeout(() => setMessage(null), 2500);
  };

  const testBridge = async () => {
    setBridgeTesting(true);
    try {
      const res = await fetch("/api/copilot/bridge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "test" }),
      });
      const data = await res.json();
      if (data.ok) {
        setMessage("✓ Copilot bridge connected!");
        await fetchAiSessions(); // refresh bridge status
      } else {
        setMessage(data.error || "Bridge test failed");
      }
    } catch {
      setMessage("Network error");
    }
    setBridgeTesting(false);
    setTimeout(() => setMessage(null), 4000);
  };

  /* ---------- computed ---------- */

  const activeScanTerm = selected?.type === "scan"
    ? terminals.find((t) => t.id === selected.id)
    : null;
  const activeAiSession = selected?.type === "ai"
    ? aiSessions.find((s) => s.id === selected.id)
    : null;

  const runningCount =
    terminals.filter((t) => t.status === "running").length +
    aiSessions.filter((s) => s.status === "running").length;

  const allItems = [
    ...aiSessions.map((s) => ({ ...s, _type: "ai" as const })),
    ...terminals.map((t) => ({ ...t, _type: "scan" as const, label: t.tool || t.tools.join(", ").slice(0, 20) || "scan", provider: "scan" })),
  ];

  if (!isOpen) return null;

  /* ---------- helpers ---------- */

  const statusDot = (status: string) => {
    const colors: Record<string, string> = {
      running: "#3b82f6",
      completed: "#22c55e",
      failed: "#ef4444",
      cancelled: "#eab308",
      stopped: "#eab308",
      error: "#ef4444",
      queued: "#888888",
    };
    return colors[status] || "#888888";
  };

  const timeAgo = (iso: string) => {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60_000) return `${Math.floor(diff / 1000)}s`;
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m`;
    return `${Math.floor(diff / 3_600_000)}h`;
  };

  const providerIcon = (provider: string) => {
    if (provider === "claude-code") return "🟣";
    if (provider === "mistral-vibe") return "🟠";
    if (provider === "shell") return "⚡";
    return "🔧";
  };

  /* ---------- render ---------- */

  return (
    <div className="terminal-overlay" ref={overlayRef}>
      {/* Backdrop */}
      <div className="terminal-overlay-backdrop" onClick={onClose} />

      {/* Terminal window */}
      <div className="terminal-overlay-window">
        {/* Sidebar */}
        <div className="terminal-overlay-sidebar">
          {/* Tab switcher */}
          <div className="terminal-overlay-sidebar-header">
            <div className="flex gap-0.5 bg-[#21262d] rounded-md p-0.5">
              <button
                onClick={() => setSidebarTab("terminals")}
                className={`text-[10px] px-2 py-1 rounded transition-colors ${
                  sidebarTab === "terminals"
                    ? "bg-[#30363d] text-[var(--text)]"
                    : "text-[var(--text-muted)] hover:text-[var(--text)]"
                }`}
              >
                Sessions
              </button>
              <button
                onClick={() => setSidebarTab("connect")}
                className={`text-[10px] px-2 py-1 rounded transition-colors ${
                  sidebarTab === "connect"
                    ? "bg-[#30363d] text-[var(--text)]"
                    : "text-[var(--text-muted)] hover:text-[var(--text)]"
                }`}
              >
                Connect
              </button>
            </div>
            {runningCount > 0 && (
              <button
                onClick={killAll}
                className="text-[10px] px-1.5 py-0.5 bg-red-900/30 text-red-400 rounded hover:bg-red-900/50 transition-colors"
                title="Kill all running"
              >
                Kill All
              </button>
            )}
          </div>

          {/* Tab content */}
          <div className="terminal-overlay-sidebar-list">
            {sidebarTab === "terminals" ? (
              /* ── Sessions list ── */
              allItems.length === 0 ? (
                <div className="px-3 py-6 text-center">
                  <div className="text-[10px] text-[var(--text-dim)]">No sessions</div>
                  <div className="text-[9px] text-[var(--text-dim)] mt-1">
                    Connect an AI or run a scan
                  </div>
                </div>
              ) : (
                allItems.map((item) => {
                  const isActive =
                    selected?.type === item._type &&
                    selected?.id === item.id;
                  const isAi = item._type === "ai";
                  return (
                    <div
                      key={`${item._type}-${item.id}`}
                      role="button"
                      tabIndex={0}
                      onClick={() => setSelected({ type: item._type, id: item.id })}
                      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setSelected({ type: item._type, id: item.id }); }}
                      className={`terminal-overlay-sidebar-item group ${isActive ? "active" : ""}`}
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className="inline-block w-2 h-2 rounded-full flex-shrink-0"
                          style={{
                            backgroundColor: statusDot(item.status),
                            boxShadow: item.status === "running" ? `0 0 6px ${statusDot(item.status)}` : "none",
                          }}
                        />
                        <span className="text-[11px]">{isAi ? providerIcon(item.provider) : ""}</span>
                        <span className="truncate text-xs">{item.label}</span>
                      </div>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        <span className="text-[10px] text-[var(--text-dim)]">
                          {timeAgo(item.createdAt)}
                        </span>
                        {item.status === "running" && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (isAi) killAiSession(item.id);
                              else killJob(item.id);
                            }}
                            className="text-[10px] text-red-400 hover:text-red-300 transition-colors"
                            title="Kill"
                          >
                            ✕
                          </button>
                        )}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            removeSession(item._type, item.id);
                          }}
                          className="text-[10px] text-[var(--text-dim)] hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
                          title="Remove session"
                        >
                          🗑
                        </button>
                      </div>
                    </div>
                  );
                })
              )
            ) : (
              /* ── Connect tab — Bridge + AI providers ── */
              <div className="p-3 space-y-3 overflow-y-auto" style={{ maxHeight: "calc(100% - 8px)" }}>
                {/* Copilot Pro Bridge card */}
                <div className={`border rounded-lg p-3 ${
                  bridge?.configured
                    ? "bg-[#0d1117] border-blue-800/40"
                    : "bg-[#161b22] border-[var(--border)]"
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-sm">🔑</span>
                      <span className="text-xs font-medium text-[var(--text)]">
                        Copilot Pro Bridge
                      </span>
                    </div>
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                        bridge?.configured
                          ? bridge.tokenCached
                            ? "bg-green-900/30 text-green-400"
                            : "bg-yellow-900/30 text-yellow-400"
                          : "bg-red-900/20 text-[var(--text-dim)]"
                      }`}
                    >
                      {bridge?.configured
                        ? bridge.tokenCached
                          ? "● active"
                          : "configured"
                        : "no token"}
                    </span>
                  </div>

                  <div className="text-[10px] text-[var(--text-dim)] mb-2">
                    Uses your <code className="text-[var(--accent)]">COPILOT_JWT</code> from Settings to authenticate with Claude &amp; Mistral via GitHub Copilot API.
                  </div>

                  {bridge?.tokenCached && bridge.tokenExpiresAt && (
                    <div className="text-[10px] text-green-400/70 mb-2">
                      Token valid until {new Date(bridge.tokenExpiresAt).toLocaleTimeString()}
                    </div>
                  )}

                  <div className="flex gap-2">
                    <button
                      onClick={testBridge}
                      disabled={!bridge?.configured || bridgeTesting}
                      className={`flex-1 text-[10px] py-1 rounded transition-colors ${
                        bridge?.configured
                          ? "bg-blue-900/30 text-blue-400 hover:bg-blue-900/50"
                          : "bg-[#21262d] text-[var(--text-dim)] cursor-not-allowed"
                      }`}
                    >
                      {bridgeTesting ? "Testing..." : "Test Connection"}
                    </button>
                    <a
                      href="/settings"
                      className="flex-1 text-[10px] py-1 rounded text-center bg-[#21262d] text-[var(--text-muted)] hover:bg-[#30363d] transition-colors"
                    >
                      Configure JWT
                    </a>
                  </div>
                </div>

                {/* Divider */}
                <div className="flex items-center gap-2 py-1">
                  <div className="flex-1 border-t border-[var(--border)]" />
                  <span className="text-[9px] uppercase tracking-wider text-[var(--text-dim)]">
                    Launch AI Session
                  </span>
                  <div className="flex-1 border-t border-[var(--border)]" />
                </div>

                {/* Provider cards */}
                {providers.filter((p) => p.id !== "shell").map((p) => {
                  const running = aiSessions.filter(
                    (s) => s.provider === p.id && s.status === "running",
                  ).length;
                  const canBridge = bridge?.configured && (p.id === "claude-code" || p.id === "mistral-vibe");
                  return (
                    <div
                      key={p.id}
                      className="bg-[#161b22] border border-[var(--border)] rounded-lg p-3"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-sm">{providerIcon(p.id)}</span>
                          <span className="text-xs font-medium text-[var(--text)]">
                            {p.label}
                          </span>
                        </div>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                            p.available
                              ? "bg-green-900/30 text-green-400"
                              : canBridge
                                ? "bg-blue-900/30 text-blue-400"
                                : "bg-red-900/20 text-red-400"
                          }`}
                        >
                          {p.available ? "installed" : canBridge ? "bridge ready" : "not found"}
                        </span>
                      </div>

                      <div className="text-[10px] text-[var(--text-dim)] font-mono mb-2">
                        $ {p.command}
                      </div>

                      {running > 0 && (
                        <div className="text-[10px] text-blue-400 mb-2">
                          {running} active session{running > 1 ? "s" : ""}
                        </div>
                      )}

                      <div className="flex gap-2">
                        {/* Direct launch */}
                        <button
                          onClick={() => launchAiSession(p.id)}
                          disabled={!p.available || !!launching}
                          className={`flex-1 text-xs py-1.5 rounded transition-colors ${
                            p.available
                              ? "bg-[var(--accent)] text-black hover:brightness-110"
                              : "bg-[#21262d] text-[var(--text-dim)] cursor-not-allowed"
                          }`}
                        >
                          {launching === p.id
                            ? "Launching..."
                            : p.available
                              ? "Direct"
                              : `Install ${p.command}`}
                        </button>

                        {/* Via Copilot bridge */}
                        {canBridge && (
                          <button
                            onClick={() => launchAiSession(p.id, true)}
                            disabled={!!launching}
                            className="flex-1 text-xs py-1.5 rounded bg-blue-900/30 text-blue-400 hover:bg-blue-900/50 transition-colors"
                          >
                            {launching === p.id + "-bridge"
                              ? "Launching..."
                              : "via Copilot 🔑"}
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}

                {/* Quick shell */}
                <div className="border-t border-[var(--border)] pt-3">
                  <button
                    onClick={() => launchAiSession("shell")}
                    disabled={!!launching}
                    className="w-full text-xs py-1.5 rounded bg-[#21262d] text-[var(--text-muted)] hover:bg-[#30363d] hover:text-[var(--text)] transition-colors"
                  >
                    ⚡ Open Shell
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="terminal-overlay-sidebar-footer">
            <span className="text-[10px] text-[var(--text-dim)]">
              {runningCount} running · {allItems.length} total
            </span>
          </div>
        </div>

        {/* Main terminal area */}
        <div className="terminal-overlay-main">
          {/* Title bar */}
          <div className="terminal-overlay-titlebar">
            <div className="flex items-center gap-3">
              <div className="flex gap-1.5">
                <button
                  onClick={onClose}
                  className="w-3 h-3 rounded-full bg-[#ff5f57] hover:brightness-110 transition-all"
                  title="Close"
                />
                <span className="w-3 h-3 rounded-full bg-[#febc2e]" />
                <span className="w-3 h-3 rounded-full bg-[#28c840]" />
              </div>
              {activeAiSession && (
                <span className="text-xs text-[var(--text-muted)] font-mono">
                  {providerIcon(activeAiSession.provider)} {activeAiSession.label}
                </span>
              )}
              {activeScanTerm && (
                <span className="text-xs text-[var(--text-muted)] font-mono">
                  🔧 {activeScanTerm.tool || "scan"} — {activeScanTerm.target.slice(0, 40)}
                </span>
              )}
              {adbCapture && !activeAiSession && !activeScanTerm && (
                <span className="text-xs text-[var(--text-muted)] font-mono">
                  📡 {adbCapture.title || "WiFi Capture"} — {adbCapture.iface}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {message && (
                <span className="text-[10px] text-[var(--accent)]">{message}</span>
              )}
              <button
                onClick={onClose}
                className="text-[var(--text-dim)] hover:text-[var(--text)] transition-colors text-lg leading-none"
                title="Close (Esc)"
              >
                ×
              </button>
            </div>
          </div>

          {/* Terminal content */}
          <div className="terminal-overlay-content">
            {adbCapture ? (
              <AdbCaptureTerminal
                key={`adb-${adbCapture.serial}-${adbCapture.endpoint || "capture"}-${Date.now()}`}
                serial={adbCapture.serial}
                iface={adbCapture.iface}
                packets={adbCapture.packets}
                outFile={adbCapture.outFile}
                endpoint={adbCapture.endpoint}
                title={adbCapture.title}
                extraBody={adbCapture.extraBody}
              />
            ) : activeAiSession ? (
              <InteractiveTerminal
                key={activeAiSession.id}
                sessionId={activeAiSession.id}
                label={activeAiSession.label}
                provider={activeAiSession.provider}
                isRunning={activeAiSession.status === "running"}
                onKill={() => killAiSession(activeAiSession.id)}
              />
            ) : activeScanTerm ? (
              <TerminalPanel
                key={activeScanTerm.id}
                jobId={activeScanTerm.id}
                tool={activeScanTerm.tool}
                target={activeScanTerm.target}
                isRunning={activeScanTerm.status === "running"}
                onKill={() => killJob(activeScanTerm.id)}
              />
            ) : (
              <div className="flex flex-col items-center justify-center h-full gap-4 text-sm text-[var(--text-dim)]">
                <div className="text-3xl">🐕</div>
                <div>No active session</div>
                <button
                  onClick={() => setSidebarTab("connect")}
                  className="text-xs px-3 py-1.5 bg-[var(--accent)] text-black rounded hover:brightness-110 transition-colors"
                >
                  Connect an AI
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
