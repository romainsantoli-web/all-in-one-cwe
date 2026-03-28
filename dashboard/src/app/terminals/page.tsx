// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback } from "react";
import TerminalPanel from "@/components/TerminalPanel";
import InteractiveTerminal from "@/components/InteractiveTerminal";

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

export default function TerminalsPage() {
  const [terminals, setTerminals] = useState<TerminalInfo[]>([]);
  const [aiSessions, setAiSessions] = useState<AISession[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState<string | null>(null);
  const [creatingShell, setCreatingShell] = useState(false);

  const fetchTerminals = useCallback(async () => {
    try {
      const [scanRes, aiRes] = await Promise.all([
        fetch("/api/terminals"),
        fetch("/api/terminals/ai-session"),
      ]);
      const scanData = await scanRes.json();
      const aiData = await aiRes.json();
      setTerminals(scanData.terminals || []);
      setAiSessions(aiData.sessions || []);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTerminals();
    const interval = setInterval(fetchTerminals, 3000);
    return () => clearInterval(interval);
  }, [fetchTerminals]);

  const killJob = async (jobId: string) => {
    try {
      const res = await fetch("/api/terminals", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jobId }),
      });
      if (res.ok) {
        setMessage(`Process ${jobId.slice(0, 8)} killed`);
        await fetchTerminals();
      } else {
        const err = await res.json();
        setMessage(err.error || "Kill failed");
      }
    } catch {
      setMessage("Network error");
    }
    setTimeout(() => setMessage(null), 3000);
  };

  const killAiSession = async (sessionId: string) => {
    try {
      const res = await fetch("/api/terminals/ai-session", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId }),
      });
      if (res.ok) {
        setMessage(`Session ${sessionId.slice(0, 8)} killed`);
        await fetchTerminals();
      } else {
        const err = await res.json();
        setMessage(err.error || "Kill failed");
      }
    } catch {
      setMessage("Network error");
    }
    setTimeout(() => setMessage(null), 3000);
  };

  const deleteTerminal = async (jobId: string) => {
    try {
      const res = await fetch(`/api/scans/jobs/${encodeURIComponent(jobId)}`, {
        method: "DELETE",
      });
      if (res.ok) {
        setMessage(`Job ${jobId.slice(0, 8)} deleted`);
        await fetchTerminals();
      } else {
        const err = await res.json();
        setMessage(err.error || "Delete failed");
      }
    } catch {
      setMessage("Network error");
    }
    setTimeout(() => setMessage(null), 3000);
  };

  const createShellSession = async () => {
    setCreatingShell(true);
    try {
      const res = await fetch("/api/terminals/ai-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: "shell" }),
      });
      if (res.ok) {
        const data = await res.json();
        setMessage(`Shell session created: ${data.sessionId?.slice(0, 8) || "ok"}`);
        await fetchTerminals();
        // Auto-expand the new session
        if (data.sessionId) {
          setExpanded((prev) => new Set([...prev, `ai-${data.sessionId}`]));
        }
      } else {
        const err = await res.json();
        setMessage(err.error || "Failed to create shell");
      }
    } catch {
      setMessage("Network error");
    } finally {
      setCreatingShell(false);
    }
    setTimeout(() => setMessage(null), 3000);
  };

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const running = terminals.filter((t) => t.status === "running");
  const recent = terminals.filter((t) => t.status !== "running").slice(0, 20);

  const statusBadge = (status: string) => {
    const colors: Record<string, string> = {
      running: "bg-blue-900/30 text-blue-400",
      completed: "bg-green-900/30 text-green-400",
      failed: "bg-red-900/30 text-red-400",
      cancelled: "bg-yellow-900/30 text-yellow-400",
      queued: "bg-gray-800 text-gray-400",
    };
    return colors[status] || "bg-gray-800 text-gray-400";
  };

  const timeAgo = (iso: string) => {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    return `${Math.floor(diff / 3_600_000)}h ago`;
  };

  return (
    <main className="px-6 py-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Terminals</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Live terminal output from scans and tool runs. Kill running processes or review past output.
          </p>
        </div>
        <button
          onClick={createShellSession}
          disabled={creatingShell}
          className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm font-medium hover:opacity-90 transition-opacity disabled:opacity-50 inline-flex items-center gap-2"
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          {creatingShell ? "Creating..." : "New Terminal"}
        </button>
      </div>

      {message && (
        <div className="mb-4 p-3 rounded text-sm bg-[var(--card-bg)] border border-[var(--border)] text-[var(--text)]">
          {message}
        </div>
      )}

      {loading ? (
        <div className="text-sm text-[var(--text-muted)]">Loading...</div>
      ) : (
        <>
          {/* Active terminals */}
          {running.length > 0 && (
            <div className="mb-8">
              <div className="flex items-center gap-3 mb-4">
                <h2 className="font-bold text-lg">Active</h2>
                <span className="text-xs bg-blue-900/30 text-blue-400 px-2 py-0.5 rounded-full">
                  {running.length} running
                </span>
                {running.length > 1 && (
                  <button
                    onClick={() => {
                      for (const t of running) killJob(t.id);
                    }}
                    className="text-xs px-2 py-0.5 bg-red-900/20 text-red-400 rounded hover:bg-red-900/30"
                  >
                    Kill All
                  </button>
                )}
              </div>
              <div className="space-y-4">
                {running.map((t) => (
                  <TerminalPanel
                    key={t.id}
                    jobId={t.id}
                    tool={t.tool}
                    target={t.target}
                    isRunning
                    onKill={() => killJob(t.id)}
                  />
                ))}
              </div>
            </div>
          )}

          {/* Interactive sessions (Shell / AI) */}
          {aiSessions.length > 0 && (
            <div className="mb-8">
              <div className="flex items-center gap-3 mb-4">
                <h2 className="font-bold text-lg">Interactive Sessions</h2>
                <span className="text-xs bg-purple-900/30 text-purple-400 px-2 py-0.5 rounded-full">
                  {aiSessions.filter((s) => s.status === "running").length} running
                </span>
              </div>
              <div className="space-y-4">
                {aiSessions.map((s) => {
                  const providerIcon = s.provider === "claude-code" ? "🟣"
                    : s.provider === "mistral-vibe" ? "🟠" : "⚡";
                  const isRunning = s.status === "running";
                  const isExpanded = expanded.has(`ai-${s.id}`);
                  return (
                    <div key={s.id}>
                      <div
                        className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3 cursor-pointer hover:border-[var(--border-hover)] transition-colors"
                        onClick={() => toggleExpand(`ai-${s.id}`)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span>{providerIcon}</span>
                            <span className="text-sm font-medium">{s.label}</span>
                            <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${statusBadge(s.status)}`}>
                              {s.status}
                            </span>
                          </div>
                          <div className="flex items-center gap-3 text-xs text-[var(--text-muted)]">
                            {s.pid && <span className="font-mono text-[var(--text-dim)]">PID {s.pid}</span>}
                            <span>{timeAgo(s.createdAt)}</span>
                            {isRunning && (
                              <button
                                onClick={(e) => { e.stopPropagation(); killAiSession(s.id); }}
                                className="text-xs px-2 py-0.5 bg-red-900/20 text-red-400 rounded hover:bg-red-900/30"
                              >
                                Kill
                              </button>
                            )}
                            <span className="text-[var(--text-dim)]">{isExpanded ? "▾" : "▸"}</span>
                          </div>
                        </div>
                      </div>
                      {isExpanded && (
                        <div className="mt-1 rounded-lg border border-[var(--border)] overflow-hidden" style={{ height: "350px" }}>
                          <InteractiveTerminal
                            sessionId={s.id}
                            label={s.label}
                            provider={s.provider}
                            isRunning={isRunning}
                            onKill={() => killAiSession(s.id)}
                          />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Recent terminals */}
          <div>
            <h2 className="font-bold text-lg mb-4">Recent</h2>
            {recent.length === 0 && running.length === 0 && aiSessions.length === 0 ? (
              <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-8 text-center">
                <p className="text-sm text-[var(--text-muted)]">No terminals yet.</p>
                <p className="text-xs text-[var(--text-dim)] mt-1">
                  Run a tool, trigger a scan, or open a shell session to see terminal output here.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {recent.map((t) => (
                  <div key={t.id}>
                    <div
                      className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3 cursor-pointer hover:border-[var(--border-hover)] transition-colors group"
                      onClick={() => toggleExpand(t.id)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="text-xs font-mono text-[var(--text-dim)]">
                            {t.id.slice(0, 8)}
                          </span>
                          <span className="text-sm font-medium">
                            {t.tool || t.tools.join(", ").slice(0, 40) || "scan"}
                          </span>
                          <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${statusBadge(t.status)}`}>
                            {t.status}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 text-xs text-[var(--text-muted)]">
                          {t.findings > 0 && (
                            <span className="text-[var(--accent)]">{t.findings} findings</span>
                          )}
                          <span>{timeAgo(t.createdAt)}</span>
                          <button
                            onClick={(e) => { e.stopPropagation(); deleteTerminal(t.id); }}
                            className="text-xs px-2 py-0.5 bg-red-900/20 text-red-400 rounded hover:bg-red-900/30 opacity-0 group-hover:opacity-100 transition-opacity"
                            title="Delete job"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                          </button>
                          <span className="text-[var(--text-dim)]">{expanded.has(t.id) ? "▾" : "▸"}</span>
                        </div>
                      </div>
                    </div>
                    {expanded.has(t.id) && (
                      <div className="mt-1">
                        <TerminalPanel
                          jobId={t.id}
                          tool={t.tool}
                          target={t.target}
                          isRunning={false}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </main>
  );
}
