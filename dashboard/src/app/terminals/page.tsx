// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback } from "react";
import TerminalPanel from "@/components/TerminalPanel";

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

export default function TerminalsPage() {
  const [terminals, setTerminals] = useState<TerminalInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState<string | null>(null);

  const fetchTerminals = useCallback(async () => {
    try {
      const res = await fetch("/api/terminals");
      const data = await res.json();
      setTerminals(data.terminals || []);
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
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Terminals</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Live terminal output from scans and tool runs. Kill running processes or review past output.
        </p>
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

          {/* Recent terminals */}
          <div>
            <h2 className="font-bold text-lg mb-4">Recent</h2>
            {recent.length === 0 && running.length === 0 ? (
              <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-8 text-center">
                <p className="text-sm text-[var(--text-muted)]">No terminals yet.</p>
                <p className="text-xs text-[var(--text-dim)] mt-1">
                  Run a tool or trigger a scan to see terminal output here.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {recent.map((t) => (
                  <div key={t.id}>
                    <div
                      className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3 cursor-pointer hover:border-[var(--border-hover)] transition-colors"
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
