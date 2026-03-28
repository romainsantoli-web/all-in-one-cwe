// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";
import { triggerScan } from "@/lib/api-client";
import { useJobStatus } from "@/hooks/useJobStatus";
import { getAllTools, PARALLEL_GROUPS } from "@/lib/tools-data";
import StreamingOutput from "@/components/StreamingOutput";

const PROFILES = ["light", "medium", "full"] as const;

export default function ScanLauncher() {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<"light" | "medium" | "full">("light");
  const [selectedTools, setSelectedTools] = useState<Set<string>>(new Set());
  const [useCustomTools, setUseCustomTools] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);
  const { job, cancel } = useJobStatus({ jobId });

  const allTools = getAllTools();

  const toggleTool = (name: string) => {
    setSelectedTools((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const launch = async () => {
    if (!target.trim()) return;
    setError(null);
    setLaunching(true);
    try {
      const params = {
        target: target.trim(),
        profile,
        ...(useCustomTools && selectedTools.size > 0
          ? { tools: Array.from(selectedTools) }
          : {}),
      };
      const result = await triggerScan(params);
      setJobId(result.jobId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Launch failed");
    } finally {
      setLaunching(false);
    }
  };

  const statusColor = (s: string) => {
    switch (s) {
      case "completed": return "text-green-400";
      case "failed": return "text-red-400";
      case "running": return "text-blue-400";
      case "queued": return "text-yellow-400";
      default: return "text-[var(--text-muted)]";
    }
  };

  return (
    <div className="space-y-6">
      {/* Target + Profile */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="font-bold text-lg mb-4">Launch Scan</h2>

        <div className="space-y-4">
          <div>
            <label className="text-xs text-[var(--text-muted)] mb-1 block">Target URL</label>
            <input
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.example.com"
              className="w-full bg-[var(--bg)] border border-[var(--border)] rounded-lg px-4 py-3 text-sm text-[var(--text)] placeholder:text-[var(--text-dim)] focus:outline-none focus:border-[var(--accent)]"
            />
          </div>

          <div>
            <label className="text-xs text-[var(--text-muted)] mb-2 block">Scan Profile</label>
            <div className="flex gap-2">
              {PROFILES.map((p) => (
                <button
                  key={p}
                  onClick={() => setProfile(p)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    profile === p
                      ? "bg-[var(--accent)] text-white"
                      : "bg-[var(--bg)] border border-[var(--border)] text-[var(--text-muted)] hover:border-[var(--border-hover)]"
                  }`}
                >
                  {p.charAt(0).toUpperCase() + p.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Custom tool selection toggle */}
          <div>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                checked={useCustomTools}
                onChange={(e) => setUseCustomTools(e.target.checked)}
                className="rounded"
              />
              Custom tool selection
            </label>
          </div>

          {useCustomTools && (
            <div className="max-h-60 overflow-y-auto border border-[var(--border)] rounded-lg p-3 space-y-3">
              {PARALLEL_GROUPS.map((group) => (
                <div key={group.name}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-bold text-[var(--text-muted)] uppercase">{group.name}</span>
                    <button
                      onClick={() => {
                        const next = new Set(selectedTools);
                        const allSelected = group.tools.every((t) => next.has(t));
                        for (const t of group.tools) {
                          if (allSelected) next.delete(t);
                          else next.add(t);
                        }
                        setSelectedTools(next);
                      }}
                      className="text-[10px] text-[var(--accent)] hover:underline"
                    >
                      {group.tools.every((t) => selectedTools.has(t)) ? "deselect all" : "select all"}
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {group.tools.map((t) => (
                      <button
                        key={t}
                        onClick={() => toggleTool(t)}
                        className={`text-xs px-2 py-1 rounded transition-colors ${
                          selectedTools.has(t)
                            ? "bg-[var(--accent)] text-white"
                            : "bg-[var(--bg)] border border-[var(--border)] text-[var(--text-muted)] hover:border-[var(--border-hover)]"
                        }`}
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {error && <p className="text-red-400 text-sm">{error}</p>}

          <button
            onClick={launch}
            disabled={launching || !target.trim() || !!jobId}
            className="w-full py-3 bg-[var(--accent)] text-white rounded-lg text-sm font-bold disabled:opacity-50 hover:opacity-90 transition-opacity"
          >
            {launching ? "Launching..." : jobId ? "Scan in progress..." : "🚀 Launch Scan"}
          </button>
        </div>
      </div>

      {/* Job status */}
      {job && (
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold">Scan Progress</h3>
            <span className={`text-sm font-medium ${statusColor(job.status)}`}>
              {job.status.toUpperCase()}
            </span>
          </div>

          {/* Animated progress bar */}
          <div className="w-full bg-[var(--bg)] rounded-full h-4 mb-3 overflow-hidden relative">
            {job.status === "running" ? (
              <>
                <div
                  className="h-full rounded-full transition-all duration-700 ease-out relative"
                  style={{
                    width: `${Math.max(job.progress, 5)}%`,
                    background: "linear-gradient(90deg, #3b82f6, #6366f1, #8b5cf6)",
                  }}
                >
                  <div
                    className="absolute inset-0 rounded-full"
                    style={{
                      backgroundImage:
                        "repeating-linear-gradient(45deg, transparent, transparent 8px, rgba(255,255,255,0.1) 8px, rgba(255,255,255,0.1) 16px)",
                      animation: "progress-stripes 0.8s linear infinite",
                    }}
                  />
                </div>
                <div
                  className="absolute top-0 right-0 h-full w-16 rounded-full"
                  style={{
                    background: "linear-gradient(90deg, transparent, rgba(139, 92, 246, 0.4))",
                    filter: "blur(6px)",
                    animation: "pulse-glow 1.5s ease-in-out infinite",
                  }}
                />
              </>
            ) : job.status === "completed" ? (
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: "100%",
                  background: "linear-gradient(90deg, #22c55e, #10b981)",
                  boxShadow: "0 0 12px rgba(34, 197, 94, 0.4)",
                }}
              />
            ) : job.status === "failed" ? (
              <div
                className="h-full rounded-full"
                style={{
                  width: `${Math.max(job.progress, 15)}%`,
                  background: "linear-gradient(90deg, #ef4444, #dc2626)",
                }}
              />
            ) : (
              <div
                className="h-full rounded-full bg-yellow-500/60 transition-all duration-500"
                style={{ width: `${Math.max(job.progress, 3)}%` }}
              />
            )}
            {/* Percentage label */}
            <span className="absolute inset-0 flex items-center justify-center text-[10px] font-bold text-white drop-shadow-sm">
              {job.progress}%
            </span>
          </div>

          <style jsx>{`
            @keyframes progress-stripes {
              0% { background-position: 0 0; }
              100% { background-position: 32px 0; }
            }
            @keyframes pulse-glow {
              0%, 100% { opacity: 0.4; }
              50% { opacity: 1; }
            }
          `}</style>

          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <span className="text-[var(--text-muted)]">Target: </span>
              <span className="font-mono text-xs">{job.target}</span>
            </div>
            <div>
              <span className="text-[var(--text-muted)]">Tools: </span>
              <span>{job.tools.length}</span>
            </div>
            <div>
              <span className="text-[var(--text-muted)]">Findings: </span>
              <span className="font-bold">{job.findings}</span>
            </div>
          </div>

          {job.error && (
            <p className="text-red-400 text-sm mt-3">{job.error}</p>
          )}

          <div className="flex gap-2 mt-4">
            {job.status === "running" && (
              <button
                onClick={cancel}
                className="px-4 py-2 bg-red-600 text-white rounded text-sm hover:bg-red-700 transition-colors"
              >
                Cancel
              </button>
            )}
            {job.status === "completed" && jobId && (
              <a
                href={`/launch/${jobId}`}
                className="px-4 py-2 bg-green-600 text-white rounded text-sm hover:bg-green-700 transition-colors inline-flex items-center gap-1.5"
              >
                📊 View Report
              </a>
            )}
            {["completed", "failed", "cancelled"].includes(job.status) && (
              <button
                onClick={() => setJobId(null)}
                className="px-4 py-2 bg-[var(--card-bg)] border border-[var(--border)] rounded text-sm hover:border-[var(--border-hover)] transition-colors"
              >
                New Scan
              </button>
            )}
          </div>

          {jobId && <StreamingOutput url={`/api/stream/${jobId}`} />}
        </div>
      )}
    </div>
  );
}
