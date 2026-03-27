// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";
import { runTool } from "@/lib/api-client";
import { useJobStatus } from "@/hooks/useJobStatus";

interface ToolRunnerProps {
  toolName: string;
  onClose?: () => void;
}

export default function ToolRunner({ toolName, onClose }: ToolRunnerProps) {
  const [target, setTarget] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);
  const { job } = useJobStatus({ jobId });

  const launch = async () => {
    if (!target.trim()) return;
    setError(null);
    setLaunching(true);
    try {
      const result = await runTool({ tool: toolName, target: target.trim() });
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
    <div className="bg-[var(--bg)] border border-[var(--border)] rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-semibold text-sm">Run: {toolName}</h3>
        {onClose && (
          <button onClick={onClose} className="text-[var(--text-dim)] hover:text-[var(--text)] text-xs">
            ✕
          </button>
        )}
      </div>

      {!jobId ? (
        <div className="space-y-3">
          <input
            type="url"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://target.example.com"
            className="w-full bg-[var(--card-bg)] border border-[var(--border)] rounded px-3 py-2 text-sm text-[var(--text)] placeholder:text-[var(--text-dim)] focus:outline-none focus:border-[var(--accent)]"
          />
          {error && <p className="text-red-400 text-xs">{error}</p>}
          <button
            onClick={launch}
            disabled={launching || !target.trim()}
            className="w-full py-2 bg-[var(--accent)] text-white rounded text-sm font-medium disabled:opacity-50 hover:opacity-90 transition-opacity"
          >
            {launching ? "Launching..." : "Run Tool"}
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-xs text-[var(--text-muted)]">Job:</span>
            <code className="text-xs font-mono">{jobId.slice(0, 8)}</code>
            {job && (
              <span className={`text-xs font-medium ${statusColor(job.status)}`}>
                {job.status}
              </span>
            )}
          </div>
          {job && (
            <>
              <div className="w-full bg-[var(--card-bg)] rounded-full h-2">
                <div
                  className="h-2 rounded-full bg-[var(--accent)] transition-all"
                  style={{ width: `${job.progress}%` }}
                />
              </div>
              {job.findings > 0 && (
                <p className="text-xs text-[var(--text-muted)]">
                  {job.findings} findings so far
                </p>
              )}
              {job.error && (
                <p className="text-red-400 text-xs">{job.error}</p>
              )}
              {["completed", "failed", "cancelled"].includes(job.status) && (
                <button
                  onClick={() => { setJobId(null); setTarget(""); }}
                  className="text-xs text-[var(--accent)] hover:underline"
                >
                  Run again
                </button>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
