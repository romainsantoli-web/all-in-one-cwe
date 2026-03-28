// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";

interface Finding {
  title?: string;
  name?: string;
  severity?: string;
  cwe?: string;
  tool?: string;
}

interface CheckpointData {
  state: string;
  findings: Finding[];
  chains: Array<{ id?: string; chain_id?: string }>;
  budget: {
    steps_used: number;
    steps_max: number;
    elapsed_seconds: number;
    max_time_seconds: number;
  };
  message?: string;
}

interface CheckpointModalProps {
  data: CheckpointData;
  onResume: () => void;
  onAbort: () => void;
}

export default function CheckpointModal({ data, onResume, onAbort }: CheckpointModalProps) {
  const [confirming, setConfirming] = useState(false);

  const severityCounts: Record<string, number> = {};
  for (const f of data.findings) {
    const sev = (f.severity || "info").toLowerCase();
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
  }

  const elapsed = Math.round(data.budget.elapsed_seconds);
  const remaining = data.budget.steps_max - data.budget.steps_used;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-xl shadow-2xl w-full max-w-lg mx-4">
        {/* Header */}
        <div className="px-6 py-4 border-b border-[var(--border)] flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-amber-500/20 flex items-center justify-center text-amber-400">
            ⏸
          </div>
          <div>
            <h2 className="font-bold text-lg">Checkpoint — {data.state}</h2>
            <p className="text-xs text-[var(--text-muted)]">
              {data.message || "Review findings before continuing."}
            </p>
          </div>
        </div>

        {/* Stats */}
        <div className="px-6 py-4 grid grid-cols-3 gap-4 text-center">
          <div>
            <div className="text-2xl font-bold">{data.findings.length}</div>
            <div className="text-xs text-[var(--text-muted)]">Findings</div>
          </div>
          <div>
            <div className="text-2xl font-bold">{data.chains.length}</div>
            <div className="text-xs text-[var(--text-muted)]">Chains</div>
          </div>
          <div>
            <div className="text-2xl font-bold">{remaining}</div>
            <div className="text-xs text-[var(--text-muted)]">Steps left</div>
          </div>
        </div>

        {/* Severity breakdown */}
        {Object.keys(severityCounts).length > 0 && (
          <div className="px-6 pb-3 flex gap-2 flex-wrap">
            {Object.entries(severityCounts).map(([sev, count]) => (
              <span
                key={sev}
                className="px-2 py-0.5 rounded text-xs font-medium"
                style={{
                  background: sev === "critical" ? "#ef444433" : sev === "high" ? "#f9731633" : sev === "medium" ? "#eab30833" : "#6b728033",
                  color: sev === "critical" ? "#ef4444" : sev === "high" ? "#f97316" : sev === "medium" ? "#eab308" : "#9ca3af",
                }}
              >
                {count} {sev}
              </span>
            ))}
          </div>
        )}

        {/* Recent findings preview */}
        {data.findings.length > 0 && (
          <div className="px-6 pb-4">
            <div className="text-xs font-medium text-[var(--text-muted)] mb-2">Recent findings:</div>
            <div className="space-y-1 max-h-32 overflow-y-auto">
              {data.findings.slice(-5).map((f, i) => (
                <div key={i} className="text-xs bg-[var(--bg)] rounded px-2 py-1 flex justify-between">
                  <span className="truncate">{f.title || f.name || "Untitled"}</span>
                  <span className="text-[var(--text-muted)] ml-2 shrink-0">{f.tool}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Time info */}
        <div className="px-6 pb-4 text-xs text-[var(--text-muted)]">
          Elapsed: {elapsed}s · Steps: {data.budget.steps_used}/{data.budget.steps_max}
        </div>

        {/* Actions */}
        <div className="px-6 py-4 border-t border-[var(--border)] flex gap-3 justify-end">
          {confirming ? (
            <>
              <span className="text-sm text-amber-400 self-center mr-auto">Abort the hunt?</span>
              <button
                onClick={() => setConfirming(false)}
                className="px-4 py-2 text-sm rounded-lg border border-[var(--border)] hover:bg-[var(--bg)]"
              >
                Cancel
              </button>
              <button
                onClick={onAbort}
                className="px-4 py-2 text-sm rounded-lg bg-red-600 text-white hover:bg-red-700"
              >
                Confirm Abort
              </button>
            </>
          ) : (
            <>
              <button
                onClick={() => setConfirming(true)}
                className="px-4 py-2 text-sm rounded-lg border border-red-500/50 text-red-400 hover:bg-red-500/10"
              >
                Abort
              </button>
              <button
                onClick={onResume}
                className="px-4 py-2 text-sm rounded-lg bg-[var(--accent)] text-black font-medium hover:opacity-90"
              >
                Continue Hunting →
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
