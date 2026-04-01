// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, Fragment } from "react";
import Link from "next/link";
import { getJob, getJobSummary, getJobLog, getToolFindings, type JobStatus, type JobSummary, type ToolFinding } from "@/lib/api-client";
import { useParams } from "next/navigation";

const severityColor: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10",
  high: "text-orange-400 bg-orange-400/10",
  medium: "text-yellow-400 bg-yellow-400/10",
  low: "text-blue-400 bg-blue-400/10",
  info: "text-[var(--text-dim)] bg-[var(--bg)]",
};

const statusColor: Record<string, string> = {
  completed: "text-green-400",
  failed: "text-red-400",
  running: "text-blue-400",
  queued: "text-yellow-400",
  cancelled: "text-orange-400",
};

const statusBg: Record<string, string> = {
  completed: "bg-green-500/10 border-green-500/30",
  failed: "bg-red-500/10 border-red-500/30",
  running: "bg-blue-500/10 border-blue-500/30",
  queued: "bg-yellow-500/10 border-yellow-500/30",
  cancelled: "bg-orange-500/10 border-orange-500/30",
};

export default function JobDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [job, setJob] = useState<JobStatus | null>(null);
  const [summary, setSummary] = useState<JobSummary | null>(null);
  const [log, setLog] = useState<string>("");
  const [showLog, setShowLog] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedTool, setExpandedTool] = useState<string | null>(null);
  const [toolFindings, setToolFindings] = useState<Record<string, ToolFinding[]>>({});
  const [loadingTool, setLoadingTool] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getJob(id)
      .then(setJob)
      .catch(() => setError("Job not found"));
    getJobSummary(id).then(setSummary);
  }, [id]);

  useEffect(() => {
    if (!id || !showLog) return;
    getJobLog(id).then(setLog);
  }, [id, showLog]);

  // Poll while running
  useEffect(() => {
    if (!id || !job || (job.status !== "running" && job.status !== "queued")) return;
    const interval = setInterval(() => {
      getJob(id).then(setJob).catch(() => {});
      getJobSummary(id).then(setSummary);
    }, 3000);
    return () => clearInterval(interval);
  }, [id, job?.status]);

  if (error) {
    return (
      <main className="px-6 py-6">
        <Link href="/launch" className="text-[var(--text-muted)] hover:text-[var(--text)] text-sm">← Back to Launch</Link>
        <div className="mt-6 bg-[var(--card-bg)] border border-red-500/30 rounded-lg p-8 text-center">
          <p className="text-red-400 font-semibold">{error}</p>
        </div>
      </main>
    );
  }

  if (!job) {
    return (
      <main className="px-6 py-6">
        <div className="animate-pulse space-y-4">
          <div className="h-6 w-48 bg-[var(--card-bg)] rounded" />
          <div className="h-40 bg-[var(--card-bg)] rounded-lg" />
        </div>
      </main>
    );
  }

  const elapsed = job.updatedAt && job.createdAt
    ? ((new Date(job.updatedAt).getTime() - new Date(job.createdAt).getTime()) / 1000).toFixed(1)
    : null;

  return (
    <main className="px-6 py-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm mb-6">
        <Link href="/launch" className="text-[var(--text-muted)] hover:text-[var(--text)]">← Launch</Link>
        <span className="text-[var(--text-dim)]">/</span>
        <span className="font-mono text-xs text-[var(--text-dim)]">{job.id.slice(0, 8)}…</span>
      </div>

      {/* Header card */}
      <div className={`border rounded-lg p-5 mb-6 ${statusBg[job.status] || "bg-[var(--card-bg)] border-[var(--border)]"}`}>
        <div className="flex items-center justify-between mb-3">
          <h1 className="text-xl font-bold">{job.target}</h1>
          <span className={`text-sm font-bold uppercase ${statusColor[job.status] || ""}`}>
            {job.status}
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
          <div>
            <div className="text-[var(--text-dim)] text-xs">Profile</div>
            <div className="font-medium">{job.profile || "—"}</div>
          </div>
          <div>
            <div className="text-[var(--text-dim)] text-xs">Tools</div>
            <div className="font-medium">{job.tools.length}</div>
          </div>
          <div>
            <div className="text-[var(--text-dim)] text-xs">Findings</div>
            <div className="font-bold text-lg">{job.findings}</div>
          </div>
          <div>
            <div className="text-[var(--text-dim)] text-xs">Duration</div>
            <div className="font-medium">{elapsed ? `${elapsed}s` : "—"}</div>
          </div>
        </div>
        <div className="mt-3 text-[10px] font-mono text-[var(--text-dim)]">
          Created {new Date(job.createdAt).toLocaleString()} · ID {job.id}
        </div>
      </div>

      {/* Progress bar for running jobs */}
      {(job.status === "running" || job.status === "queued") && (
        <div className="mb-6">
          <div className="flex justify-between text-xs mb-1">
            <span className="text-[var(--text-muted)]">Progress</span>
            <span className="font-mono">{job.progress}%</span>
          </div>
          <div className="h-2 bg-[var(--bg)] rounded-full overflow-hidden">
            <div
              className="h-full bg-blue-500 rounded-full transition-all duration-500"
              style={{ width: `${job.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Tool results from summary */}
      {summary && summary.results.length > 0 && (
        <div className="mb-6">
          <h2 className="font-bold text-sm mb-3">Tool Results</h2>
          <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-[var(--text-muted)] text-xs">
                  <th className="text-left px-4 py-2 font-medium">Tool</th>
                  <th className="text-left px-4 py-2 font-medium">Status</th>
                  <th className="text-right px-4 py-2 font-medium">Findings</th>
                  <th className="text-right px-4 py-2 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {summary.results.map((r) => {
                  const hasFindings = (r.findings ?? 0) > 0;
                  const isExpanded = expandedTool === r.tool;
                  const findings = toolFindings[r.tool];
                  return (
                    <Fragment key={r.tool}>
                      <tr
                        className={`border-b border-[var(--border)] last:border-0 transition-colors ${
                          hasFindings ? "cursor-pointer hover:bg-[var(--bg)]/80" : "hover:bg-[var(--bg)]/50"
                        } ${isExpanded ? "bg-[var(--bg)]/60" : ""}`}
                        onClick={() => {
                          if (!hasFindings) return;
                          if (isExpanded) { setExpandedTool(null); return; }
                          setExpandedTool(r.tool);
                          if (!toolFindings[r.tool]) {
                            setLoadingTool(r.tool);
                            getToolFindings(r.tool).then((res) => {
                              setToolFindings((prev) => ({ ...prev, [r.tool]: res.findings }));
                              setLoadingTool(null);
                            });
                          }
                        }}
                      >
                        <td className="px-4 py-2.5 font-mono text-xs">
                          <span className="flex items-center gap-1.5">
                            {hasFindings && (
                              <span className={`text-[10px] transition-transform ${isExpanded ? "rotate-90" : ""}`}>&#9654;</span>
                            )}
                            <span className={hasFindings ? "text-[var(--text)] underline decoration-dotted underline-offset-2" : ""}>{r.tool}</span>
                          </span>
                        </td>
                        <td className="px-4 py-2.5">
                          <span className={r.status === "completed" ? "text-green-400" : r.status === "skipped" ? "text-yellow-400" : "text-red-400"}>
                            {r.status}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-right font-bold">
                          {hasFindings ? (
                            <span className="text-yellow-400">{r.findings}</span>
                          ) : (
                            <span className="text-[var(--text-dim)]">{r.findings ?? "—"}</span>
                          )}
                        </td>
                        <td className="px-4 py-2.5 text-right text-[var(--text-muted)]">
                          {r.elapsed_s != null ? `${r.elapsed_s.toFixed(1)}s` : "—"}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr key={`${r.tool}-detail`}>
                          <td colSpan={4} className="px-0 py-0">
                            {loadingTool === r.tool ? (
                              <div className="px-6 py-4 text-xs text-[var(--text-muted)] animate-pulse">Loading findings…</div>
                            ) : findings && findings.length > 0 ? (
                              <div className="border-t border-[var(--border)] bg-[var(--bg)]/40">
                                {findings.map((f, i) => (
                                  <div key={`${f.id}-${i}`} className="px-6 py-3 border-b border-[var(--border)]/50 last:border-0">
                                    <div className="flex items-start justify-between gap-3 mb-1">
                                      <div className="flex items-center gap-2">
                                        <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${severityColor[f.severity] || severityColor.info}`}>
                                          {f.severity}
                                        </span>
                                        <span className="font-mono text-[10px] text-[var(--text-dim)]">{f.cwe}</span>
                                      </div>
                                      {f.url && <span className="text-[10px] font-mono text-[var(--text-dim)] truncate max-w-[200px]">{f.url}</span>}
                                    </div>
                                    <p className="text-xs font-medium mb-1">{f.name}</p>
                                    <p className="text-xs text-[var(--text-muted)] mb-1">{f.description}</p>
                                    {f.evidence && typeof f.evidence === "object" && Object.keys(f.evidence).length > 0 && (
                                      <div className="mt-2">
                                        <span className="text-[10px] font-semibold text-[var(--text-dim)] uppercase">Evidence</span>
                                        {Array.isArray(f.evidence.secrets) && f.evidence.secrets.length > 0 && (
                                          <div className="mt-1 space-y-1">
                                            {(f.evidence.secrets as Array<{type?: string; source?: string; redacted?: string}>).map((s, si) => (
                                              <div key={si} className="bg-black/30 rounded px-2 py-1 text-[10px] font-mono">
                                                <span className="text-red-400">{s.type}</span>
                                                {s.source && <span className="text-[var(--text-dim)] ml-2 break-all">in {s.source}</span>}
                                                {s.redacted && <span className="text-yellow-400 ml-2">{s.redacted}</span>}
                                              </div>
                                            ))}
                                          </div>
                                        )}
                                        {Array.isArray(f.evidence.endpoints) && f.evidence.endpoints.length > 0 && (
                                          <div className="mt-1 space-y-0.5">
                                            {(f.evidence.endpoints as Array<{path?: string; status?: number; reason?: string}>).map((ep, ei) => (
                                              <div key={ei} className="text-[10px] font-mono text-[var(--text-muted)]">
                                                <span className="text-yellow-400">{ep.path}</span>
                                                {ep.status != null && <span className="ml-1 text-red-400">[{ep.status}]</span>}
                                                {ep.reason && <span className="ml-1">{ep.reason}</span>}
                                              </div>
                                            ))}
                                          </div>
                                        )}
                                        {!Array.isArray(f.evidence.secrets) && !Array.isArray(f.evidence.endpoints) && (
                                          <pre className="mt-1 text-[10px] font-mono bg-black/30 rounded p-2 overflow-x-auto whitespace-pre-wrap max-h-32">
                                            {JSON.stringify(f.evidence, null, 2)}
                                          </pre>
                                        )}
                                      </div>
                                    )}
                                    {f.impact && (
                                      <p className="text-[10px] text-[var(--text-dim)] mt-1">
                                        <span className="font-semibold">Impact:</span> {f.impact}
                                      </p>
                                    )}
                                    {f.steps && f.steps.length > 0 && (
                                      <ol className="text-[10px] text-[var(--text-dim)] mt-1 list-decimal list-inside space-y-0.5">
                                        {f.steps.map((s: string, j: number) => <li key={j}>{s}</li>)}
                                      </ol>
                                    )}
                                    {f.remediation && (
                                      <p className="text-xs text-green-400/80 mt-1">
                                        <span className="font-semibold">Fix: </span>{f.remediation}
                                      </p>
                                    )}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div className="px-6 py-4 text-xs text-[var(--text-dim)]">No detailed findings available.</div>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
            <div className="px-4 py-2 bg-[var(--bg)] border-t border-[var(--border)] flex justify-between text-xs text-[var(--text-muted)]">
              <span>{summary.completed}/{summary.tools_run} tools completed</span>
              <span className="font-bold">{summary.total_findings} total findings</span>
            </div>
          </div>
        </div>
      )}

      {/* Requested tools list (when no summary) */}
      {!summary && job.tools.length > 0 && (
        <div className="mb-6">
          <h2 className="font-bold text-sm mb-3">Requested Tools</h2>
          <div className="flex flex-wrap gap-2">
            {job.tools.map((t) => (
              <span key={t} className="px-2.5 py-1 bg-[var(--card-bg)] border border-[var(--border)] rounded text-xs font-mono">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Error display */}
      {job.error && (
        <div className="mb-6 bg-red-500/10 border border-red-500/30 rounded-lg p-4">
          <h2 className="font-bold text-sm text-red-400 mb-1">Error</h2>
          <pre className="text-xs font-mono text-red-300 whitespace-pre-wrap">{job.error}</pre>
        </div>
      )}

      {/* Log section */}
      <div className="mb-6">
        <button
          onClick={() => setShowLog(!showLog)}
          className="text-sm text-[var(--text-muted)] hover:text-[var(--text)] transition-colors"
        >
          {showLog ? "▼" : "▶"} Job Log
        </button>
        {showLog && (
          <div className="mt-2 bg-[#0d1117] border border-[var(--border)] rounded-lg p-4 max-h-80 overflow-auto">
            <pre className="text-xs font-mono text-green-300 whitespace-pre-wrap">
              {log || "No log output available."}
            </pre>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex gap-3">
        <Link
          href="/scans"
          className="px-4 py-2 bg-[var(--card-bg)] border border-[var(--border)] rounded text-sm hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors"
        >
          View All Reports
        </Link>
        <Link
          href="/launch"
          className="px-4 py-2 bg-[var(--accent)] text-white rounded text-sm hover:opacity-90 transition-opacity"
        >
          New Scan
        </Link>
      </div>
    </main>
  );
}
