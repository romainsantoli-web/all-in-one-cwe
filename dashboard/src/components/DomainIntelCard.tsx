// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useEffect, useState } from "react";

interface DomainProfile {
  domain: string;
  tech_stack: string[];
  last_scanned: string;
  findings_summary: {
    total: number;
    by_severity: Record<string, number>;
    by_cwe: Record<string, number>;
  };
}

interface ToolScore {
  hit_count: number;
  avg_severity: string;
  tech_stacks: string[];
}

interface DomainIntelData {
  profile: DomainProfile | null;
  recommended_tools: Array<{ name: string; score: ToolScore }>;
  tech_findings: number;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
};

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const days = Math.floor(diff / 86400000);
  if (days === 0) return "today";
  if (days === 1) return "1 day ago";
  return `${days} days ago`;
}

export default function DomainIntelCard({ domain }: { domain: string }) {
  const [data, setData] = useState<DomainIntelData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!domain) {
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    fetch(`/api/memory/domain-intel?domain=${encodeURIComponent(domain)}`, {
      signal: controller.signal,
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => setData(d))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, [domain]);

  if (loading) {
    return (
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5 animate-pulse">
        <div className="h-4 bg-[var(--border)] rounded w-1/3 mb-3" />
        <div className="h-3 bg-[var(--border)] rounded w-2/3" />
      </div>
    );
  }

  if (!data || !data.profile) {
    return (
      <div className="bg-[var(--card-bg)] border border-dashed border-[var(--border)] rounded-lg p-5">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-lg">🧠</span>
          <h3 className="font-semibold text-sm">Domain Intelligence</h3>
        </div>
        <p className="text-xs text-[var(--text-muted)]">
          No memory profile for <span className="font-mono">{domain || "this target"}</span>.
          Run a scan to build cross-target intelligence.
        </p>
      </div>
    );
  }

  const { profile, recommended_tools, tech_findings } = data;
  const sevEntries = Object.entries(profile.findings_summary.by_severity || {}).sort(
    (a, b) => (["critical", "high", "medium", "low", "info"].indexOf(a[0]) -
               ["critical", "high", "medium", "low", "info"].indexOf(b[0]))
  );

  return (
    <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className="text-lg">🧠</span>
          <h3 className="font-semibold text-sm">Domain Intelligence</h3>
        </div>
        <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-900/40 text-purple-400 font-medium">
          Last scan: {timeAgo(profile.last_scanned)}
        </span>
      </div>

      {/* Tech Stack */}
      {profile.tech_stack.length > 0 && (
        <div className="mb-4">
          <p className="text-[10px] uppercase tracking-wider text-[var(--text-dim)] mb-1.5">
            Detected Tech Stack
          </p>
          <div className="flex flex-wrap gap-1.5">
            {profile.tech_stack.map((tech) => (
              <span
                key={tech}
                className="text-[10px] font-mono bg-blue-900/30 text-blue-400 px-2 py-0.5 rounded"
              >
                {tech}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Severity Breakdown */}
      {sevEntries.length > 0 && (
        <div className="mb-4">
          <p className="text-[10px] uppercase tracking-wider text-[var(--text-dim)] mb-1.5">
            Historical Findings ({profile.findings_summary.total})
          </p>
          <div className="flex gap-2">
            {sevEntries.map(([sev, count]) => (
              <div
                key={sev}
                className="flex items-center gap-1 text-xs"
                style={{ color: SEVERITY_COLORS[sev] || "#6b7280" }}
              >
                <span className="w-2 h-2 rounded-full" style={{ background: SEVERITY_COLORS[sev] || "#6b7280" }} />
                <span className="font-medium">{count}</span>
                <span className="text-[var(--text-dim)]">{sev}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommended Tools */}
      {recommended_tools.length > 0 && (
        <div className="mb-3">
          <p className="text-[10px] uppercase tracking-wider text-[var(--text-dim)] mb-1.5">
            Recommended Tools (by effectiveness)
          </p>
          <div className="space-y-1">
            {recommended_tools.slice(0, 5).map((t) => (
              <div key={t.name} className="flex items-center justify-between bg-[var(--bg)] rounded px-3 py-1.5">
                <span className="text-xs font-mono">{t.name}</span>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-[var(--text-dim)]">{t.score.hit_count} hits</span>
                  <span
                    className="text-[10px] px-1.5 py-0.5 rounded"
                    style={{
                      background: `${SEVERITY_COLORS[t.score.avg_severity] || "#6b7280"}20`,
                      color: SEVERITY_COLORS[t.score.avg_severity] || "#6b7280",
                    }}
                  >
                    avg: {t.score.avg_severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cross-target insights */}
      {tech_findings > 0 && (
        <p className="text-[10px] text-[var(--text-muted)] border-t border-[var(--border)] pt-2 mt-2">
          📊 {tech_findings} findings from similar tech stacks in memory
        </p>
      )}
    </div>
  );
}
