// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { loadLatestScan } from "@/lib/data";
import { SEVERITY_ORDER, SEVERITY_COLORS } from "@/lib/types";
import SeverityBadge from "@/components/SeverityBadge";
import SeverityChart from "@/components/SeverityChart";
import ToolBarChart from "@/components/ToolBarChart";
import CweBarChart from "@/components/CweBarChart";
import CvssHistogram from "@/components/CvssHistogram";
import FindingsTable from "@/components/FindingsTable";
import ExportButton from "@/components/ExportButton";
import QuickActions from "@/components/QuickActions";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const report = await loadLatestScan();

  if (!report) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--text-dim)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" className="mx-auto mb-4">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <h1 className="text-2xl font-bold mb-2">No scan data found</h1>
          <p className="text-[var(--text-muted)]">
            Run a scan first:{" "}
            <code className="bg-[var(--card-bg)] px-2 py-1 rounded text-sm">
              make scan-light TARGET=https://example.com
            </code>
          </p>
        </div>
      </main>
    );
  }

  const findings = report.findings;
  const severityCounts: Record<string, number> = {};
  const cweCounts: Record<string, number> = {};
  const toolCounts: Record<string, number> = {};
  let totalCvss = 0;
  let cvssCount = 0;

  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
    if (f.cwe_id || f.cwe) {
      const cwe = f.cwe_id || f.cwe || "unknown";
      cweCounts[cwe] = (cweCounts[cwe] || 0) + 1;
    }
    toolCounts[f.tool] = (toolCounts[f.tool] || 0) + 1;
    if (f.cvss_score != null && f.cvss_score > 0) {
      totalCvss += f.cvss_score;
      cvssCount++;
    }
  }

  const avgCvss = cvssCount > 0 ? (totalCvss / cvssCount).toFixed(1) : null;
  const uniqueTools = Object.keys(toolCounts).length;
  const uniqueCwes = Object.keys(cweCounts).length;

  // Risk score color
  const riskColor = (score: number) => {
    if (score >= 9) return "var(--critical)";
    if (score >= 7) return "var(--high)";
    if (score >= 4) return "var(--medium)";
    return "var(--low)";
  };

  return (
    <main className="px-6 py-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-[var(--text-muted)] mt-0.5">
            {report.target && <span>{report.target} · </span>}
            {findings.length} findings
            {report.scan_date && <span> · {report.scan_date}</span>}
          </p>
        </div>
        <ExportButton findings={findings} />
      </div>

      {/* Quick Actions */}
      <QuickActions />

      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
        {SEVERITY_ORDER.map((sev) => (
          <div
            key={sev}
            className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3"
          >
            <div className="flex items-center justify-between mb-1">
              <SeverityBadge severity={sev} />
            </div>
            <div className="text-2xl font-bold">{severityCounts[sev] || 0}</div>
          </div>
        ))}
        {/* Avg CVSS */}
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-xs text-[var(--text-muted)] mb-1">Avg CVSS</div>
          {avgCvss ? (
            <div className="text-2xl font-bold" style={{ color: riskColor(parseFloat(avgCvss)) }}>
              {avgCvss}
            </div>
          ) : (
            <div className="text-2xl font-bold text-[var(--text-dim)]">—</div>
          )}
        </div>
        {/* Unique counts */}
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-xs text-[var(--text-muted)] mb-1">Tools / CWEs</div>
          <div className="text-2xl font-bold">
            {uniqueTools} <span className="text-sm text-[var(--text-muted)]">/</span> {uniqueCwes}
          </div>
        </div>
      </div>

      {/* Charts grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        {/* Severity doughnut */}
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold text-sm mb-3">Severity Distribution</h3>
          <SeverityChart severityCounts={severityCounts} />
        </div>

        {/* CVSS histogram */}
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold text-sm mb-3">CVSS Score Distribution</h3>
          <div className="h-[220px]">
            <CvssHistogram findings={findings} />
          </div>
        </div>

        {/* Tool bar chart */}
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold text-sm mb-3">Findings by Tool</h3>
          <div className="h-[220px]">
            <ToolBarChart toolCounts={toolCounts} />
          </div>
        </div>
      </div>

      {/* CWE bar chart (full width) */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
        <h3 className="font-semibold text-sm mb-3">Top CWE Categories</h3>
        <div className="h-[300px]">
          <CweBarChart cweCounts={cweCounts} />
        </div>
      </div>

      {/* Findings table */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg">
        <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
          <h3 className="font-semibold text-sm">All Findings</h3>
          <span className="text-xs text-[var(--text-muted)]">{findings.length} total</span>
        </div>
        <FindingsTable findings={findings} />
      </div>
    </main>
  );
}
