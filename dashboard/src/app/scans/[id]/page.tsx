// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { loadScan } from "@/lib/data";
import { notFound } from "next/navigation";
import Link from "next/link";
import FindingsTable from "@/components/FindingsTable";
import SeverityChart from "@/components/SeverityChart";
import CvssHistogram from "@/components/CvssHistogram";
import ExportButton from "@/components/ExportButton";
import { SEVERITY_ORDER } from "@/lib/types";
import SeverityBadge from "@/components/SeverityBadge";

export const dynamic = "force-dynamic";

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const filename = decodeURIComponent(id);
  const report = await loadScan(filename);

  if (!report) notFound();

  const findings = report.findings;
  const severityCounts: Record<string, number> = {};
  const toolCounts: Record<string, number> = {};
  let totalCvss = 0;
  let cvssCount = 0;

  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
    toolCounts[f.tool] = (toolCounts[f.tool] || 0) + 1;
    if (f.cvss_score != null && f.cvss_score > 0) {
      totalCvss += f.cvss_score;
      cvssCount++;
    }
  }

  const avgCvss = cvssCount > 0 ? (totalCvss / cvssCount).toFixed(1) : null;
  const uniqueTools = Object.keys(toolCounts).length;

  return (
    <main className="px-6 py-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Link
              href="/scans"
              className="text-[var(--text-muted)] hover:text-[var(--text)] text-sm"
            >
              ← Scans
            </Link>
            <span className="text-[var(--text-dim)]">/</span>
            <h1 className="text-xl font-bold">{filename}</h1>
          </div>
          <p className="text-sm text-[var(--text-muted)]">
            {report.target && <span>{report.target} · </span>}
            {findings.length} findings
            {report.scan_date && <span> · {report.scan_date}</span>}
            {uniqueTools > 0 && <span> · {uniqueTools} tools</span>}
          </p>
        </div>
        <ExportButton findings={findings} />
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-3 md:grid-cols-7 gap-3 mb-6">
        {SEVERITY_ORDER.map((sev) => (
          <div
            key={sev}
            className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3"
          >
            <SeverityBadge severity={sev} />
            <div className="text-xl font-bold mt-1">
              {severityCounts[sev] || 0}
            </div>
          </div>
        ))}
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-xs text-[var(--text-muted)]">Avg CVSS</div>
          <div className="text-xl font-bold mt-1">{avgCvss || "—"}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-xs text-[var(--text-muted)]">Tools</div>
          <div className="text-xl font-bold mt-1">{uniqueTools}</div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold text-sm mb-3">Severity Distribution</h3>
          <SeverityChart severityCounts={severityCounts} />
        </div>
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold text-sm mb-3">CVSS Distribution</h3>
          <div className="h-[220px]">
            <CvssHistogram findings={findings} />
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg">
        <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
          <h3 className="font-semibold text-sm">Findings</h3>
          <span className="text-xs text-[var(--text-muted)]">{findings.length} total</span>
        </div>
        <FindingsTable findings={findings} />
      </div>
    </main>
  );
}
