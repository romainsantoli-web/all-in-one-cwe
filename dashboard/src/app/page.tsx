// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { loadLatestScan } from "@/lib/data";
import { SEVERITY_ORDER } from "@/lib/types";
import SeverityBadge from "@/components/SeverityBadge";
import SeverityChart from "@/components/SeverityChart";
import FindingsTable from "@/components/FindingsTable";
import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const report = await loadLatestScan();

  if (!report) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold mb-4">No scan data found</h1>
          <p className="text-[var(--text-muted)]">
            Run a scan first:{" "}
            <code className="bg-[var(--card-bg)] px-2 py-1 rounded">
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

  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
    if (f.cwe_id || f.cwe) {
      const cwe = f.cwe_id || f.cwe || "unknown";
      cweCounts[cwe] = (cweCounts[cwe] || 0) + 1;
    }
    toolCounts[f.tool] = (toolCounts[f.tool] || 0) + 1;
  }

  const topCwes = Object.entries(cweCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  const topTools = Object.entries(toolCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  return (
    <main className="max-w-7xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Security Dashboard</h1>
          <p className="text-[var(--text-muted)] mt-1">
            {report.target && <span>Target: {report.target} · </span>}
            {findings.length} findings
            {report.scan_date && <span> · {report.scan_date}</span>}
          </p>
        </div>
        <div className="flex gap-2">
          <Link
            href="/scans"
            className="px-4 py-2 bg-[var(--card-bg)] border border-[var(--border)] rounded-lg hover:border-[var(--text-muted)] transition-colors"
          >
            All Scans
          </Link>
          <Link
            href="/compare"
            className="px-4 py-2 bg-[var(--card-bg)] border border-[var(--border)] rounded-lg hover:border-[var(--text-muted)] transition-colors"
          >
            Compare
          </Link>
        </div>
      </div>

      {/* Severity summary cards */}
      <div className="grid grid-cols-5 gap-4 mb-8">
        {SEVERITY_ORDER.map((sev) => (
          <div
            key={sev}
            className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4"
          >
            <div className="flex items-center justify-between">
              <SeverityBadge severity={sev} />
              <span className="text-2xl font-bold">
                {severityCounts[sev] || 0}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold mb-3">By Severity</h3>
          <SeverityChart severityCounts={severityCounts} />
        </div>
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold mb-3">Top 10 CWEs</h3>
          <div className="space-y-2">
            {topCwes.map(([cwe, count]) => (
              <div key={cwe} className="flex justify-between text-sm">
                <span className="text-[var(--text-muted)]">{cwe}</span>
                <span className="font-mono">{count}</span>
              </div>
            ))}
            {topCwes.length === 0 && (
              <p className="text-[var(--text-muted)] text-sm">No CWE data</p>
            )}
          </div>
        </div>
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="font-semibold mb-3">Top 10 Tools</h3>
          <div className="space-y-2">
            {topTools.map(([tool, count]) => (
              <div key={tool} className="flex justify-between text-sm">
                <span className="text-[var(--text-muted)]">{tool}</span>
                <span className="font-mono">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Findings table */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg">
        <div className="p-4 border-b border-[var(--border)]">
          <h3 className="font-semibold">All Findings</h3>
        </div>
        <FindingsTable findings={findings} />
      </div>
    </main>
  );
}
