// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { loadScan } from "@/lib/data";
import { notFound } from "next/navigation";
import Link from "next/link";
import FindingsTable from "@/components/FindingsTable";
import SeverityChart from "@/components/SeverityChart";
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
  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
  }

  return (
    <main className="max-w-7xl mx-auto px-4 py-8">
      <div className="flex items-center gap-4 mb-6">
        <Link
          href="/scans"
          className="text-[var(--text-muted)] hover:text-[var(--text)]"
        >
          ← Scans
        </Link>
        <h1 className="text-2xl font-bold">{filename}</h1>
      </div>

      <div className="flex gap-4 mb-6 flex-wrap">
        {report.target && (
          <span className="text-sm text-[var(--text-muted)]">
            Target: <strong>{report.target}</strong>
          </span>
        )}
        {report.scan_date && (
          <span className="text-sm text-[var(--text-muted)]">
            Date: {report.scan_date}
          </span>
        )}
        <span className="text-sm text-[var(--text-muted)]">
          {findings.length} findings
        </span>
      </div>

      {/* Severity summary + chart */}
      <div className="grid grid-cols-1 md:grid-cols-6 gap-4 mb-8">
        {SEVERITY_ORDER.map((sev) => (
          <div
            key={sev}
            className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3 text-center"
          >
            <SeverityBadge severity={sev} />
            <div className="text-xl font-bold mt-1">
              {severityCounts[sev] || 0}
            </div>
          </div>
        ))}
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-3">
          <SeverityChart severityCounts={severityCounts} />
        </div>
      </div>

      {/* Table */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg">
        <FindingsTable findings={findings} />
      </div>
    </main>
  );
}
