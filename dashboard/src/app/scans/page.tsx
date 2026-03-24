// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { listScans, loadScan } from "@/lib/data";
import Link from "next/link";
import SeverityBadge from "@/components/SeverityBadge";

export const dynamic = "force-dynamic";

export default async function ScansPage() {
  const files = await listScans();

  const scans = await Promise.all(
    files.map(async (filename) => {
      const report = await loadScan(filename);
      if (!report) return null;
      const severityCounts: Record<string, number> = {};
      for (const f of report.findings) {
        const sev = (f.severity || "info").toLowerCase();
        severityCounts[sev] = (severityCounts[sev] || 0) + 1;
      }
      return {
        filename,
        target: report.target || "unknown",
        date: report.scan_date || filename,
        total: report.findings.length,
        severityCounts,
      };
    })
  );

  const validScans = scans.filter(Boolean);

  return (
    <main className="max-w-5xl mx-auto px-4 py-8">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">All Scans</h1>
        <Link
          href="/"
          className="text-sm text-[var(--text-muted)] hover:text-[var(--text)]"
        >
          ← Dashboard
        </Link>
      </div>

      {validScans.length === 0 ? (
        <p className="text-[var(--text-muted)]">
          No scan reports found. Run a scan first.
        </p>
      ) : (
        <div className="space-y-3">
          {validScans.map((scan) => (
            <Link
              key={scan!.filename}
              href={`/scans/${encodeURIComponent(scan!.filename)}`}
              className="block bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 hover:border-[var(--text-muted)] transition-colors"
            >
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-medium">{scan!.target}</span>
                  <span className="text-[var(--text-muted)] text-sm ml-3">
                    {scan!.date}
                  </span>
                </div>
                <div className="flex gap-2">
                  {["critical", "high", "medium", "low", "info"].map(
                    (sev) =>
                      (scan!.severityCounts[sev] || 0) > 0 && (
                        <span key={sev} className="flex items-center gap-1">
                          <SeverityBadge severity={sev} />
                          <span className="text-xs font-mono">
                            {scan!.severityCounts[sev]}
                          </span>
                        </span>
                      )
                  )}
                </div>
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-1">
                {scan!.total} findings · {scan!.filename}
              </p>
            </Link>
          ))}
        </div>
      )}
    </main>
  );
}
