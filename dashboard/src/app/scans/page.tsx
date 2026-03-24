// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { listScans, loadScan } from "@/lib/data";
import Link from "next/link";
import SeverityBadge from "@/components/SeverityBadge";
import { SEVERITY_ORDER } from "@/lib/types";

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
        profile: report.profile,
        tool_count: report.tool_count,
        severityCounts,
      };
    })
  );

  const validScans = scans.filter(Boolean);

  return (
    <main className="px-6 py-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Scan Reports</h1>
          <p className="text-sm text-[var(--text-muted)] mt-0.5">
            {validScans.length} report{validScans.length !== 1 ? "s" : ""} available
          </p>
        </div>
      </div>

      {validScans.length === 0 ? (
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-8 text-center">
          <p className="text-[var(--text-muted)]">
            No scan reports found. Run a scan first.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {validScans.map((scan) => (
            <Link
              key={scan!.filename}
              href={`/scans/${encodeURIComponent(scan!.filename)}`}
              className="block bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 hover:border-[var(--border-hover)] transition-all"
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <span className="font-semibold">{scan!.target}</span>
                  {scan!.profile && (
                    <span className="text-xs px-2 py-0.5 bg-[var(--accent)]20 text-[var(--accent)] rounded font-medium">
                      {scan!.profile}
                    </span>
                  )}
                </div>
                <span className="text-xs text-[var(--text-muted)]">{scan!.date}</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex gap-2">
                  {SEVERITY_ORDER.map(
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
                <span className="text-xs text-[var(--text-dim)]">
                  {scan!.total} findings
                  {scan!.tool_count ? ` · ${scan!.tool_count} tools` : ""}
                  {" · "}
                  {scan!.filename}
                </span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </main>
  );
}
