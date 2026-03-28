// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { listScans, loadScan } from "@/lib/data";
import ScansList from "@/components/ScansList";
import type { ScanItem } from "@/components/ScansList";

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
      } satisfies ScanItem;
    })
  );

  const validScans: ScanItem[] = scans.filter((s) => s !== null);

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

      <ScansList initialScans={validScans} />
    </main>
  );
}
