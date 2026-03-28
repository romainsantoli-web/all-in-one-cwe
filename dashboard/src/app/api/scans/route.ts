// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { listScans, loadScan } from "@/lib/data";

export const dynamic = "force-dynamic";

export async function GET() {
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
  return NextResponse.json(scans.filter((s) => s !== null));
}
