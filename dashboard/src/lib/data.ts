// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { readdir, readFile } from "fs/promises";
import { join } from "path";
import type { ScanReport } from "./types";

const REPORTS_DIR = process.env.REPORTS_DIR || "/data/reports/unified";

/** List available scan report files (sorted newest first). */
export async function listScans(): Promise<string[]> {
  try {
    const files = await readdir(REPORTS_DIR);
    return files
      .filter((f) => f.endsWith(".json"))
      .sort()
      .reverse();
  } catch {
    return [];
  }
}

/** Load a single scan report by filename. */
export async function loadScan(filename: string): Promise<ScanReport | null> {
  // Prevent path traversal
  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, "");
  if (safe !== filename) return null;

  try {
    const raw = await readFile(join(REPORTS_DIR, safe), "utf-8");
    const data = JSON.parse(raw);
    // Normalize: accept both array and {findings: [...]} formats
    if (Array.isArray(data)) {
      return { findings: data, finding_count: data.length };
    }
    return data as ScanReport;
  } catch {
    return null;
  }
}

/** Load the latest scan report (try analyzed → scored → deduped → unified). */
export async function loadLatestScan(): Promise<ScanReport | null> {
  const candidates = [
    "analyzed-report.json",
    "scored-report.json",
    "deduped-report.json",
    "unified-report.json",
  ];
  for (const name of candidates) {
    const report = await loadScan(name);
    if (report && report.findings.length > 0) return report;
  }
  // Fallback: try the latest file
  const files = await listScans();
  if (files.length > 0) return loadScan(files[0]);
  return null;
}
