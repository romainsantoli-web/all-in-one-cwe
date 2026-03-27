// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { readdir, readFile } from "fs/promises";
import { join } from "path";
import type { ScanReport } from "./types";

const REPORTS_DIR = process.env.REPORTS_DIR || "/data/reports/unified";
const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

/** List available scan report files (sorted newest first). */
export async function listScans(): Promise<string[]> {
  try {
    const files = await readdir(REPORTS_DIR);
    return files
      .filter((f) => f.endsWith(".json") && !f.startsWith("payload-stats"))
      .sort()
      .reverse();
  } catch {
    return [];
  }
}

/** Normalize a single finding: map alternate field names to canonical ones. */
function normalizeFinding(raw: Record<string, unknown>): Record<string, unknown> {
  const f = { ...raw };
  // name → title (unified reports use "name")
  if (!f.title && f.name) f.title = f.name;
  // solution → remediation
  if (!f.remediation && f.solution) f.remediation = f.solution;
  // Normalize severity: "unknown" → "info"
  if (!f.severity || f.severity === "unknown") f.severity = "info";
  return f;
}

/** Normalize a raw report object into a ScanReport. */
function normalizeReport(data: Record<string, unknown>): ScanReport {
  let findings: Record<string, unknown>[] = [];
  if (Array.isArray(data)) {
    findings = data;
  } else if (Array.isArray(data.findings)) {
    findings = data.findings as Record<string, unknown>[];
  }
  const normalized = findings.map(normalizeFinding);
  return {
    scan_date: (data.scan_date ?? data.generated_at) as string | undefined,
    target: data.target as string | undefined,
    profile: data.profile as string | undefined,
    tool_count: data.tool_count as number | undefined,
    finding_count: (data.finding_count ?? data.total_findings ?? normalized.length) as number,
    findings: normalized as unknown as ScanReport["findings"],
    severity_summary: (data.severity_summary ?? data.by_severity) as Record<string, number> | undefined,
  };
}

/** Load a single scan report by filename. */
export async function loadScan(filename: string): Promise<ScanReport | null> {
  // Prevent path traversal
  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, "");
  if (safe !== filename) return null;

  try {
    const raw = await readFile(join(REPORTS_DIR, safe), "utf-8");
    const data = JSON.parse(raw);
    return normalizeReport(data);
  } catch {
    return null;
  }
}

/** Load the latest scan report (try analyzed → scored → deduped → unified → fallback). */
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
  // Fallback: try the latest file (prefer unified-report-* files, then any .json)
  const files = await listScans();
  const unified = files.filter((f) => f.startsWith("unified-report"));
  const ordered = [...unified, ...files.filter((f) => !unified.includes(f))];
  for (const file of ordered) {
    const report = await loadScan(file);
    if (report && report.findings.length > 0) return report;
  }
  return null;
}

/** Payload stats shape. */
export interface PayloadStats {
  patt_categories: number;
  patt_files: number;
  patt_payloads: number;
  patt_commit_hash: string;
  patt_commit_date: string;
  patt_age_days: number | null;
  patt_stale: boolean;
  curated_files: number;
  indexed_at: string;
  categories: { name: string; cwe: string; files: number; payloads: number }[];
}

/** Load payload engine stats from reports/payload-stats.json. */
export async function loadPayloadStats(): Promise<PayloadStats | null> {
  const candidates = [
    join(PROJECT_ROOT, "reports", "payload-stats.json"),
    join(REPORTS_DIR, "..", "payload-stats.json"),
  ];
  for (const path of candidates) {
    try {
      const raw = await readFile(path, "utf-8");
      return JSON.parse(raw) as PayloadStats;
    } catch {
      // try next
    }
  }
  return null;
}
