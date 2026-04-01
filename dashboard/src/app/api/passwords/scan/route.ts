// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";

export const dynamic = "force-dynamic";

const execFileAsync = promisify(execFile);

const SCANNER_PATH = path.resolve(
  process.cwd(),
  "..",
  "tools",
  "python-scanners",
  "vault_extractor.py"
);

const PYTHON = process.env.PYTHON_BIN || "python3";

export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const extraDirs = searchParams.get("extra_dirs") || "";
  const category = searchParams.get("category") || "";

  // Validate inputs — block path traversal
  if (extraDirs.includes("..") || category.includes("..")) {
    return NextResponse.json({ error: "Invalid input" }, { status: 400 });
  }

  const args = ["--json"];
  if (extraDirs) {
    args.push("--extra-dirs", ...extraDirs.split(",").map((d) => d.trim()).filter(Boolean));
  }
  if (category) {
    args.push("--categories", category);
  }

  try {
    const { stdout } = await execFileAsync(PYTHON, [SCANNER_PATH, ...args], {
      timeout: 30000,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });

    // Parse output — vault_extractor.py outputs JSON findings
    let results: Array<{
      format_id: string;
      format_name: string;
      category: string;
      file_path: string;
      size: number;
      encrypted: boolean;
      note: string;
    }> = [];

    try {
      const parsed = JSON.parse(stdout);
      if (Array.isArray(parsed)) {
        results = parsed;
      } else if (parsed.findings) {
        results = parsed.findings.map((f: Record<string, unknown>) => ({
          format_id: f.format_id || "",
          format_name: f.title || f.format_name || "",
          category: f.category || "unknown",
          file_path: f.endpoint || f.file_path || "",
          size: f.size || 0,
          encrypted: f.encrypted ?? true,
          note: f.description || f.note || "",
        }));
      }
    } catch {
      // Try line-by-line JSON
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.startsWith("{")) {
          try {
            results.push(JSON.parse(trimmed));
          } catch { /* skip */ }
        }
      }
    }

    // Build category counts
    const categories: Record<string, number> = {};
    for (const r of results) {
      categories[r.category] = (categories[r.category] || 0) + 1;
    }

    return NextResponse.json({
      total: results.length,
      results,
      categories,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg, total: 0, results: [], categories: {} }, { status: 500 });
  }
}
