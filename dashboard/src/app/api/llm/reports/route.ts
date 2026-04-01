// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { readdir, readFile, mkdir } from "fs/promises";
import { join } from "path";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const REPORTS_LLM_DIR = join(PROJECT_ROOT, "reports", "reports-llm");
const REPORTS_SCAN_DIR = join(PROJECT_ROOT, "reports", "unified");

const SAFE_FILENAME = /^[a-zA-Z0-9._-]{1,200}$/;

async function ensureDir(dir: string) {
  await mkdir(dir, { recursive: true });
}

/** GET — list LLM reports and scan reports */
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const type = searchParams.get("type") || "all";
  const filename = searchParams.get("file");

  // Download a specific file
  if (filename && SAFE_FILENAME.test(filename)) {
    const dir = searchParams.get("dir") === "scan" ? REPORTS_SCAN_DIR : REPORTS_LLM_DIR;
    try {
      const content = await readFile(join(dir, filename), "utf-8");
      return new Response(content, {
        headers: {
          "Content-Type": filename.endsWith(".md") ? "text/markdown" : "application/json",
          "Content-Disposition": `attachment; filename="${filename}"`,
        },
      });
    } catch {
      return NextResponse.json({ error: "File not found" }, { status: 404 });
    }
  }

  const result: { llm: Array<Record<string, unknown>>; scan: Array<Record<string, unknown>> } = {
    llm: [],
    scan: [],
  };

  // LLM reports
  if (type === "all" || type === "llm") {
    await ensureDir(REPORTS_LLM_DIR);
    try {
      const files = await readdir(REPORTS_LLM_DIR);
      result.llm = files
        .filter((f) => f.endsWith(".md") || f.endsWith(".json"))
        .sort()
        .reverse()
        .map((f) => ({ filename: f, type: "llm" }));
    } catch { /* empty */ }
  }

  // Scan reports
  if (type === "all" || type === "scan") {
    try {
      const files = await readdir(REPORTS_SCAN_DIR);
      result.scan = files
        .filter((f) => f.endsWith(".json") && !f.startsWith("payload-stats"))
        .sort()
        .reverse()
        .map((f) => ({ filename: f, type: "scan" }));
    } catch { /* empty */ }
  }

  return NextResponse.json(result);
}
