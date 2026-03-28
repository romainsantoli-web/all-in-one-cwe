// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { execFile } from "child_process";
import { promisify } from "util";

export const dynamic = "force-dynamic";

const execFileAsync = promisify(execFile);
const PYTHON_BIN = process.env.PYTHON_BIN || "python3";
const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

// Domain validation: only alphanumeric, dots, hyphens
const DOMAIN_RE = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$/;

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = searchParams.get("domain") || "";

  if (!domain || !DOMAIN_RE.test(domain)) {
    return NextResponse.json({ error: "Invalid domain parameter" }, { status: 400 });
  }

  try {
    const { stdout } = await execFileAsync(
      PYTHON_BIN,
      ["-c", `
import sys, json
sys.path.insert(0, "${PROJECT_ROOT}")
from memory.scan_memory import ScanMemory

mem = ScanMemory()
if not mem.available:
    print(json.dumps({"profile": None, "recommended_tools": [], "tech_findings": 0}))
    sys.exit(0)

domain = ${JSON.stringify(domain)}
profile = mem.recall_domain_profile(domain)
scores = mem.get_effectiveness_scores()
tech_stack = (profile or {}).get("tech_stack", [])
tech_results = mem.recall_by_tech_stack(tech_stack, limit=20) if tech_stack else []

recommended = sorted(
    [{"name": k, "score": v} for k, v in scores.items()],
    key=lambda x: x["score"]["hit_count"],
    reverse=True,
)[:10]

print(json.dumps({
    "profile": profile,
    "recommended_tools": recommended,
    "tech_findings": len(tech_results),
}))
`],
      { cwd: PROJECT_ROOT, timeout: 10000 },
    );

    const data = JSON.parse(stdout.trim());
    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { profile: null, recommended_tools: [], tech_findings: 0 },
      { status: 200 },
    );
  }
}
