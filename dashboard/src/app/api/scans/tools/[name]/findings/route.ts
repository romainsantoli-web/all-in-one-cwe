// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { readFile } from "fs/promises";
import { join } from "path";

function getProjectRoot(): string {
  return process.env.PROJECT_ROOT || "/data";
}

const TOOL_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ name: string }> },
) {
  const { name } = await params;

  // Validate tool name — block path traversal
  if (!name || !TOOL_NAME_RE.test(name)) {
    return NextResponse.json({ error: "Invalid tool name" }, { status: 400 });
  }

  const reportPath = join(getProjectRoot(), "reports", name, "scan-latest.json");

  try {
    const raw = await readFile(reportPath, "utf-8");
    const data: unknown = JSON.parse(raw);

    // Findings can be top-level array or nested under .findings
    let findings: unknown[];
    if (Array.isArray(data)) {
      findings = data;
    } else if (data && typeof data === "object" && "findings" in data && Array.isArray((data as Record<string, unknown>).findings)) {
      findings = (data as Record<string, unknown>).findings as unknown[];
    } else {
      findings = [];
    }

    return NextResponse.json({ tool: name, count: findings.length, findings });
  } catch {
    return NextResponse.json({ tool: name, count: 0, findings: [] });
  }
}
