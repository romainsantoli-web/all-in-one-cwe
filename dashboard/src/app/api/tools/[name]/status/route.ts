// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { access } from "fs/promises";
import { join } from "path";
import { TOOL_META } from "@/lib/tools-data";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ name: string }> }
) {
  const { name } = await params;

  if (!TOOL_META[name]) {
    return NextResponse.json({ available: false, reason: "Unknown tool" }, { status: 404 });
  }

  const meta = TOOL_META[name];
  const isPythonScanner = meta.profile === "python-scanners";

  if (isPythonScanner) {
    const scriptName = name.replace(/-/g, "_") + ".py";
    const scriptPath = join(PROJECT_ROOT, "tools", "python-scanners", scriptName);
    try {
      await access(scriptPath);
      return NextResponse.json({ available: true });
    } catch {
      return NextResponse.json({ available: false, reason: "Scanner script not found" });
    }
  }

  // For Docker tools, check if docker is available
  try {
    const { execSync } = await import("child_process");
    execSync("docker info", { stdio: "ignore", timeout: 5000 });
    return NextResponse.json({ available: true });
  } catch {
    return NextResponse.json({ available: false, reason: "Docker not available" });
  }
}
