// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";

export const dynamic = "force-dynamic";

const execFileAsync = promisify(execFile);
const PYTHON = process.env.PYTHON_BIN || "python3";
const SCANNERS_DIR = path.resolve(process.cwd(), "..", "tools", "python-scanners");

const ALLOWED_TOOLS: Record<string, string> = {
  "crypto-analyzer": "crypto_analyzer.py",
  "steg-analyzer": "steg_analyzer.py",
  "pcap-analyzer": "pcap_analyzer.py",
  "forensic-toolkit": "forensic_toolkit.py",
};

export async function POST(req: NextRequest) {
  let body: { tool?: string; target?: string; mode?: string; input?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const { tool, target, mode, input } = body;

  if (!tool || !ALLOWED_TOOLS[tool]) {
    return NextResponse.json(
      { error: `Invalid tool. Allowed: ${Object.keys(ALLOWED_TOOLS).join(", ")}` },
      { status: 400 },
    );
  }

  // Block path traversal
  if (target && (target.includes("..") || target.includes("\0"))) {
    return NextResponse.json({ error: "Invalid target path" }, { status: 400 });
  }
  if (input && input.length > 10000) {
    return NextResponse.json({ error: "Input too large" }, { status: 400 });
  }

  const scriptPath = path.join(SCANNERS_DIR, ALLOWED_TOOLS[tool]);
  const args: string[] = [];

  if (target) args.push("--target", target);
  if (mode) args.push("--mode", mode.replace(/[^a-z-]/g, ""));
  if (input && tool === "crypto-analyzer") args.push("--input", input);

  try {
    const { stdout, stderr } = await execFileAsync(PYTHON, [scriptPath, ...args], {
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });

    // Try to parse the last JSON line (report path) or return raw output
    const lines = stdout.trim().split("\n");
    let report = null;
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        report = JSON.parse(lines[i]);
        break;
      } catch {
        continue;
      }
    }

    return NextResponse.json({
      ok: true,
      tool,
      output: stdout.slice(0, 8000),
      stderr: stderr.slice(0, 2000),
      report,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ ok: false, error: message.slice(0, 2000) }, { status: 500 });
  }
}
