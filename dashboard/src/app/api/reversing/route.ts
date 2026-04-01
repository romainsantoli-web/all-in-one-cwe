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
  "disasm-analyzer": "disasm_analyzer.py",
  "pwn-toolkit": "pwn_toolkit.py",
  "privesc-scanner": "privesc_scanner.py",
};

export async function POST(req: NextRequest) {
  let body: {
    tool?: string;
    target?: string;
    mode?: string;
    length?: number;
    find?: string;
    function?: string;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const { tool, target, mode } = body;

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

  const scriptPath = path.join(SCANNERS_DIR, ALLOWED_TOOLS[tool]);
  const args: string[] = [];

  if (target) args.push("--target", target);
  if (mode) args.push("--mode", mode.replace(/[^a-z-]/g, ""));

  // pwn-toolkit specific args
  if (tool === "pwn-toolkit") {
    if (body.length && Number.isInteger(body.length) && body.length > 0 && body.length <= 10000) {
      args.push("--length", String(body.length));
    }
    if (body.find && typeof body.find === "string" && body.find.length < 200) {
      args.push("--find", body.find.replace(/[^a-zA-Z0-9]/g, ""));
    }
  }

  // disasm-analyzer specific args
  if (tool === "disasm-analyzer" && body.function) {
    const fn = String(body.function).replace(/[^a-zA-Z0-9_]/g, "");
    if (fn) args.push("--function", fn);
  }

  try {
    const { stdout, stderr } = await execFileAsync(PYTHON, [scriptPath, ...args], {
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });

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
