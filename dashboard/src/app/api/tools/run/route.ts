// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { spawn } from "child_process";
import { join } from "path";
import { readFile } from "fs/promises";
import { createWriteStream } from "fs";
import { createJob, updateJob } from "@/lib/jobs";
import { TOOL_META } from "@/lib/tools-data";

async function countFindings(toolName: string): Promise<number> {
  try {
    const reportPath = join(PROJECT_ROOT, "reports", toolName, "scan-latest.json");
    const raw = await readFile(reportPath, "utf-8");
    const data = JSON.parse(raw);
    if (Array.isArray(data)) return data.length;
    if (data && Array.isArray(data.findings)) return data.findings.length;
  } catch { /* report not found or invalid */ }
  return 0;
}

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const PYTHON_BIN = process.env.PYTHON_BIN || "python3";
const MAX_TARGET_LEN = 2048;

function isValidTarget(target: string): boolean {
  try {
    const u = new URL(target);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const tool = body.tool;
  if (typeof tool !== "string" || !TOOL_META[tool]) {
    return NextResponse.json(
      { error: `Unknown tool. Available: ${Object.keys(TOOL_META).slice(0, 20).join(", ")}...` },
      { status: 400 },
    );
  }

  const target = body.target;
  if (typeof target !== "string" || target.length === 0 || target.length > MAX_TARGET_LEN) {
    return NextResponse.json({ error: "target: required URL string" }, { status: 400 });
  }
  if (!isValidTarget(target)) {
    return NextResponse.json({ error: "target: must be valid http/https URL" }, { status: 400 });
  }

  const options = (typeof body.options === "object" && body.options !== null)
    ? body.options as Record<string, string>
    : {};

  // Create job record
  const job = await createJob({
    target,
    tools: [tool],
    tool,
  });

  // Determine how to run the tool
  const meta = TOOL_META[tool];
  const isPythonScanner = meta.profile === "python-scanners";

  if (isPythonScanner) {
    // Run the Python scanner directly
    const scriptName = tool.replace(/-/g, "_") + ".py";
    const scriptPath = join(PROJECT_ROOT, "tools", "python-scanners", scriptName);
    const args = [scriptPath, "--target", target];

    const child = spawn(PYTHON_BIN, args, {
      cwd: PROJECT_ROOT,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        TARGET: target,
        OUTPUT_DIR: join(PROJECT_ROOT, "reports", tool),
        SCAN_DATE: new Date().toISOString().slice(0, 10),
        ...options,
      },
    });

    child.unref();
    await updateJob(job.id, { status: "running", pid: child.pid });

    // Capture output to log file for terminal view
    const logFile = join(PROJECT_ROOT, "reports", ".jobs", `${job.id}.log`);
    const logStream = createWriteStream(logFile, { flags: "a" });
    child.stdout?.pipe(logStream);
    child.stderr?.pipe(logStream);

    child.on("exit", async (code) => {
      const findings = code === 0 ? await countFindings(tool) : 0;
      await updateJob(job.id, {
        status: code === 0 ? "completed" : "failed",
        progress: 100,
        findings,
        error: code !== 0 ? `Exited with code ${code}` : undefined,
      });
    });
  } else {
    // For Docker-based tools, use docker compose run
    const child = spawn("docker", ["compose", "run", "--rm", tool], {
      cwd: PROJECT_ROOT,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        TARGET: target,
        SCAN_DATE: new Date().toISOString().slice(0, 10),
      },
    });

    child.unref();
    await updateJob(job.id, { status: "running", pid: child.pid });

    // Capture output to log file for terminal view
    const logFile = join(PROJECT_ROOT, "reports", ".jobs", `${job.id}.log`);
    const logStream2 = createWriteStream(logFile, { flags: "a" });
    child.stdout?.pipe(logStream2);
    child.stderr?.pipe(logStream2);

    child.on("exit", async (code) => {
      const findings = code === 0 ? await countFindings(tool) : 0;
      await updateJob(job.id, {
        status: code === 0 ? "completed" : "failed",
        progress: 100,
        findings,
        error: code !== 0 ? `Exited with code ${code}` : undefined,
      });
    });
  }

  return NextResponse.json({ jobId: job.id, status: "queued" }, { status: 202 });
}
