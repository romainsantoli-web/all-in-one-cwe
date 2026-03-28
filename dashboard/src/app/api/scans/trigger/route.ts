// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { spawn } from "child_process";
import { join } from "path";
import { readFile } from "fs/promises";
import { createJob, updateJob } from "@/lib/jobs";
import { TOOL_META, getToolsForProfile } from "@/lib/tools-data";

function getProjectRoot(): string {
  return process.env.PROJECT_ROOT || "/data";
}

async function countAllFindings(tools: string[]): Promise<number> {
  let total = 0;
  for (const t of tools) {
    try {
      const reportPath = join(getProjectRoot(), "reports", t, "scan-latest.json");
      const raw = await readFile(reportPath, "utf-8");
      const data = JSON.parse(raw);
      if (Array.isArray(data)) total += data.length;
      else if (data && Array.isArray(data.findings)) total += data.findings.length;
    } catch { /* skip */ }
  }
  return total;
}

export const dynamic = "force-dynamic";

const PYTHON_BIN = process.env.PYTHON_BIN || "python3";

// Allowed profiles
const VALID_PROFILES = new Set(["light", "medium", "full"]);

// Max target URL length
const MAX_TARGET_LEN = 2048;

// URL validation — must be http(s)
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
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const target = body.target;
  if (typeof target !== "string" || target.length === 0 || target.length > MAX_TARGET_LEN) {
    return NextResponse.json({ error: "target: required URL string, max 2048 chars" }, { status: 400 });
  }
  if (!isValidTarget(target)) {
    return NextResponse.json({ error: "target: must be a valid http/https URL" }, { status: 400 });
  }

  const profile = body.profile ?? "light";
  if (typeof profile !== "string" || !VALID_PROFILES.has(profile)) {
    return NextResponse.json({ error: "profile: must be light|medium|full" }, { status: 400 });
  }

  let toolNames: string[] = [];
  if (Array.isArray(body.tools) && body.tools.length > 0) {
    // Validate each tool name
    for (const t of body.tools) {
      if (typeof t !== "string" || !TOOL_META[t]) {
        return NextResponse.json({ error: `Unknown tool: ${String(t)}` }, { status: 400 });
      }
    }
    toolNames = body.tools as string[];
  } else {
    toolNames = getToolsForProfile(profile as "light" | "medium" | "full");
  }

  const rateLimit = typeof body.rateLimit === "number" ? Math.max(1, Math.min(100, body.rateLimit)) : 10;
  const dryRun = body.dryRun === true;

  // Create job record
  const job = await createJob({
    target,
    profile,
    tools: toolNames,
  });

  // Spawn the runner process asynchronously
  const runnerScript = join(getProjectRoot(), "runner.py");
  const args = [
    runnerScript,
    "--target", target,
    "--profile", profile,
    "--rate-limit", String(rateLimit),
    "--job-id", job.id,
  ];
  if (dryRun) args.push("--dry-run");
  if (toolNames.length > 0 && Array.isArray(body.tools)) {
    args.push("--tools", toolNames.join(","));
  }

  try {
    const child = spawn(PYTHON_BIN, args, {
      cwd: getProjectRoot(),
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        JOB_ID: job.id,
        TARGET: target,
        SCAN_DATE: new Date().toISOString().slice(0, 10),
        SCANNER_RATE_LIMIT: String(rateLimit),
      },
    });

    child.unref();
    await updateJob(job.id, { status: "running", pid: child.pid });

    // Capture output to log file
    const logFile = join(getProjectRoot(), "reports", ".jobs", `${job.id}.log`);
    const { createWriteStream } = await import("fs");
    const logStream = createWriteStream(logFile, { flags: "a" });
    child.stdout?.pipe(logStream);
    child.stderr?.pipe(logStream);

    child.on("exit", async (code) => {
      if (code === 0) {
        // Read runner's summary for accurate findings count
        let findings = 0;
        try {
          const summaryPath = join(getProjectRoot(), "reports", ".jobs", `${job.id}-summary.json`);
          const raw = await readFile(summaryPath, "utf-8");
          const summary = JSON.parse(raw);
          findings = summary.total_findings || 0;
        } catch {
          findings = await countAllFindings(toolNames);
        }
        await updateJob(job.id, { status: "completed", progress: 100, findings });
      } else {
        await updateJob(job.id, { status: "failed", error: `Process exited with code ${code}` });
      }
    });
  } catch (err) {
    await updateJob(job.id, {
      status: "failed",
      error: err instanceof Error ? err.message : "Failed to spawn process",
    });
  }

  return NextResponse.json({ jobId: job.id, status: "queued" }, { status: 202 });
}
