// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * GET /api/terminals/logs
 * Returns combined recent terminal logs for LLM context injection.
 * Query params:
 *   - jobId (optional): specific job ID
 *   - limit (optional): max characters to return (default 4000)
 *   - running (optional): "true" to only include running terminals
 */
import { NextResponse } from "next/server";
import { listJobs, getJob } from "@/lib/jobs";
import { readFile, stat } from "fs/promises";
import { join } from "path";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const MAX_LOG_SIZE = 8000;

async function readLogTail(jobId: string, maxChars: number): Promise<string | null> {
  const safeId = jobId.replace(/[^a-zA-Z0-9_-]/g, "");
  const logPath = join(PROJECT_ROOT, "reports", ".jobs", `${safeId}.log`);

  try {
    const st = await stat(logPath);
    if (st.size === 0) return null;

    const raw = await readFile(logPath, "utf-8");
    // Return last N chars (tail)
    if (raw.length > maxChars) {
      return "...(truncated)\n" + raw.slice(-maxChars);
    }
    return raw;
  } catch {
    return null;
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const specificJobId = searchParams.get("jobId");
  const limitStr = searchParams.get("limit");
  const onlyRunning = searchParams.get("running") === "true";

  const limit = limitStr ? Math.min(Math.max(parseInt(limitStr, 10) || 4000, 500), MAX_LOG_SIZE) : 4000;

  // Single job mode
  if (specificJobId) {
    const safeId = specificJobId.replace(/[^a-zA-Z0-9_-]/g, "");
    const job = await getJob(safeId);
    if (!job) {
      return NextResponse.json({ error: "Job not found" }, { status: 404 });
    }
    const log = await readLogTail(safeId, limit);
    return NextResponse.json({
      terminals: [{
        id: job.id,
        tool: job.tool,
        target: job.target,
        status: job.status,
        log: log || "(no output yet)",
        findings: job.findings,
        error: job.error ?? null,
      }],
    });
  }

  // Multi-job mode
  const jobs = await listJobs();
  const filtered = onlyRunning ? jobs.filter((j) => j.status === "running") : jobs.slice(0, 10);
  const perJobLimit = Math.floor(limit / Math.max(filtered.length, 1));

  const results = await Promise.all(
    filtered.map(async (job) => {
      const log = await readLogTail(job.id, Math.min(perJobLimit, 2000));
      return {
        id: job.id,
        tool: job.tool,
        target: job.target,
        status: job.status,
        log: log || "(no output yet)",
        findings: job.findings,
        error: job.error ?? null,
      };
    })
  );

  return NextResponse.json({ terminals: results });
}
