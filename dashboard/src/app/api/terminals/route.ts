// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { listJobs, updateJob } from "@/lib/jobs";

export const dynamic = "force-dynamic";

/**
 * GET /api/terminals
 * List all jobs with their terminal status. Running jobs have live terminals.
 */
export async function GET() {
  const jobs = await listJobs();
  const terminals = jobs.map((j) => ({
    id: j.id,
    tool: j.tool,
    tools: j.tools,
    target: j.target,
    status: j.status,
    pid: j.pid ?? null,
    createdAt: j.createdAt,
    updatedAt: j.updatedAt,
    findings: j.findings,
    error: j.error ?? null,
  }));
  return NextResponse.json({ terminals });
}

/**
 * POST /api/terminals
 * Kill a running terminal (process) by job ID.
 * Body: { jobId: string }
 */
export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const jobId = body.jobId;
  if (typeof jobId !== "string" || jobId.length === 0) {
    return NextResponse.json({ error: "jobId: required string" }, { status: 400 });
  }

  const jobs = await listJobs();
  const job = jobs.find((j) => j.id === jobId);
  if (!job) {
    return NextResponse.json({ error: "Job not found" }, { status: 404 });
  }

  if (job.status !== "running") {
    return NextResponse.json({ error: "Job is not running" }, { status: 400 });
  }

  if (!job.pid) {
    return NextResponse.json({ error: "No PID recorded for this job" }, { status: 400 });
  }

  try {
    // Send SIGTERM to the process group (negative PID kills the group)
    process.kill(-job.pid, "SIGTERM");
  } catch {
    try {
      // Fallback: kill just the process
      process.kill(job.pid, "SIGTERM");
    } catch {
      // Process may already be gone
    }
  }

  await updateJob(jobId, { status: "cancelled", error: "Killed by user" });

  return NextResponse.json({ killed: true, jobId });
}
