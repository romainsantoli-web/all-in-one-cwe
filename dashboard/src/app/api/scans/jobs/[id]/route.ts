// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { getJob, updateJob, deleteJob } from "@/lib/jobs";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const job = await getJob(id);
  if (!job) {
    return NextResponse.json({ error: "Job not found" }, { status: 404 });
  }
  return NextResponse.json(job);
}

export async function DELETE(
  _request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const job = await getJob(id);
  if (!job) {
    return NextResponse.json({ error: "Job not found" }, { status: 404 });
  }

  // Running/queued → cancel (kill process)
  if (job.status === "running" || job.status === "queued") {
    if (job.pid) {
      try {
        process.kill(job.pid, "SIGTERM");
      } catch {
        // Process may have already exited
      }
    }
    await updateJob(id, { status: "cancelled" });
    return NextResponse.json({ ok: true, action: "cancelled" });
  }

  // Completed/failed/cancelled → delete the job file
  const deleted = await deleteJob(id);
  if (!deleted) {
    return NextResponse.json({ error: "Failed to delete job" }, { status: 500 });
  }
  return NextResponse.json({ ok: true, action: "deleted" });
}
