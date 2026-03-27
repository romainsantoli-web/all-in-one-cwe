// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * SSE stream for terminal output — tails the job log file in real-time.
 * GET /api/terminals/[jobId]/stream
 */
import { getJob } from "@/lib/jobs";
import { open, stat } from "fs/promises";
import { join } from "path";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ jobId: string }> }
) {
  const { jobId } = await params;
  const encoder = new TextEncoder();

  // Prevent path traversal in jobId
  const safeId = jobId.replace(/[^a-zA-Z0-9_-]/g, "");
  const logPath = join(PROJECT_ROOT, "reports", ".jobs", `${safeId}.log`);

  const stream = new ReadableStream({
    async start(controller) {
      const POLL_INTERVAL = 500; // 0.5s for near real-time feel
      const MAX_POLLS = 3600; // 30 minutes max
      let offset = 0;

      for (let i = 0; i < MAX_POLLS; i++) {
        // Check job status
        const job = await getJob(safeId);

        // Try to read new content from log file
        try {
          const st = await stat(logPath);
          if (st.size > offset) {
            const fd = await open(logPath, "r");
            const buf = Buffer.alloc(st.size - offset);
            await fd.read(buf, 0, buf.length, offset);
            await fd.close();
            offset = st.size;

            const text = buf.toString("utf-8");
            // Send as SSE lines
            const payload = JSON.stringify({ type: "output", text });
            controller.enqueue(encoder.encode(`data: ${payload}\n\n`));
          }
        } catch {
          // Log file may not exist yet
        }

        // If job is done, send final status and close
        if (job && (job.status === "completed" || job.status === "failed" || job.status === "cancelled")) {
          const statusPayload = JSON.stringify({
            type: "status",
            status: job.status,
            findings: job.findings,
            error: job.error ?? null,
          });
          controller.enqueue(encoder.encode(`data: ${statusPayload}\n\n`));
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
          controller.close();
          return;
        }

        if (!job) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: "error", text: "Job not found" })}\n\n`));
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
          controller.close();
          return;
        }

        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
      }

      // Timeout
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: "error", text: "Stream timeout" })}\n\n`));
      controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}
