// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * SSE stream for job progress polling.
 * Polls the job JSON file every 2s and sends updates to the client.
 */
import { getJob } from "@/lib/jobs";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ jobId: string }> }
) {
  const { jobId } = await params;
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const POLL_INTERVAL = 2000;
      const MAX_POLLS = 900; // 30 minutes max

      for (let i = 0; i < MAX_POLLS; i++) {
        const job = await getJob(jobId);
        if (!job) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ error: "Job not found" })}\n\n`));
          controller.close();
          return;
        }

        controller.enqueue(encoder.encode(`data: ${JSON.stringify(job)}\n\n`));

        // Terminal states → close stream
        if (job.status === "completed" || job.status === "failed" || job.status === "cancelled") {
          controller.enqueue(encoder.encode("data: [DONE]\n\n"));
          controller.close();
          return;
        }

        await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL));
      }

      // Timeout
      controller.enqueue(encoder.encode(`data: ${JSON.stringify({ error: "Stream timeout" })}\n\n`));
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
