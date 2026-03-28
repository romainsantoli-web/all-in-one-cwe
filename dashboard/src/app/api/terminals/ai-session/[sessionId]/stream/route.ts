// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { subscribeOutput, getInteractiveSession } from "@/lib/interactive-sessions";

export const dynamic = "force-dynamic";

/**
 * GET /api/terminals/ai-session/[sessionId]/stream
 * SSE stream of stdout/stderr from an interactive session.
 */
export async function GET(
  _request: Request,
  { params }: { params: Promise<{ sessionId: string }> },
) {
  const { sessionId } = await params;

  // Path traversal guard
  if (!sessionId || /[^a-zA-Z0-9_-]/.test(sessionId)) {
    return new Response("Invalid sessionId", { status: 400 });
  }

  const session = getInteractiveSession(sessionId);
  if (!session) {
    return new Response("Session not found", { status: 404 });
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    start(controller) {
      const unsubscribe = subscribeOutput(sessionId, (chunk) => {
        try {
          const data = JSON.stringify({ type: "output", text: chunk });
          controller.enqueue(encoder.encode(`data: ${data}\n\n`));
        } catch {
          // Stream closed
        }
      });

      if (!unsubscribe) {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ type: "error", text: "Session not found" })}\n\n`));
        controller.close();
        return;
      }

      // Check periodically if session has stopped
      const checkInterval = setInterval(() => {
        const s = getInteractiveSession(sessionId);
        if (!s || s.status !== "running") {
          clearInterval(checkInterval);
          try {
            const status = s?.status || "stopped";
            controller.enqueue(
              encoder.encode(`data: ${JSON.stringify({ type: "status", status })}\n\n`),
            );
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            controller.close();
          } catch { /* already closed */ }
          unsubscribe();
        }
      }, 1000);

      // Cleanup on cancel
      _request.signal.addEventListener("abort", () => {
        clearInterval(checkInterval);
        unsubscribe();
      });
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
