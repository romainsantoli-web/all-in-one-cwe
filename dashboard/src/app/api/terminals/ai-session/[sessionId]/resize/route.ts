// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { resizeSession, getInteractiveSession } from "@/lib/interactive-sessions";

export const dynamic = "force-dynamic";

/**
 * POST /api/terminals/ai-session/[sessionId]/resize
 * Resize the PTY for a shell session.
 * Body: { cols: number, rows: number }
 */
export async function POST(
  request: Request,
  { params }: { params: Promise<{ sessionId: string }> },
) {
  const { sessionId } = await params;

  // Path traversal guard
  if (!sessionId || /[^a-zA-Z0-9_-]/.test(sessionId)) {
    return NextResponse.json({ error: "Invalid sessionId" }, { status: 400 });
  }

  const session = getInteractiveSession(sessionId);
  if (!session) {
    return NextResponse.json({ error: "Session not found" }, { status: 404 });
  }

  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const cols = Number(body.cols);
  const rows = Number(body.rows);

  if (!Number.isFinite(cols) || !Number.isFinite(rows) || cols < 1 || rows < 1) {
    return NextResponse.json({ error: "cols and rows must be positive integers" }, { status: 400 });
  }

  const ok = resizeSession(sessionId, Math.floor(cols), Math.floor(rows));
  return NextResponse.json({ resized: ok });
}
