// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { sendInput, getInteractiveSession } from "@/lib/interactive-sessions";

export const dynamic = "force-dynamic";

/**
 * POST /api/terminals/ai-session/[sessionId]/input
 * Send text to the stdin of an interactive session.
 * Body: { text: string }
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

  const text = body.text;
  if (typeof text !== "string") {
    return NextResponse.json({ error: "text: required string" }, { status: 400 });
  }

  // Limit input size (prevent abuse)
  if (text.length > 10_000) {
    return NextResponse.json({ error: "Input too large (max 10KB)" }, { status: 400 });
  }

  const ok = sendInput(sessionId, text);
  if (!ok) {
    return NextResponse.json({ error: "Session is not running" }, { status: 400 });
  }

  return NextResponse.json({ sent: true });
}
