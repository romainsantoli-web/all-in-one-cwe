// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import {
  copilotChatCompletion,
  COPILOT_MODELS,
  type BridgeTarget,
} from "@/lib/copilot-bridge";

export const dynamic = "force-dynamic";

const VALID_TARGETS = new Set(Object.keys(COPILOT_MODELS));

/**
 * POST /api/copilot/chat
 * Chat completion proxied through the Copilot bridge.
 * Body: {
 *   target: "claude-code" | "mistral-vibe",
 *   messages: [{ role, content }],
 *   temperature?: number,
 *   maxTokens?: number,
 *   stream?: boolean
 * }
 */
export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const target = body.target as string;
  if (!target || !VALID_TARGETS.has(target)) {
    return NextResponse.json(
      { error: `target must be one of: ${[...VALID_TARGETS].join(", ")}` },
      { status: 400 },
    );
  }

  const messages = body.messages;
  if (!Array.isArray(messages) || messages.length === 0) {
    return NextResponse.json(
      { error: "messages: non-empty array required" },
      { status: 400 },
    );
  }

  // Validate each message
  for (const msg of messages) {
    if (
      typeof msg !== "object" ||
      msg === null ||
      typeof msg.role !== "string" ||
      typeof msg.content !== "string"
    ) {
      return NextResponse.json(
        { error: "Each message must have { role: string, content: string }" },
        { status: 400 },
      );
    }
    if (msg.content.length > 100_000) {
      return NextResponse.json(
        { error: "Message content too large (max 100KB)" },
        { status: 400 },
      );
    }
  }

  const temperature =
    typeof body.temperature === "number"
      ? Math.max(0, Math.min(2, body.temperature))
      : undefined;
  const maxTokens =
    typeof body.maxTokens === "number"
      ? Math.max(1, Math.min(32_000, body.maxTokens))
      : undefined;
  const stream = body.stream === true;

  try {
    const upstreamRes = await copilotChatCompletion({
      target: target as BridgeTarget,
      messages: messages as Array<{ role: string; content: string }>,
      temperature,
      maxTokens,
      stream,
    });

    if (!upstreamRes.ok) {
      const errText = await upstreamRes.text().catch(() => "");
      return NextResponse.json(
        {
          error: `Copilot API error (${upstreamRes.status})`,
          details: errText.slice(0, 500),
        },
        { status: upstreamRes.status >= 500 ? 502 : upstreamRes.status },
      );
    }

    if (stream && upstreamRes.body) {
      // Forward the SSE stream from Copilot
      return new Response(upstreamRes.body, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        },
      });
    }

    // Non-streaming: return parsed JSON
    const data = await upstreamRes.json();
    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      {
        error: err instanceof Error ? err.message : "Bridge request failed",
      },
      { status: 502 },
    );
  }
}
