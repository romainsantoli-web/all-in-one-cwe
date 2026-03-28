// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import {
  createInteractiveSession,
  listInteractiveSessions,
  killInteractiveSession,
  removeInteractiveSession,
  getProviderInfo,
  type AIProvider,
} from "@/lib/interactive-sessions";
import {
  getBridgeEnvForProvider,
  getBridgeStatus,
  type BridgeTarget,
} from "@/lib/copilot-bridge";

export const dynamic = "force-dynamic";

const VALID_PROVIDERS = new Set<AIProvider>(["claude-code", "mistral-vibe", "shell"]);
const BRIDGE_TARGETS = new Set<BridgeTarget>(["claude-code", "mistral-vibe"]);

/**
 * GET /api/terminals/ai-session
 * List all interactive AI sessions + provider availability + bridge status.
 */
export async function GET() {
  const sessions = listInteractiveSessions();
  const providers = getProviderInfo();
  const bridge = await getBridgeStatus();
  return NextResponse.json({ sessions, providers, bridge });
}

/**
 * POST /api/terminals/ai-session
 * Create a new interactive AI session.
 * Body: { provider: "claude-code" | "mistral-vibe" | "shell", useBridge?: boolean }
 */
export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const provider = body.provider as AIProvider;
  if (!provider || !VALID_PROVIDERS.has(provider)) {
    return NextResponse.json(
      { error: `Invalid provider. Must be one of: ${[...VALID_PROVIDERS].join(", ")}` },
      { status: 400 },
    );
  }

  // If useBridge requested, inject Copilot credentials as env vars
  let bridgeEnv: Record<string, string> = {};
  const useBridge = body.useBridge === true;
  if (useBridge && BRIDGE_TARGETS.has(provider as BridgeTarget)) {
    try {
      bridgeEnv = await getBridgeEnvForProvider(provider as BridgeTarget);
    } catch (err) {
      return NextResponse.json(
        { error: `Bridge error: ${err instanceof Error ? err.message : String(err)}` },
        { status: 400 },
      );
    }
  }

  try {
    const session = createInteractiveSession(provider, bridgeEnv);
    return NextResponse.json(
      { session, bridged: useBridge && Object.keys(bridgeEnv).length > 0 },
      { status: 201 },
    );
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to create session" },
      { status: 500 },
    );
  }
}

/**
 * DELETE /api/terminals/ai-session
 * Kill an interactive session.
 * Body: { sessionId: string }
 */
export async function DELETE(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const sessionId = body.sessionId;
  if (typeof sessionId !== "string" || sessionId.length === 0) {
    return NextResponse.json({ error: "sessionId: required string" }, { status: 400 });
  }

  const remove = body.remove === true;

  if (remove) {
    const removed = removeInteractiveSession(sessionId);
    if (!removed) {
      return NextResponse.json({ error: "Session not found" }, { status: 404 });
    }
    return NextResponse.json({ removed: true, sessionId });
  }

  const killed = killInteractiveSession(sessionId);
  if (!killed) {
    return NextResponse.json({ error: "Session not found" }, { status: 404 });
  }

  return NextResponse.json({ killed: true, sessionId });
}
