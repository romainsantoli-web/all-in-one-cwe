// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import {
  getBridgeStatus,
  testBridgeConnection,
  clearTokenCache,
} from "@/lib/copilot-bridge";

export const dynamic = "force-dynamic";

/**
 * GET /api/copilot/bridge
 * Returns bridge configuration status.
 */
export async function GET() {
  const status = await getBridgeStatus();
  return NextResponse.json(status);
}

/**
 * POST /api/copilot/bridge
 * Test the bridge connection or clear token cache.
 * Body: { action: "test" | "clear-cache" }
 */
export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const action = body.action;

  if (action === "test") {
    const result = await testBridgeConnection();
    return NextResponse.json(result);
  }

  if (action === "clear-cache") {
    clearTokenCache();
    return NextResponse.json({ cleared: true });
  }

  return NextResponse.json(
    { error: "action must be 'test' or 'clear-cache'" },
    { status: 400 },
  );
}
