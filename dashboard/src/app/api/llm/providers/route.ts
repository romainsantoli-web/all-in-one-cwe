// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { LLM_PROVIDERS, PROVIDER_MODELS } from "@/lib/tools-data";
import { getProviderSettings, saveProviderSettings } from "@/lib/settings";

export const dynamic = "force-dynamic";

export async function GET() {
  const saved = await getProviderSettings();
  const providers = LLM_PROVIDERS.map((p) => ({
    name: p.name,
    model: p.model,
    envVar: p.envVar,
    available: !!(saved[p.envVar] || process.env[p.envVar]),
    source: saved[p.envVar] ? "settings" : process.env[p.envVar] ? "env" : "none",
    models: PROVIDER_MODELS[p.name] || [p.model],
  }));
  return NextResponse.json({ providers });
}

/** DELETE — Disconnect a provider (remove its saved key) */
export async function DELETE(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const envVar = body.envVar;
  if (typeof envVar !== "string" || !/^[A-Z][A-Z0-9_]{1,63}$/.test(envVar)) {
    return NextResponse.json({ error: "Invalid envVar" }, { status: 400 });
  }

  const saved = await getProviderSettings();
  if (envVar in saved) {
    delete saved[envVar];
    // Also remove related tokens if disconnecting copilot
    if (envVar === "COPILOT_OAUTH_TOKEN") {
      delete saved["COPILOT_JWT"];
    }
    await saveProviderSettings(saved);
  }

  return NextResponse.json({ ok: true });
}
