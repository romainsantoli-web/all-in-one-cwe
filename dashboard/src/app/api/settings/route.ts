// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { getProviderSettings, saveProviderSettings, maskSecret } from "@/lib/settings";
import { LLM_PROVIDERS } from "@/lib/tools-data";

export const dynamic = "force-dynamic";

// Known env var names from LLM_PROVIDERS
const KNOWN_ENV_VARS = new Set(LLM_PROVIDERS.map((p) => p.envVar));

/**
 * GET /api/settings
 * Returns provider configuration with masked keys.
 */
export async function GET() {
  const saved = await getProviderSettings();

  const providers = LLM_PROVIDERS.map((p) => {
    const savedValue = saved[p.envVar];
    const envValue = process.env[p.envVar];
    const hasKey = !!(savedValue || envValue);
    const source = savedValue ? "settings" : envValue ? "env" : "none";

    return {
      name: p.name,
      model: p.model,
      envVar: p.envVar,
      configured: hasKey,
      source,
      maskedKey: hasKey ? maskSecret(savedValue || envValue || "") : null,
    };
  });

  return NextResponse.json({ providers });
}

/**
 * PUT /api/settings
 * Save/update provider API keys. Only accepts known env var names.
 * Body: { keys: { "ANTHROPIC_API_KEY": "sk-ant-...", ... } }
 */
export async function PUT(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const keys = body.keys;
  if (typeof keys !== "object" || keys === null || Array.isArray(keys)) {
    return NextResponse.json({ error: "keys: must be an object { envVar: value }" }, { status: 400 });
  }

  const existing = await getProviderSettings();
  const updates: Record<string, string> = { ...existing };
  const errors: string[] = [];

  for (const [envVar, value] of Object.entries(keys as Record<string, unknown>)) {
    if (!KNOWN_ENV_VARS.has(envVar)) {
      errors.push(`Unknown provider env var: ${envVar}`);
      continue;
    }
    if (typeof value === "string" && value.length > 0) {
      if (value.length > 512) {
        errors.push(`${envVar}: key too long (max 512)`);
        continue;
      }
      updates[envVar] = value;
    } else if (value === null || value === "") {
      // Allow deletion
      delete updates[envVar];
    } else {
      errors.push(`${envVar}: must be a string or null`);
    }
  }

  if (errors.length > 0) {
    return NextResponse.json({ error: errors.join("; ") }, { status: 400 });
  }

  try {
    await saveProviderSettings(updates);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Failed to save" },
      { status: 500 },
    );
  }

  return NextResponse.json({ saved: Object.keys(updates).length });
}
