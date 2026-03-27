// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { LLM_PROVIDERS } from "@/lib/tools-data";
import { getProviderSettings } from "@/lib/settings";

export const dynamic = "force-dynamic";

export async function GET() {
  const saved = await getProviderSettings();
  const providers = LLM_PROVIDERS.map((p) => ({
    name: p.name,
    model: p.model,
    envVar: p.envVar,
    available: !!(saved[p.envVar] || process.env[p.envVar]),
  }));
  return NextResponse.json(providers);
}
