// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { readFile } from "fs/promises";
import { join } from "path";
import { getAllTools, buildGraphData, PARALLEL_GROUPS, CWE_TRIGGERS, LLM_PROVIDERS } from "@/lib/tools-data";
import { getProviderSettings } from "@/lib/settings";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

export async function GET() {
  // Load graph export if it exists
  let graphExport = null;
  try {
    const raw = await readFile(join(PROJECT_ROOT, "reports", "tool-graph.json"), "utf-8");
    graphExport = JSON.parse(raw);
  } catch {
    // Fall back to computed graph
    graphExport = buildGraphData();
  }

  // Check scope file
  let scopeConfig = null;
  for (const candidate of ["configs/scope-example.yaml", "scope.yaml", "scope.json"]) {
    try {
      const raw = await readFile(join(PROJECT_ROOT, candidate), "utf-8");
      scopeConfig = { file: candidate, content: raw };
      break;
    } catch { /* next */ }
  }

  // Check smart config
  let smartConfig = null;
  try {
    const raw = await readFile(join(PROJECT_ROOT, "configs", "smart-config.yaml"), "utf-8");
    smartConfig = raw;
  } catch { /* skip */ }

  // Check LLM config
  let llmConfig = null;
  try {
    const raw = await readFile(join(PROJECT_ROOT, "configs", "llm-config.yaml"), "utf-8");
    llmConfig = raw;
  } catch { /* skip */ }

  // Check which env vars are present (saved settings + process.env, never expose values)
  const saved = await getProviderSettings();
  const envStatus: Record<string, boolean> = {};
  for (const p of LLM_PROVIDERS) {
    envStatus[p.envVar] = !!(saved[p.envVar] || process.env[p.envVar]);
  }

  return NextResponse.json({
    tools: getAllTools(),
    groups: PARALLEL_GROUPS,
    cweTriggers: CWE_TRIGGERS,
    providers: LLM_PROVIDERS.map((p) => ({
      ...p,
      available: envStatus[p.envVar] || false,
    })),
    graph: graphExport,
    scope: scopeConfig,
    smartConfig,
    llmConfig,
  });
}
