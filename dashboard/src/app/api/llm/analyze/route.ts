// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { callLLM } from "@/lib/llm-bridge";
import { LLM_PROVIDERS } from "@/lib/tools-data";

export const dynamic = "force-dynamic";

const PROVIDER_NAMES = new Set(LLM_PROVIDERS.map((p) => p.name));

function getDefaultProvider(): string | null {
  for (const p of LLM_PROVIDERS) {
    if (process.env[p.envVar]) return p.name;
  }
  return null;
}

export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  // Validate findings array
  if (!Array.isArray(body.findings) || body.findings.length === 0) {
    return NextResponse.json({ error: "findings: non-empty array required" }, { status: 400 });
  }
  if (body.findings.length > 50) {
    return NextResponse.json({ error: "findings: max 50 items" }, { status: 400 });
  }

  // Validate provider
  const provider = typeof body.provider === "string" && PROVIDER_NAMES.has(body.provider)
    ? body.provider
    : getDefaultProvider();
  if (!provider) {
    return NextResponse.json({ error: "No LLM provider available. Configure an API key." }, { status: 503 });
  }

  // Build the analysis prompt
  const findingsText = (body.findings as Array<Record<string, unknown>>)
    .map((f, i) => {
      const title = String(f.title || "Unknown");
      const sev = String(f.severity || "info");
      const cwe = f.cwe ? ` (${f.cwe})` : "";
      const desc = f.description ? `\n   ${String(f.description).slice(0, 500)}` : "";
      return `${i + 1}. [${sev.toUpperCase()}] ${title}${cwe}${desc}`;
    })
    .join("\n");

  const userPrompt = typeof body.prompt === "string" && body.prompt.length > 0
    ? body.prompt
    : "Analyze these security findings. For each, explain the risk, exploitability, and provide specific remediation steps. Prioritize by severity.";

  const messages = [
    {
      role: "system",
      content: "You are a senior security researcher. Analyze vulnerability findings concisely. Use markdown formatting. Be specific about exploitation scenarios and remediation steps.",
    },
    {
      role: "user",
      content: `${userPrompt}\n\n## Findings\n${findingsText}`,
    },
  ];

  const stream = callLLM({ provider, messages });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Provider": provider,
    },
  });
}
