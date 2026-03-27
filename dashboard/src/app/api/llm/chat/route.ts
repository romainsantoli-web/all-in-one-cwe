// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { callLLM } from "@/lib/llm-bridge";
import { LLM_PROVIDERS } from "@/lib/tools-data";

export const dynamic = "force-dynamic";

const PROVIDER_NAMES = new Set(LLM_PROVIDERS.map((p) => p.name));
const MAX_MESSAGES = 50;
const MAX_CONTENT_LEN = 10000;

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

  // Validate messages
  if (!Array.isArray(body.messages) || body.messages.length === 0) {
    return NextResponse.json({ error: "messages: non-empty array required" }, { status: 400 });
  }
  if (body.messages.length > MAX_MESSAGES) {
    return NextResponse.json({ error: `messages: max ${MAX_MESSAGES} items` }, { status: 400 });
  }

  const validRoles = new Set(["user", "assistant"]);
  for (const msg of body.messages as Array<Record<string, unknown>>) {
    if (typeof msg.role !== "string" || !validRoles.has(msg.role)) {
      return NextResponse.json({ error: "messages[].role must be 'user' or 'assistant'" }, { status: 400 });
    }
    if (typeof msg.content !== "string" || msg.content.length === 0 || msg.content.length > MAX_CONTENT_LEN) {
      return NextResponse.json({ error: `messages[].content: 1-${MAX_CONTENT_LEN} chars required` }, { status: 400 });
    }
  }

  // Validate provider
  const provider = typeof body.provider === "string" && PROVIDER_NAMES.has(body.provider)
    ? body.provider
    : getDefaultProvider();
  if (!provider) {
    return NextResponse.json({ error: "No LLM provider available" }, { status: 503 });
  }

  // Build messages with system prompt
  const context = typeof body.context === "string" ? body.context.slice(0, 5000) : "";
  const systemPrompt = [
    "You are a senior security researcher and bug bounty expert.",
    "Help the user analyze vulnerabilities, plan testing strategies, and write remediation reports.",
    "Use markdown formatting. Be precise and actionable.",
    context ? `\n## Additional Context\n${context}` : "",
  ].join(" ");

  const messages = [
    { role: "system", content: systemPrompt },
    ...(body.messages as Array<{ role: string; content: string }>),
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
