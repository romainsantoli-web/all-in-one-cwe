// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { callLLMSync } from "@/lib/llm-bridge";
import { TOOL_META, CWE_TRIGGERS, LLM_PROVIDERS } from "@/lib/tools-data";
import { spawn } from "child_process";
import { join } from "path";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const MAX_STEPS = 5;

function getDefaultProvider(): string | null {
  for (const p of LLM_PROVIDERS) {
    if (process.env[p.envVar]) return p.name;
  }
  return null;
}

const PROVIDER_NAMES = new Set(LLM_PROVIDERS.map((p) => p.name));

const PYTHON_TOOLS = new Set(
  Object.entries(TOOL_META)
    .filter(([, m]) => m.profile === "python-scanners" && m.requires === "target")
    .map(([name]) => name),
);

function runToolSync(tool: string, target: string): Promise<string> {
  return new Promise((resolve) => {
    const scriptName = tool.replace(/-/g, "_") + ".py";
    const scriptPath = join(PROJECT_ROOT, "tools", "python-scanners", scriptName);
    const child = spawn("python3", [scriptPath, "--target", target], {
      cwd: PROJECT_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        TARGET: target,
        OUTPUT_DIR: join(PROJECT_ROOT, "reports", tool),
        SCAN_DATE: new Date().toISOString().slice(0, 10),
      },
    });

    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d: Buffer) => { stdout += d.toString(); });
    child.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });

    const timeout = setTimeout(() => { child.kill("SIGTERM"); }, 120_000);

    child.on("exit", (code) => {
      clearTimeout(timeout);
      if (code === 0) {
        resolve(stdout.slice(0, 8000) || "Tool completed with no output.");
      } else {
        resolve(`Tool failed (code ${code}): ${stderr.slice(0, 1000)}`);
      }
    });
    child.on("error", (err) => {
      clearTimeout(timeout);
      resolve(`Tool error: ${err.message}`);
    });
  });
}

/** Given a finding's CWE, suggest tools from CWE_TRIGGERS. */
function cweSuggestedTools(cwe: string | undefined): string[] {
  if (!cwe) return [];
  const normalized = cwe.startsWith("CWE-") ? cwe : `CWE-${cwe}`;
  return CWE_TRIGGERS[normalized] ?? [];
}

export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  // Validate finding
  const finding = body.finding;
  if (!finding || typeof finding !== "object" || Array.isArray(finding)) {
    return NextResponse.json({ error: "finding: object required" }, { status: 400 });
  }
  const f = finding as Record<string, unknown>;
  const title = typeof f.title === "string" ? f.title.slice(0, 500) : "";
  const severity = typeof f.severity === "string" ? f.severity.slice(0, 20) : "unknown";
  const cwe = typeof f.cwe === "string" ? f.cwe.slice(0, 20) : (typeof f.cwe_id === "string" ? f.cwe_id.slice(0, 20) : undefined);
  const evidence = typeof f.evidence === "string" ? f.evidence.slice(0, 2000) : "";
  const description = typeof f.description === "string" ? f.description.slice(0, 2000) : "";
  const findingUrl = typeof f.url === "string" ? f.url.slice(0, 2048) : (typeof f.endpoint === "string" ? f.endpoint.slice(0, 2048) : "");
  const toolName = typeof f.tool === "string" ? f.tool.slice(0, 100) : "";

  // Validate target
  const target = typeof body.target === "string" ? body.target.slice(0, 2048) : "";
  if (!target) {
    return NextResponse.json({ error: "target: required" }, { status: 400 });
  }
  try {
    const u = new URL(target);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      return NextResponse.json({ error: "target: must be http/https" }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: "target: invalid URL" }, { status: 400 });
  }

  // Phase: "suggest" (LLM suggests tools) or "execute" (run confirmed tools)
  const phase = typeof body.phase === "string" ? body.phase : "suggest";
  const confirmedTools = Array.isArray(body.confirmedTools)
    ? (body.confirmedTools as string[]).filter((t): t is string => typeof t === "string" && PYTHON_TOOLS.has(t)).slice(0, MAX_STEPS)
    : [];

  const provider = typeof body.provider === "string" && PROVIDER_NAMES.has(body.provider)
    ? body.provider
    : getDefaultProvider();
  if (!provider) {
    return NextResponse.json({ error: "No LLM provider available" }, { status: 503 });
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const emit = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ event, ...data as object })}\n\n`));
      };

      try {
        if (phase === "suggest") {
          // --- PHASE 1: Suggest tools ---
          emit("phase", { phase: "suggest" });

          // CWE-based suggestions
          const cweSuggestions = cweSuggestedTools(cwe);
          emit("cwe_suggestions", { tools: cweSuggestions, cwe });

          // LLM-based suggestion
          const toolList = Array.from(PYTHON_TOOLS).join(", ");
          const suggestPrompt = [
            "You are a security testing expert. Given a vulnerability finding, suggest which tools to run for deeper investigation.",
            `\nFinding: ${title}`,
            `Severity: ${severity}`,
            cwe ? `CWE: ${cwe}` : "",
            description ? `Description: ${description}` : "",
            evidence ? `Evidence: ${evidence.slice(0, 500)}` : "",
            findingUrl ? `URL: ${findingUrl}` : "",
            toolName ? `Found by: ${toolName}` : "",
            `\nAvailable tools: ${toolList}`,
            "\nRespond in JSON: {\"tools\": [\"tool-name\", ...], \"reasoning\": \"why these tools\"}",
            "Pick 1-3 most relevant tools. Only pick tools from the available list.",
          ].filter(Boolean).join("\n");

          let llmResponse: string;
          try {
            llmResponse = await callLLMSync({ provider, messages: [{ role: "user", content: suggestPrompt }] });
          } catch (err: unknown) {
            emit("error", { message: `LLM failed: ${(err as Error).message}` });
            controller.enqueue(encoder.encode("data: [DONE]\n\n"));
            controller.close();
            return;
          }

          // Parse LLM suggestion
          let suggested: { tools: string[]; reasoning: string } = { tools: [], reasoning: "" };
          try {
            const jsonMatch = llmResponse.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
              const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;
              const rawTools = Array.isArray(parsed.tools) ? parsed.tools : [];
              suggested = {
                tools: rawTools.filter((t): t is string => typeof t === "string" && PYTHON_TOOLS.has(t)),
                reasoning: typeof parsed.reasoning === "string" ? parsed.reasoning : "",
              };
            }
          } catch {
            // Fallback to CWE suggestions
            suggested = { tools: cweSuggestions, reasoning: "CWE-based suggestion (LLM parse failed)" };
          }

          // Merge CWE + LLM suggestions, deduplicate
          const allSuggested = [...new Set([...suggested.tools, ...cweSuggestions])].slice(0, MAX_STEPS);
          emit("suggestions", {
            tools: allSuggested,
            reasoning: suggested.reasoning,
            llmRaw: llmResponse.slice(0, 1000),
          });
          emit("await_confirmation", { tools: allSuggested });

        } else if (phase === "execute" && confirmedTools.length > 0) {
          // --- PHASE 2: Execute confirmed tools ---
          emit("phase", { phase: "execute" });
          emit("execution_start", { tools: confirmedTools, target });

          const allResults: Array<{ tool: string; output: string }> = [];

          for (const tool of confirmedTools) {
            emit("tool_start", { tool });
            const result = await runToolSync(tool, target);
            allResults.push({ tool, output: result.slice(0, 4000) });
            emit("tool_result", { tool, output: result.slice(0, 4000) });
          }

          // --- PHASE 3: LLM summarizes findings ---
          emit("phase", { phase: "summarize" });

          const summaryPrompt = [
            "You are a security analyst. Summarize the tool results in context of the original finding.",
            `\nOriginal finding: ${title} (${severity})`,
            cwe ? `CWE: ${cwe}` : "",
            description ? `Description: ${description}` : "",
            findingUrl ? `URL: ${findingUrl}` : "",
            "\nTool results:",
            ...allResults.map((r) => `\n--- ${r.tool} ---\n${r.output.slice(0, 3000)}`),
            "\nProvide:",
            "1. Whether the original finding is confirmed, escalated, or a false positive",
            "2. Any new vulnerabilities discovered",
            "3. Specific remediation recommendations",
            "4. Risk score assessment (critical/high/medium/low)",
          ].filter(Boolean).join("\n");

          let summary: string;
          try {
            summary = await callLLMSync({ provider, messages: [{ role: "user", content: summaryPrompt }] });
          } catch (err: unknown) {
            summary = `LLM summary failed: ${(err as Error).message}. Raw results available above.`;
          }

          emit("summary", { text: summary.slice(0, 6000) });
        } else {
          emit("error", { message: "Invalid phase or no confirmed tools" });
        }
      } catch (err: unknown) {
        emit("error", { message: (err as Error).message });
      } finally {
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Provider": provider,
    },
  });
}
