// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { callLLMSync } from "@/lib/llm-bridge";
import { TOOL_META, LLM_PROVIDERS } from "@/lib/tools-data";
import { listJobs } from "@/lib/jobs";
import { readFile, stat } from "fs/promises";
import { spawn } from "child_process";
import { join } from "path";

export const dynamic = "force-dynamic";
export const maxDuration = 300; // 5m limit

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const PROVIDER_NAMES = new Set(LLM_PROVIDERS.map((p) => p.name));
const MAX_STEPS = 10;
const MAX_GOAL_LEN = 2000;
const MAX_TARGET_LEN = 2048;

function getDefaultProvider(): string | null {
  for (const p of LLM_PROVIDERS) {
    if (process.env[p.envVar]) return p.name;
  }
  return null;
}

function isValidTarget(target: string): boolean {
  try {
    const u = new URL(target);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/** Available tool definitions for the LLM system prompt. */
function buildToolDefs(): string {
  const pythonTools = Object.entries(TOOL_META)
    .filter(([, m]) => m.profile === "python-scanners" && m.requires === "target")
    .map(([name]) => `- ${name}`)
    .join("\n");
  return pythonTools;
}

/** Read recent terminal logs to inject as context for the LLM. */
async function getTerminalContext(): Promise<string> {
  try {
    const jobs = await listJobs();
    const recent = jobs.slice(0, 5);
    if (recent.length === 0) return "";

    const parts: string[] = [];
    for (const job of recent) {
      const safeId = job.id.replace(/[^a-zA-Z0-9_-]/g, "");
      const logPath = join(PROJECT_ROOT, "reports", ".jobs", `${safeId}.log`);
      let logTail = "";
      try {
        const st = await stat(logPath);
        if (st.size > 0) {
          const raw = await readFile(logPath, "utf-8");
          logTail = raw.length > 1500 ? raw.slice(-1500) : raw;
        }
      } catch { /* no log file */ }

      parts.push(
        `[Terminal ${safeId.slice(0, 8)}] tool=${job.tool || "scan"} status=${job.status} target=${job.target}` +
        (logTail ? `\n${logTail}` : " (no output)")
      );
    }
    return parts.join("\n---\n");
  } catch {
    return "";
  }
}

/** Run a single Python scanner tool synchronously. Returns findings JSON or error. */
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

const PYTHON_BIN = process.env.PYTHON_BIN || "python3";
const VALID_MODES = new Set(["paranoid", "normal", "yolo"]);
const VALID_PROFILES = new Set(["light", "medium", "full"]);
const MAX_AUTOPILOT_STEPS = 200;
const MAX_AUTOPILOT_TIME = 7200;

/** Handle autopilot mode — spawns react_engine.py and streams JSONL as SSE. */
function handleAutopilot(body: Record<string, unknown>): Response {
  const target = body.target;
  if (typeof target !== "string" || !isValidTarget(target)) {
    return NextResponse.json({ error: "target: valid http/https URL required" }, { status: 400 });
  }
  if (target.length > MAX_TARGET_LEN) {
    return NextResponse.json({ error: "target: too long" }, { status: 400 });
  }

  const checkpointMode = typeof body.checkpointMode === "string" && VALID_MODES.has(body.checkpointMode)
    ? body.checkpointMode : "normal";
  const profile = typeof body.profile === "string" && VALID_PROFILES.has(body.profile)
    ? body.profile : "medium";
  const maxSteps = typeof body.maxSteps === "number"
    ? Math.min(Math.max(Math.floor(body.maxSteps), 5), MAX_AUTOPILOT_STEPS) : 50;
  const maxTime = typeof body.maxTime === "number"
    ? Math.min(Math.max(Math.floor(body.maxTime), 60), MAX_AUTOPILOT_TIME) : 3600;

  const encoder = new TextEncoder();
  const scriptPath = join(PROJECT_ROOT, "scripts", "react_engine.py");

  const stream = new ReadableStream({
    start(controller) {
      const emit = (data: unknown) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
      };

      const child = spawn(PYTHON_BIN, [
        scriptPath,
        "--target", target,
        "--mode", checkpointMode,
        "--max-steps", String(maxSteps),
        "--max-time", String(maxTime),
        "--profile", profile,
      ], {
        cwd: PROJECT_ROOT,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
      });

      let buffer = "";
      child.stdout?.on("data", (chunk: Buffer) => {
        buffer += chunk.toString();
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const parsed = JSON.parse(line);
            emit(parsed);
          } catch {
            emit({ event: "log", message: line.slice(0, 1000) });
          }
        }
      });

      child.stderr?.on("data", (chunk: Buffer) => {
        const msg = chunk.toString().slice(0, 500);
        emit({ event: "log", level: "stderr", message: msg });
      });

      const timeout = setTimeout(() => {
        child.kill("SIGTERM");
      }, (maxTime + 30) * 1000);

      child.on("exit", (code) => {
        clearTimeout(timeout);
        if (buffer.trim()) {
          try {
            emit(JSON.parse(buffer));
          } catch { /* skip */ }
        }
        emit({ event: "exit", code });
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      });

      child.on("error", (err) => {
        clearTimeout(timeout);
        emit({ event: "error", message: err.message });
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}

export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  // Autopilot mode — delegate to react_engine.py
  if (body.mode === "autopilot") {
    return handleAutopilot(body);
  }

  const goal = body.goal;
  if (typeof goal !== "string" || goal.length === 0 || goal.length > MAX_GOAL_LEN) {
    return NextResponse.json({ error: `goal: 1-${MAX_GOAL_LEN} chars required` }, { status: 400 });
  }

  const target = body.target;
  if (typeof target !== "string" || !isValidTarget(target)) {
    return NextResponse.json({ error: "target: valid http/https URL required" }, { status: 400 });
  }
  if (target.length > MAX_TARGET_LEN) {
    return NextResponse.json({ error: "target: too long" }, { status: 400 });
  }

  const maxSteps = typeof body.maxSteps === "number"
    ? Math.min(Math.max(Math.floor(body.maxSteps), 1), MAX_STEPS)
    : 5;

  const provider = typeof body.provider === "string" && PROVIDER_NAMES.has(body.provider)
    ? body.provider
    : getDefaultProvider();
  if (!provider) {
    return NextResponse.json({ error: "No LLM provider available" }, { status: 503 });
  }

  const encoder = new TextEncoder();
  const toolDefs = buildToolDefs();
  const pythonTools = new Set(
    Object.entries(TOOL_META)
      .filter(([, m]) => m.profile === "python-scanners" && m.requires === "target")
      .map(([name]) => name)
  );

  const stream = new ReadableStream({
    async start(controller) {
      const emit = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ event, ...data as object })}\n\n`));
      };

      try {
        emit("start", { goal, target, provider, maxSteps });

        // Gather terminal context for the LLM
        const terminalCtx = await getTerminalContext();

        const conversationHistory: Array<{ role: string; content: string }> = [];

        const systemPrompt = [
          "You are an autonomous security testing agent. You analyze targets and decide which tools to run.",
          `\nTarget: ${target}`,
          `\nGoal: ${goal}`,
          "\n\nAvailable tools (Python scanners you can invoke):",
          toolDefs,
          "\n\nYou MUST respond in JSON with this structure:",
          '{"action":"run_tool","tool":"tool-name","reason":"why"} — to run a tool',
          '{"action":"read_terminal","jobId":"id"} — to read a terminal\'s latest output',
          '{"action":"done","summary":"final analysis"} — when you are done',
          "\n\nRules:",
          "- Pick the most relevant tool for the current step.",
          "- You can read terminal output from running or recent scans with read_terminal.",
          "- After seeing a tool's results, decide if another tool is needed or if you're done.",
          "- Always end with 'done' action and a comprehensive summary.",
          `- You have a maximum of ${maxSteps} steps.`,
          terminalCtx ? `\n\n## Recent Terminal Output\n${terminalCtx}` : "",
        ].filter(Boolean).join("\n");

        for (let step = 0; step < maxSteps; step++) {
          emit("step", { step: step + 1, maxSteps });

          const messages = [
            { role: "system", content: systemPrompt },
            ...conversationHistory,
          ];

          if (step === 0) {
            messages.push({ role: "user", content: `Analyze ${target}. Goal: ${goal}. What tool should we start with?` });
          }

          // Ask LLM for next action
          emit("thinking", { step: step + 1 });
          let llmResponse: string;
          try {
            llmResponse = await callLLMSync({ provider, messages });
          } catch (err) {
            emit("error", { message: `LLM call failed: ${(err as Error).message}` });
            break;
          }

          conversationHistory.push(
            { role: "user", content: messages[messages.length - 1].content },
            { role: "assistant", content: llmResponse }
          );

          // Parse LLM decision
          let decision: { action: string; tool?: string; reason?: string; summary?: string };
          try {
            // Extract JSON from response (LLM might wrap it in markdown)
            const jsonMatch = llmResponse.match(/\{[\s\S]*?\}/);
            if (!jsonMatch) throw new Error("No JSON found");
            decision = JSON.parse(jsonMatch[0]);
          } catch {
            emit("llm_response", { raw: llmResponse.slice(0, 2000), step: step + 1 });
            emit("done", { summary: llmResponse.slice(0, 4000) });
            break;
          }

          if (decision.action === "done") {
            emit("done", { summary: decision.summary || "Agent completed." });
            break;
          }

          if (decision.action === "read_terminal" && typeof (decision as Record<string, unknown>).jobId === "string") {
            const reqJobId = ((decision as Record<string, unknown>).jobId as string).replace(/[^a-zA-Z0-9_-]/g, "");
            emit("terminal_read", { jobId: reqJobId });
            const logPath = join(PROJECT_ROOT, "reports", ".jobs", `${reqJobId}.log`);
            let logContent = "No log available.";
            try {
              const raw = await readFile(logPath, "utf-8");
              logContent = raw.length > 4000 ? raw.slice(-4000) : raw;
            } catch { /* no log */ }
            conversationHistory.push({
              role: "user",
              content: `Terminal ${reqJobId} output:\n${logContent}\n\nAnalyze this output. Run another tool or finish with "done".`,
            });
            continue;
          }

          if (decision.action === "run_tool" && decision.tool) {
            const toolName = decision.tool;
            if (!pythonTools.has(toolName)) {
              emit("tool_skip", { tool: toolName, reason: "Unknown tool" });
              conversationHistory.push({
                role: "user",
                content: `Tool "${toolName}" is not available. Pick another tool or finish with "done".`,
              });
              continue;
            }

            emit("tool_start", { tool: toolName, reason: decision.reason, step: step + 1 });

            const result = await runToolSync(toolName, target);
            emit("tool_result", { tool: toolName, output: result.slice(0, 4000), step: step + 1 });

            conversationHistory.push({
              role: "user",
              content: `Tool "${toolName}" output:\n${result.slice(0, 6000)}\n\nAnalyze these results. Run another tool or finish with "done".`,
            });
          } else {
            emit("llm_response", { raw: llmResponse.slice(0, 2000), step: step + 1 });
            break;
          }
        }

        // If loop exhausted, force a summary
        if (conversationHistory.length > 0) {
          emit("complete", { steps: Math.ceil(conversationHistory.length / 2) });
        }
      } catch (err) {
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
