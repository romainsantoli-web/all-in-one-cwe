// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { callLLM } from "@/lib/llm-bridge";
import { LLM_PROVIDERS } from "@/lib/tools-data";
import { getProviderSettings } from "@/lib/settings";
import { listJobs } from "@/lib/jobs";
import { readFile, stat } from "fs/promises";
import { join } from "path";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const PROVIDER_NAMES = new Set(LLM_PROVIDERS.map((p) => p.name));
const MAX_MESSAGES = 50;
const MAX_CONTENT_LEN = 10000;

async function getDefaultProvider(): Promise<string | null> {
  const saved = await getProviderSettings();
  for (const p of LLM_PROVIDERS) {
    if (saved[p.envVar] || process.env[p.envVar]) return p.name;
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
    : await getDefaultProvider();
  if (!provider) {
    return NextResponse.json({ error: "No LLM provider available" }, { status: 503 });
  }

  // Validate model (optional)
  const model = typeof body.model === "string" && body.model.length <= 100
    ? body.model
    : undefined;

  // Agentic mode flag — enables tool calling loop in Python
  const agentic = body.agentic === true;

  // Conversation ID — used to scope workspace files per conversation
  const conversationId = typeof body.conversationId === "string"
    && /^[a-zA-Z0-9_-]{1,64}$/.test(body.conversationId)
    ? body.conversationId
    : undefined;

  // Build messages with system prompt
  const context = typeof body.context === "string" ? body.context.slice(0, 5000) : "";
  const includeTerminals = body.includeTerminals !== false; // default: true

  // Gather running terminal context
  let terminalCtx = "";
  if (includeTerminals) {
    try {
      const jobs = await listJobs();
      const running = jobs.filter((j) => j.status === "running").slice(0, 3);
      if (running.length > 0) {
        const parts: string[] = [];
        for (const job of running) {
          const safeId = job.id.replace(/[^a-zA-Z0-9_-]/g, "");
          const logPath = join(PROJECT_ROOT, "reports", ".jobs", `${safeId}.log`);
          let logTail = "";
          try {
            const st = await stat(logPath);
            if (st.size > 0) {
              const raw = await readFile(logPath, "utf-8");
              logTail = raw.length > 1000 ? raw.slice(-1000) : raw;
            }
          } catch { /* noop */ }
          parts.push(`[Terminal ${safeId.slice(0, 8)}] tool=${job.tool || "scan"} status=${job.status}\n${logTail || "(no output yet)"}`);
        }
        terminalCtx = parts.join("\n---\n");
      }
    } catch { /* noop */ }
  }

  const agenticInstructions = agentic
    ? [
        "\n\n## AGENT MODE — Structured Methodology",
        "",
        "You are an autonomous security agent with tool access. Follow this MANDATORY workflow:",
        "",
        "### Phase 1: PLANNING (Always start here)",
        "1. Call `update_plan` FIRST to create a numbered task list before doing anything else.",
        "2. Break the request into concrete, atomic tasks (e.g., 'Recon: discover subdomains', 'Scan: test for XSS on /api/*').",
        "3. Order tasks logically: reconnaissance → scanning → analysis → exploitation/PoC → reporting.",
        "",
        "### Phase 2: EXECUTION (One task at a time)",
        "For each task in your plan:",
        "1. Call `update_plan` to mark the current task as `in-progress`.",
        "2. Execute the task using the appropriate tool(s).",
        "3. Analyze the results — adapt your strategy if needed (add new tasks to the plan).",
        "4. Call `update_plan` to mark the task as `done` (include a brief result) or `failed`.",
        "5. Move to the next task.",
        "",
        "### Phase 3: SYNTHESIS & REPORT",
        "After all tasks are done:",
        "1. Call `update_plan` one last time with a summary of all findings.",
        "2. Present a structured response: executive summary, findings by severity, PoCs, recommendations.",
        "3. If vulnerabilities were found, call `generate_report` for a professional report.",
        "",
        "### Available Tools (17)",
        "- **update_plan**: Create/update your task plan (ALWAYS call first, update after each task).",
        "- **run_scan**: Launch scanners — supports Python scanners AND external tools (nuclei, nmap, nikto, sqlmap, ffuf, testssl, etc.).",
        "- **shell_exec**: Execute any shell command (curl, python, custom scripts, PoC exploits, etc.).",
        "- **read_file**: Read scan reports, configs, source code, previous results.",
        "- **write_file**: Write PoC exploits, scripts, custom configs, reports.",
        "- **list_findings**: Aggregate all scan results with severity filtering.",
        "- **list_tools**: Discover all available scanning tools before starting.",
        "- **generate_report**: Create professional reports (markdown, yeswehack, hackerone, bugcrowd, etc.). **AUTO-SAVES** to `reports/generated-reports/` and to the conversation workspace. Returns the saved file paths.",
        "- **list_dir**: Browse project directories — explore structure, find configs and reports.",
        "- **grep_search**: Search for text or regex patterns across files (like ripgrep). Find functions, config values, secrets.",
        "- **file_search**: Find files by name/glob pattern in the project tree.",
        "- **fetch_webpage**: Fetch web page content (HTTP) — read docs, check target responses, verify fixes.",
        "- **cdp_exec**: Execute raw Chrome DevTools Protocol commands on a live browser — evaluate JS, extract cookies/tokens, intercept requests, capture screenshots, DOM analysis. Use Runtime.evaluate, Network.getAllCookies, Page.navigate, etc.",
        "- **browse_page**: Navigate to a URL in the CDP browser and get the fully rendered page (with JS executed). Unlike fetch_webpage, this renders SPAs and dynamic content. Extract specific elements with CSS selectors.",
        "- **workspace_write**: Write files to the current conversation's dedicated workspace folder. Each conversation has its own isolated directory for PoC scripts, notes, and analysis.",
        "- **workspace_read**: Read files from the conversation workspace.",
        "- **workspace_list**: List all files in the conversation workspace.",
        "",
        "### Rules",
        "- NEVER ask the user what to do. Be autonomous — decide and execute.",
        "- NEVER call the same tool with the same arguments twice. If a tool fails, try a different approach.",
        "- Wait for each tool result before deciding the next action.",
        "- If a scan returns no results, move on — don't retry the same scan.",
        "- Adapt your plan based on findings: if you discover a new attack surface, add tasks.",
        "- Always validate findings with a PoC (shell_exec + curl/python) before reporting.",
        "",
        "### Report Saving (MANDATORY)",
        "- When you call `generate_report`, the report is automatically saved to disk AND to your conversation workspace.",
        "- The report file path is returned in the tool result — always show the path to the user.",
        "- After generating a report, call `workspace_list` to confirm the file is there, and use `workspace_read` to display it inline if the user asks.",
        `- Your conversation_id is: \`${conversationId || "default"}\`. All workspace_write/workspace_read/workspace_list calls use this automatically.`,
      ].join("\n")
    : "";

  const systemPrompt = [
    "You are a senior security researcher and bug bounty expert.",
    "Help the user analyze vulnerabilities, plan testing strategies, and write remediation reports.",
    "You have access to live terminal output from running scans. Use this context to provide informed analysis.",
    "Use markdown formatting. Be precise and actionable.",
    context ? `\n## Additional Context\n${context}` : "",
    terminalCtx ? `\n## Live Terminal Output\n${terminalCtx}` : "",
    agenticInstructions,
  ].filter(Boolean).join(" ");

  const messages = [
    { role: "system", content: systemPrompt },
    ...(body.messages as Array<{ role: string; content: string }>),
  ];

  const stream = callLLM({ provider, messages, model, agentic, conversationId });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Provider": provider,
      "X-Agentic": agentic ? "true" : "false",
    },
  });
}
