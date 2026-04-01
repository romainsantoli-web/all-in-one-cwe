// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextRequest } from "next/server";
import { spawn, ChildProcess } from "child_process";
import { writeFileSync, unlinkSync, existsSync } from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";

export const dynamic = "force-dynamic";
export const maxDuration = 300; // 5 min max

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------

// Self-contained: recovery engine lives inside the project tree
// process.cwd() = dashboard/, go up one level to project root
const V4_ROOT = path.resolve(process.cwd(), "..", "tools", "recovery-engine");
const CLI_PATH = path.join(V4_ROOT, "packages", "cli", "dist", "index.js");

const ALLOWED_STRATEGIES = new Set(["profile", "dictionary", "bruteforce", "all"]);
const ALLOWED_CHARSETS = new Set(["lowercase", "alpha", "alphanumeric", "full"]);
const MAX_PROFILE_TOKENS = 500;
const MAX_WORDLIST_LINES = 10_000_000;
const MAX_LENGTH_LIMIT = 64;

// Allowed profile keys (strict allowlist)
const PROFILE_KEYS = new Set([
  "names", "dates", "words", "partials", "oldPasswords", "hints",
]);

// --------------------------------------------------------------------------
// Validation helpers
// --------------------------------------------------------------------------

function hasTraversal(val: string): boolean {
  return val.includes("..") || val.includes("\0");
}

function sanitizePath(raw: string): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed || hasTraversal(trimmed)) return null;
  const resolved = path.resolve(trimmed);
  // Block /etc, /var, /usr, /System, etc. — allow only user home paths
  const home = os.homedir();
  if (!resolved.startsWith(home) && !resolved.startsWith("/tmp")) return null;
  return resolved;
}

function sanitizeProfile(raw: unknown): Record<string, string[]> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const result: Record<string, string[]> = {};
  let totalTokens = 0;

  for (const [key, val] of Object.entries(raw as Record<string, unknown>)) {
    if (!PROFILE_KEYS.has(key)) continue;
    if (!Array.isArray(val)) continue;

    const cleaned: string[] = [];
    for (const item of val) {
      if (typeof item !== "string") continue;
      const trimmed = item.trim();
      if (!trimmed || trimmed.length > 200) continue;
      if (hasTraversal(trimmed)) continue;
      cleaned.push(trimmed);
      totalTokens++;
      if (totalTokens >= MAX_PROFILE_TOKENS) break;
    }
    if (cleaned.length > 0) result[key] = cleaned;
    if (totalTokens >= MAX_PROFILE_TOKENS) break;
  }
  return result;
}

// --------------------------------------------------------------------------
// SSE POST handler — streams crack progress
// --------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  // --- Parse & validate body ---
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Required: vault_path OR file_path
  const vaultPath = sanitizePath(body.vault_path as string ?? "");
  const filePath = sanitizePath(body.file_path as string ?? "");

  if (!vaultPath && !filePath) {
    return new Response(
      JSON.stringify({ error: "vault_path or file_path required" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const targetPath = vaultPath || filePath;
  if (!targetPath || !existsSync(targetPath)) {
    return new Response(
      JSON.stringify({ error: "Target file not found" }),
      { status: 404, headers: { "Content-Type": "application/json" } }
    );
  }

  // Strategy
  const strategy = typeof body.strategy === "string" && ALLOWED_STRATEGIES.has(body.strategy)
    ? body.strategy
    : "all";

  // Charset
  const charset = typeof body.charset === "string" && ALLOWED_CHARSETS.has(body.charset)
    ? body.charset
    : "full";

  // Lengths
  const minLength = Math.max(1, Math.min(MAX_LENGTH_LIMIT, Number(body.min_length) || 8));
  const maxLength = Math.max(minLength, Math.min(MAX_LENGTH_LIMIT, Number(body.max_length) || 16));

  // Threads & concurrent
  const threads = Math.max(0, Math.min(os.cpus().length, Number(body.threads) || 0));
  const concurrent = Math.max(1, Math.min(32, Number(body.concurrent) || 8));

  // Profile — write to tmp file
  const profile = sanitizeProfile(body.profile);
  let profileTmpPath: string | null = null;
  if (Object.keys(profile).length > 0) {
    const id = crypto.randomBytes(8).toString("hex");
    profileTmpPath = path.join(os.tmpdir(), `recover-profile-${id}.json`);
    writeFileSync(profileTmpPath, JSON.stringify(profile), "utf-8");
  }

  // Wordlist path (optional)
  const wordlistPath = sanitizePath(body.wordlist_path as string ?? "");

  // Format (for crack-file)
  const format = typeof body.format === "string" && /^[a-z0-9_-]{1,50}$/.test(body.format)
    ? body.format
    : undefined;

  // Salt (for crack-file, e.g. email for LastPass)
  const salt = typeof body.salt === "string" && body.salt.length <= 200 && !hasTraversal(body.salt)
    ? body.salt
    : undefined;

  // --- Verify CLI exists ---
  if (!existsSync(CLI_PATH)) {
    return new Response(
      JSON.stringify({ error: "Recovery engine not found (v4 CLI missing)" }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  // --- Build CLI args ---
  const useUniversal = !!filePath && !vaultPath; // crack-file for non-vault files
  const args: string[] = [CLI_PATH];

  if (useUniversal) {
    args.push("crack-file", "-f", targetPath!);
    if (format) args.push("--format", format);
    if (salt) args.push("--salt", salt);
  } else {
    args.push("crack", "-v", targetPath!);
    args.push("-s", strategy);
    args.push("--charset", charset);
  }

  args.push("--min-length", String(minLength));
  args.push("--max-length", String(maxLength));

  if (threads > 0) args.push("-t", String(threads));
  args.push("-c", String(concurrent));

  if (profileTmpPath) args.push("-P", profileTmpPath);
  if (wordlistPath && existsSync(wordlistPath)) args.push("-w", wordlistPath);

  // --- Spawn & stream SSE ---
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    start(controller) {
      const cpuCount = os.cpus().length;
      const envVars = {
        ...process.env,
        UV_THREADPOOL_SIZE: String(Math.max(128, cpuCount * 16)),
        FORCE_COLOR: "0",  // disable chalk ANSI for parsing
        NO_COLOR: "1",
      };

      const child: ChildProcess = spawn("node", args, {
        cwd: V4_ROOT,
        env: envVars,
        stdio: ["ignore", "pipe", "pipe"],
      });

      function sendEvent(event: string, data: unknown) {
        const json = JSON.stringify(data);
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${json}\n\n`));
      }

      sendEvent("start", {
        command: useUniversal ? "crack-file" : "crack",
        target: path.basename(targetPath!),
        strategy,
        threads: threads || cpuCount,
        concurrent,
      });

      // --- Parse stdout line by line ---
      let stdoutBuffer = "";
      child.stdout?.on("data", (chunk: Buffer) => {
        stdoutBuffer += chunk.toString();
        const lines = stdoutBuffer.split("\n");
        stdoutBuffer = lines.pop() ?? "";

        for (const line of lines) {
          parseLine(line, sendEvent);
        }
      });

      // --- Parse stderr too (ora spinners write there) ---
      let stderrBuffer = "";
      child.stderr?.on("data", (chunk: Buffer) => {
        stderrBuffer += chunk.toString();
        const lines = stderrBuffer.split("\n");
        stderrBuffer = lines.pop() ?? "";

        for (const line of lines) {
          parseLine(line, sendEvent);
        }
      });

      child.on("close", (code: number | null) => {
        // Flush remaining buffers
        if (stdoutBuffer.trim()) parseLine(stdoutBuffer, sendEvent);
        if (stderrBuffer.trim()) parseLine(stderrBuffer, sendEvent);

        sendEvent("done", { exitCode: code });
        controller.close();

        // Cleanup tmp profile
        if (profileTmpPath) {
          try { unlinkSync(profileTmpPath); } catch { /* ignore */ }
        }
      });

      child.on("error", (err: Error) => {
        sendEvent("error", { message: err.message });
        controller.close();
        if (profileTmpPath) {
          try { unlinkSync(profileTmpPath); } catch { /* ignore */ }
        }
      });

      // Abort on client disconnect
      req.signal.addEventListener("abort", () => {
        child.kill("SIGTERM");
        if (profileTmpPath) {
          try { unlinkSync(profileTmpPath); } catch { /* ignore */ }
        }
      });
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}

// --------------------------------------------------------------------------
// Line parser — extracts structured data from CLI output
// --------------------------------------------------------------------------

// Strip ANSI codes that might leak through
const ANSI_RE = /\x1b\[[0-9;]*[a-zA-Z]/g;

function parseLine(
  raw: string,
  sendEvent: (event: string, data: unknown) => void,
) {
  const line = raw.replace(ANSI_RE, "").trim();
  if (!line) return;

  // PASSWORD FOUND
  if (line.includes("PASSWORD FOUND") || line.includes("🔑 Password:")) {
    const match = line.match(/Password:\s*(.+)/);
    if (match) {
      sendEvent("found", { password: match[1].trim() });
      return;
    }
  }

  // Seed phrase
  if (line.includes("Seed Phrase:")) {
    const match = line.match(/Seed Phrase:\s*(.+)/);
    if (match) {
      sendEvent("mnemonic", { mnemonic: match[1].trim() });
      return;
    }
  }

  // Progress line: "12,345 attempts | 118.2/s | 42s"
  const progressMatch = line.match(
    /(\d[\d,]*)\s+attempts?\s*\|\s*([\d.]+)\/?s\s*\|\s*(\d+)s/
  );
  if (progressMatch) {
    sendEvent("progress", {
      attempts: parseInt(progressMatch[1].replace(/,/g, ""), 10),
      speed: parseFloat(progressMatch[2]),
      elapsed_s: parseInt(progressMatch[3], 10),
    });
    return;
  }

  // Strategy phase
  const strategyMatch = line.match(/\[(\w+)]\s+Starting/);
  if (strategyMatch) {
    sendEvent("phase", { strategy: strategyMatch[1].toLowerCase() });
    return;
  }

  // Exhausted strategy
  const exhaustedMatch = line.match(
    /\[(\w+)]\s+Exhausted\s+([\d,]+)\s+candidates?\s+in\s+([\d.]+)s\s+\(([\d.]+)\/s\)/
  );
  if (exhaustedMatch) {
    sendEvent("phase_done", {
      strategy: exhaustedMatch[1].toLowerCase(),
      candidates: parseInt(exhaustedMatch[2].replace(/,/g, ""), 10),
      elapsed_s: parseFloat(exhaustedMatch[3]),
      speed: parseFloat(exhaustedMatch[4]),
    });
    return;
  }

  // Vault info
  if (line.includes("Iterations:")) {
    const match = line.match(/Iterations:\s*([\d,]+)/);
    if (match) {
      sendEvent("info", { iterations: parseInt(match[1].replace(/,/g, ""), 10) });
    }
    return;
  }

  // Total parallel info
  if (line.includes("Total parallel:")) {
    const match = line.match(/Total parallel:\s*(\d+)/);
    if (match) {
      sendEvent("info", { total_parallel: parseInt(match[1], 10) });
    }
    return;
  }

  // Smart-crack phases
  const phaseMatch = line.match(/Phase\s+(\d+):\s*(.+?)(?:\s*—\s*est\.\s*([\d,]+)\s+candidates)?$/);
  if (phaseMatch) {
    sendEvent("phase", {
      phase: parseInt(phaseMatch[1], 10),
      name: phaseMatch[2].trim(),
      estimate: phaseMatch[3] ? parseInt(phaseMatch[3].replace(/,/g, ""), 10) : undefined,
    });
    return;
  }

  // Not found
  if (line.includes("Password not found")) {
    sendEvent("not_found", {});
    return;
  }

  // Generic log line (don't flood — skip very short or decoration lines)
  if (line.length > 5 && !line.match(/^[═─]+$/) && !line.startsWith("Tips:")) {
    sendEvent("log", { message: line });
  }
}
