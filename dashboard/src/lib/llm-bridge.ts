// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * LLM bridge — executes Python LLM providers from Node.js via subprocess.
 * Returns streaming text via a line-buffered protocol.
 */

import { spawn } from "child_process";
import { join } from "path";
import { getEnvWithSettings } from "@/lib/settings";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

export interface LLMRequest {
  provider: string;
  messages: Array<{ role: string; content: string }>;
  temperature?: number;
  maxTokens?: number;
}

/**
 * Call the Python LLM provider and stream text back.
 * Protocol: stdout emits JSON lines: {"chunk":"text"} or {"done":true,"stats":{...}}
 */
export function callLLM(req: LLMRequest): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();

  return new ReadableStream({
    async start(controller) {
      const script = join(PROJECT_ROOT, "llm", "cli.py");
      const input = JSON.stringify({
        provider: req.provider,
        messages: req.messages,
        temperature: req.temperature ?? 0.7,
        max_tokens: req.maxTokens ?? 4096,
      });

      const env = await getEnvWithSettings();

      const child = spawn("python3", [script], {
        cwd: PROJECT_ROOT,
        env,
        stdio: ["pipe", "pipe", "pipe"],
      });

      child.stdin?.write(input);
      child.stdin?.end();

      let buffer = "";
      child.stdout?.on("data", (data: Buffer) => {
        buffer += data.toString();
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (line.trim()) {
            controller.enqueue(encoder.encode(`data: ${line}\n\n`));
          }
        }
      });

      let stderrBuf = "";
      child.stderr?.on("data", (data: Buffer) => {
        stderrBuf += data.toString();
      });

      child.on("exit", (code) => {
        if (buffer.trim()) {
          controller.enqueue(encoder.encode(`data: ${buffer.trim()}\n\n`));
        }
        if (code !== 0 && stderrBuf) {
          const errMsg = JSON.stringify({ error: stderrBuf.slice(0, 500) });
          controller.enqueue(encoder.encode(`data: ${errMsg}\n\n`));
        }
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      });

      child.on("error", (err) => {
        const errMsg = JSON.stringify({ error: err.message });
        controller.enqueue(encoder.encode(`data: ${errMsg}\n\n`));
        controller.enqueue(encoder.encode("data: [DONE]\n\n"));
        controller.close();
      });
    },
  });
}

/**
 * Non-streaming LLM call — collects full response.
 */
export async function callLLMSync(req: LLMRequest): Promise<string> {
  const env = await getEnvWithSettings();
  return new Promise((resolve, reject) => {
    const script = join(PROJECT_ROOT, "llm", "cli.py");
    const input = JSON.stringify({
      provider: req.provider,
      messages: req.messages,
      temperature: req.temperature ?? 0.7,
      max_tokens: req.maxTokens ?? 4096,
    });

    const child = spawn("python3", [script, "--sync"], {
      cwd: PROJECT_ROOT,
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });

    child.stdin?.write(input);
    child.stdin?.end();

    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d: Buffer) => { stdout += d.toString(); });
    child.stderr?.on("data", (d: Buffer) => { stderr += d.toString(); });
    child.on("exit", (code) => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(stderr.slice(0, 500) || `LLM process exited with code ${code}`));
    });
    child.on("error", reject);
  });
}
