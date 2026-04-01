// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * GitHub Copilot Pro OAuth Device Flow API
 *
 * POST → Start device flow (returns user_code + verification_uri)
 * PUT  → Poll for completion (returns status + saves JWT)
 * GET  → Check current auth status
 */

import { NextResponse } from "next/server";
import { execFile } from "child_process";
import { join } from "path";
import { getEnvWithSettings, saveProviderSettings, getProviderSettings } from "@/lib/settings";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

function runPython(code: string, env: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      "python3",
      ["-c", code],
      {
        cwd: PROJECT_ROOT,
        env,
        timeout: 15000,
        maxBuffer: 1024 * 64,
      },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(stderr || err.message));
        } else {
          resolve(stdout.trim());
        }
      },
    );
  });
}

/** POST — Start OAuth device flow */
export async function POST() {
  try {
    const env = await getEnvWithSettings();
    const code = `
import sys, json
sys.path.insert(0, "${PROJECT_ROOT}")
from llm.providers.copilot_pro import CopilotProProvider
result = CopilotProProvider.start_device_flow()
print(json.dumps(result))
`;
    const raw = await runPython(code, env);
    const data = JSON.parse(raw);
    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 500 },
    );
  }
}

/** PUT — Poll device flow & save tokens */
export async function PUT(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const deviceCode = body.device_code;
  if (typeof deviceCode !== "string" || deviceCode.length < 10 || deviceCode.length > 200) {
    return NextResponse.json({ error: "Invalid device_code" }, { status: 400 });
  }

  // Sanitize device_code for safe embedding in Python string
  const safeCode = deviceCode.replace(/[^a-zA-Z0-9_-]/g, "");
  if (safeCode !== deviceCode) {
    return NextResponse.json({ error: "Invalid device_code characters" }, { status: 400 });
  }

  try {
    const env = await getEnvWithSettings();
    const code = `
import sys, json
sys.path.insert(0, "${PROJECT_ROOT}")
from llm.providers.copilot_pro import CopilotProProvider
result = CopilotProProvider.poll_device_flow("${safeCode}")
print(json.dumps(result))
`;
    const raw = await runPython(code, env);
    const data = JSON.parse(raw);

    // If successful, save the OAuth token to provider settings
    // (OAuth token is long-lived — session tokens are fetched fresh per call)
    if (data.status === "ok" && data.oauth_token) {
      const saved = await getProviderSettings();
      saved["COPILOT_OAUTH_TOKEN"] = data.oauth_token;
      // Remove stale short-lived JWT if present
      delete saved["COPILOT_JWT"];
      await saveProviderSettings(saved);
      // Don't leak tokens in response
      delete data.oauth_token;
    }

    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 500 },
    );
  }
}

/** GET — Check current auth status */
export async function GET() {
  try {
    const env = await getEnvWithSettings();
    const code = `
import sys, json
sys.path.insert(0, "${PROJECT_ROOT}")
from llm.providers.copilot_pro import CopilotProProvider
result = CopilotProProvider.get_auth_status()
print(json.dumps(result))
`;
    const raw = await runPython(code, env);
    const data = JSON.parse(raw);
    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: (err as Error).message },
      { status: 500 },
    );
  }
}
