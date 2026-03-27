// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { spawn } from "child_process";

export const dynamic = "force-dynamic";

// Track the Chrome process globally
let chromeProcess: ReturnType<typeof spawn> | null = null;
let chromePid: number | null = null;

/**
 * POST /api/cdp/launch
 * Launch Chrome headless with remote debugging enabled.
 */
export async function POST() {
  // Check if already running
  if (chromePid) {
    try {
      process.kill(chromePid, 0); // Check if alive
      return NextResponse.json({
        launched: false,
        message: "Chrome is already running",
        pid: chromePid,
      });
    } catch {
      // Process no longer exists
      chromePid = null;
      chromeProcess = null;
    }
  }

  const port = parseInt(process.env.CDP_PORT || "9222", 10);

  // Try different Chrome paths for macOS/Linux
  const chromePaths = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    process.env.CHROME_PATH || "",
  ].filter(Boolean);

  let launched = false;
  let usedPath = "";

  for (const chromePath of chromePaths) {
    try {
      const child = spawn(chromePath, [
        "--headless=new",
        `--remote-debugging-port=${port}`,
        "--no-first-run",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-extensions",
        "about:blank",
      ], {
        detached: true,
        stdio: ["ignore", "ignore", "ignore"],
      });

      child.unref();

      if (child.pid) {
        chromeProcess = child;
        chromePid = child.pid;
        usedPath = chromePath;
        launched = true;

        child.on("exit", () => {
          chromePid = null;
          chromeProcess = null;
        });

        // Wait a moment for Chrome to start
        await new Promise((r) => setTimeout(r, 1500));
        break;
      }
    } catch {
      // Try next path
      continue;
    }
  }

  if (!launched) {
    return NextResponse.json(
      {
        launched: false,
        error: "Chrome not found. Set CHROME_PATH env var or install Chrome/Chromium.",
      },
      { status: 500 },
    );
  }

  return NextResponse.json({
    launched: true,
    pid: chromePid,
    port,
    chromePath: usedPath,
    message: `Chrome headless launched on port ${port}`,
  });
}

/**
 * DELETE /api/cdp/launch
 * Stop the Chrome headless process.
 */
export async function DELETE() {
  if (!chromePid) {
    return NextResponse.json({ stopped: false, message: "Chrome is not running" });
  }

  try {
    process.kill(chromePid, "SIGTERM");
  } catch {
    // Already gone
  }

  chromeProcess = null;
  chromePid = null;

  return NextResponse.json({ stopped: true });
}
