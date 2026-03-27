// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { createConnection } from "net";

export const dynamic = "force-dynamic";

/**
 * GET /api/cdp/status
 * Check if a Chrome DevTools Protocol endpoint is reachable.
 */
export async function GET() {
  const cdpUrl = process.env.CDP_URL || "ws://localhost:9222";
  let host: string;
  let port: number;

  try {
    const parsed = new URL(cdpUrl);
    host = parsed.hostname;
    port = parseInt(parsed.port, 10) || 9222;
  } catch {
    return NextResponse.json({ available: false, url: cdpUrl, error: "Invalid CDP_URL format" });
  }

  const available = await new Promise<boolean>((resolve) => {
    const socket = createConnection({ host, port, timeout: 2000 }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });

  return NextResponse.json({
    available,
    url: cdpUrl,
    host,
    port,
    launchHint: available
      ? null
      : `Launch Chrome with: google-chrome --headless --remote-debugging-port=${port} --no-first-run --disable-gpu`,
  });
}
