// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextRequest } from "next/server";
import { execFile, execFileSync } from "child_process";
import path from "path";
import os from "os";
import fs from "fs";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/* ---------- helpers ---------- */

const ADB_CANDIDATES = [
  "adb",
  path.join(os.homedir(), "Library/Android/sdk/platform-tools/adb"),
  "/opt/homebrew/bin/adb",
  "/usr/local/bin/adb",
];

function findAdb(): string | null {
  for (const candidate of ADB_CANDIDATES) {
    try {
      execFileSync(candidate, ["version"], { timeout: 3000, stdio: "pipe" });
      return candidate;
    } catch {
      continue;
    }
  }
  return null;
}

const SERIAL_RE = /^[\w.:@[\]-]{1,100}$/;

function runAdb(
  args: string[],
  serial?: string,
  timeout = 30000,
): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const adb = findAdb();
    if (!adb) {
      resolve({ ok: false, stdout: "", stderr: "ADB not found", code: -1 });
      return;
    }
    const cmd: string[] = [];
    if (serial) {
      if (!SERIAL_RE.test(serial)) {
        resolve({ ok: false, stdout: "", stderr: "Invalid serial", code: -1 });
        return;
      }
      cmd.push("-s", serial);
    }
    cmd.push(...args);
    execFile(adb, cmd, { timeout, maxBuffer: 1024 * 512 }, (err, stdout, stderr) => {
      const code = err && "code" in err ? (err as { code: number }).code : err ? 1 : 0;
      resolve({
        ok: code === 0,
        stdout: (stdout || "").slice(0, 8000),
        stderr: (stderr || "").slice(0, 2000),
        code: typeof code === "number" ? code : 1,
      });
    });
  });
}

function findTcpdump(): string | null {
  for (const p of ["/usr/sbin/tcpdump", "/usr/local/sbin/tcpdump", "/opt/homebrew/sbin/tcpdump", "tcpdump"]) {
    try {
      execFileSync(p, ["--version"], { timeout: 3000, stdio: "pipe" });
      return p;
    } catch {
      continue;
    }
  }
  return null;
}

function runLocal(
  cmd: string,
  args: string[],
  timeout = 60000,
): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, maxBuffer: 1024 * 512 }, (err, stdout, stderr) => {
      const code = err && "code" in err ? (err as { code: number }).code : err ? 1 : 0;
      resolve({
        ok: code === 0,
        stdout: (stdout || "").slice(0, 8000),
        stderr: (stderr || "").slice(0, 2000),
        code: typeof code === "number" ? code : 1,
      });
    });
  });
}

/* ---------- Validation ---------- */

const IFACE_RE = /^[a-zA-Z][a-zA-Z0-9_-]{0,15}$/;

/* ---------- POST /api/android/mac-capture — SSE stream ---------- */

/**
 * Mac-side passive capture workflow — no root needed on the phone.
 * Steps:
 * 1. Check Mac tcpdump availability
 * 2. Get phone IP from ADB connection
 * 3. List Mac network interfaces
 * 4. Detect active Mac interface (en0/en1)
 * 5. Start tcpdump on Mac filtering phone traffic
 * 6. Save capture file locally
 * 7. Show analysis hints
 */
export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  const serial = body.serial ? String(body.serial) : undefined;
  const macIface = String(body.macIface || "en0");
  const duration = Math.min(Math.max(parseInt(String(body.duration || "30"), 10) || 30, 5), 300);
  const outFileName = String(body.outFile || "mac-capture.pcap").replace(/[^a-zA-Z0-9._-]/g, "_");

  if (!IFACE_RE.test(macIface)) {
    return new Response("Invalid interface name", { status: 400 });
  }

  const encoder = new TextEncoder();
  let phoneIp = "";

  const steps = [
    {
      label: "Check tcpdump on Mac",
      run: async () => {
        const tcpdumpPath = findTcpdump();
        if (!tcpdumpPath) {
          return { ok: false, output: "❌ tcpdump not found on Mac. It should be pre-installed on macOS." };
        }
        const r = await runLocal(tcpdumpPath, ["--version"]);
        return { ok: true, output: `✅ tcpdump available: ${tcpdumpPath}\n${(r.stdout + r.stderr).trim().split("\n")[0]}` };
      },
    },
    {
      label: "Get phone IP address",
      run: async () => {
        // Get IP from ADB — the phone is connected via WiFi, we can get its WLAN IP
        const r = await runAdb(["shell", "ip", "route", "get", "8.8.8.8"], serial);
        const ipMatch = (r.stdout || "").match(/src\s+(\d+\.\d+\.\d+\.\d+)/);
        if (ipMatch) {
          phoneIp = ipMatch[1];
          return { ok: true, output: `✅ Phone IP detected: ${phoneIp}` };
        }
        // Fallback: try ip addr on wlan0
        const r2 = await runAdb(["shell", "ip", "addr", "show", "wlan0"], serial);
        const ipMatch2 = (r2.stdout || "").match(/inet\s+(\d+\.\d+\.\d+\.\d+)/);
        if (ipMatch2) {
          phoneIp = ipMatch2[1];
          return { ok: true, output: `✅ Phone WLAN IP: ${phoneIp}` };
        }
        // Last fallback: ifconfig
        const r3 = await runAdb(["shell", "ifconfig", "wlan0"], serial);
        const ipMatch3 = (r3.stdout || "").match(/inet addr:\s*(\d+\.\d+\.\d+\.\d+)/);
        if (ipMatch3) {
          phoneIp = ipMatch3[1];
          return { ok: true, output: `✅ Phone IP: ${phoneIp}` };
        }
        return {
          ok: false,
          output: "❌ Could not detect phone IP address.\n"
            + "Run manually on phone: ip addr show wlan0\n"
            + `Raw output: ${r.stdout} ${r2.stdout}`,
        };
      },
    },
    {
      label: "List Mac network interfaces",
      run: async () => {
        const r = await runLocal("ifconfig", ["-l"]);
        return {
          ok: r.ok,
          output: r.ok
            ? `Available interfaces: ${r.stdout.trim()}\nUsing: ${macIface}`
            : `Failed to list interfaces: ${r.stderr}`,
        };
      },
    },
    {
      label: `Check Mac interface ${macIface}`,
      run: async () => {
        const r = await runLocal("ifconfig", [macIface]);
        if (!r.ok) {
          return { ok: false, output: `❌ Interface ${macIface} not found or down.\n${r.stderr}` };
        }
        const ipMatch = r.stdout.match(/inet\s+(\d+\.\d+\.\d+\.\d+)/);
        const macIp = ipMatch ? ipMatch[1] : "unknown";
        return { ok: true, output: `✅ ${macIface} is up — Mac IP: ${macIp}\n${r.stdout.split("\n").slice(0, 5).join("\n")}` };
      },
    },
    {
      label: "Verify phone is reachable from Mac",
      run: async () => {
        if (!phoneIp) {
          return { ok: false, output: "⏭️ No phone IP — skipping ping test" };
        }
        const r = await runLocal("ping", ["-c", "2", "-t", "3", phoneIp]);
        return {
          ok: r.ok,
          output: r.ok
            ? `✅ Phone ${phoneIp} is reachable\n${r.stdout.split("\n").slice(-3).join("\n")}`
            : `⚠️ Phone not responding to ping (may be blocked by firewall — capture may still work)\n${r.stdout}`,
          warning: !r.ok,
        };
      },
    },
    {
      label: `Capture ${duration}s of phone traffic`,
      run: async () => {
        if (!phoneIp) {
          return { ok: false, output: "❌ No phone IP — cannot filter traffic" };
        }
        const tcpdumpPath = findTcpdump();
        if (!tcpdumpPath) {
          return { ok: false, output: "❌ tcpdump not found" };
        }
        const projectRoot = path.resolve(process.cwd(), "..");
        const dest = path.join(projectRoot, "reports", "android", outFileName);
        if (!dest.startsWith(projectRoot)) {
          return { ok: false, output: "❌ Path traversal blocked" };
        }
        fs.mkdirSync(path.dirname(dest), { recursive: true });

        // Run tcpdump with timeout — capture all traffic to/from phone IP
        const r = await runLocal(
          tcpdumpPath,
          [
            "-i", macIface,
            "-w", dest,
            "-G", String(duration),        // rotate every N seconds
            "-W", "1",                      // only 1 rotation = stops after duration
            "host", phoneIp,
          ],
          (duration + 10) * 1000,
        );

        // tcpdump exits after -G/-W combo — check file exists
        try {
          const stats = fs.statSync(dest);
          return {
            ok: true,
            output: `✅ Capture saved: ${dest}\n`
              + `File size: ${(stats.size / 1024).toFixed(1)} KB\n`
              + `Duration: ${duration}s | Filter: host ${phoneIp}\n`
              + (r.stderr ? `tcpdump: ${r.stderr.split("\n").slice(-3).join("\n")}` : ""),
          };
        } catch {
          return {
            ok: r.ok || (r.stderr || "").includes("packets captured"),
            output: `Capture attempted → ${dest}\n`
              + `${r.stdout}\n${r.stderr}\n`
              + "⚠️ File may be empty if no traffic was detected during capture.",
            warning: true,
          };
        }
      },
    },
    {
      label: "Analysis & next steps",
      run: async () => {
        const projectRoot = path.resolve(process.cwd(), "..");
        const dest = path.join(projectRoot, "reports", "android", outFileName);
        return {
          ok: true,
          output:
            `🎉 Mac-side capture complete!\n\n`
            + `File: ${dest}\n\n`
            + `Analyze with:\n`
            + `  # Open in Wireshark\n`
            + `  open -a Wireshark ${dest}\n\n`
            + `  # Quick stats\n`
            + `  tcpdump -r ${dest} | head -50\n\n`
            + `  # HTTP requests\n`
            + `  tcpdump -r ${dest} -A 'tcp port 80' | head -100\n\n`
            + `  # DNS queries\n`
            + `  tcpdump -r ${dest} 'udp port 53' -nn\n\n`
            + `  # TLS handshakes (SNI)\n`
            + `  tcpdump -r ${dest} 'tcp port 443' -nn | head -20\n\n`
            + `For HTTPS interception, consider mitmproxy:\n`
            + `  brew install mitmproxy\n`
            + `  mitmproxy --mode regular --listen-port 8080\n`
            + `  # Then set phone proxy → Mac IP:8080`,
        };
      },
    },
  ];

  const stream = new ReadableStream({
    async start(controller) {
      const send = (data: Record<string, unknown>) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
        } catch { /* closed */ }
      };

      send({ type: "init", totalSteps: steps.length });

      for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        send({ type: "step-start", step: i, label: step.label, cmd: "", root: false });

        try {
          const result = await step.run();
          send({
            type: "step-end",
            step: i,
            ok: result.ok,
            output: result.output,
            warning: "warning" in result ? result.warning : false,
          });

          // Abort on critical failures
          if (!result.ok && (i === 0 || i === 1 || i === 3)) {
            for (let j = i + 1; j < steps.length; j++) {
              send({ type: "step-skip", step: j, label: steps[j].label });
            }
            break;
          }
        } catch (err) {
          send({
            type: "step-end",
            step: i,
            ok: false,
            output: `Error: ${err instanceof Error ? err.message : String(err)}`,
          });
        }
      }

      send({ type: "done", aborted: false });
      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-store",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
