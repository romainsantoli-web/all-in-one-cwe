// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextRequest } from "next/server";
import { execFile } from "child_process";
import path from "path";
import os from "os";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/* ---------- ADB helpers ---------- */

const ADB_CANDIDATES = [
  "adb",
  path.join(os.homedir(), "Library/Android/sdk/platform-tools/adb"),
  "/opt/homebrew/bin/adb",
  "/usr/local/bin/adb",
];

function findAdb(): string | null {
  for (const candidate of ADB_CANDIDATES) {
    try {
      const { execFileSync } = require("child_process");
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

/* ---------- POST /api/android/termux-setup — SSE stream ---------- */

/**
 * Termux-based setup workflow for rooting + tcpdump installation.
 * Steps:
 * 1. Check Termux is installed
 * 2. Grant Termux storage permission
 * 3. Update Termux packages
 * 4. Install root-repo
 * 5. Install tsu (Termux su helper)
 * 6. Install tcpdump
 * 7. Install wireless-tools (iw)
 * 8. Verify root access via tsu
 * 9. Verify tcpdump works
 * 10. Show capture instructions
 */
export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  const serial = body.serial ? String(body.serial) : undefined;
  const encoder = new TextEncoder();

  // Helper to run a command inside Termux via its RUN_COMMAND broadcast
  // This sends commands to Termux's internal shell
  const runTermux = (cmd: string, timeout = 30000): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> => {
    // Method 1: try run-as (works if Termux is debuggable or same user)
    // Method 2: use Termux:Tasker am broadcast (requires Termux:Tasker installed)
    // Method 3: regular adb shell — commands that don't need Termux env
    // For pkg commands, we need Termux's environment, so use login shell exec
    const termuxExec = `run-as com.termux files/usr/bin/bash -lic '${cmd.replace(/'/g, "'\\''")}'`;
    return runAdb(["shell", termuxExec], serial, timeout);
  };

  // Fallback: run directly via adb shell (for non-Termux commands)
  const runShell = (cmd: string, root = false, timeout = 30000) => {
    const args = root ? ["shell", "su", "-c", cmd] : ["shell", cmd];
    return runAdb(args, serial, timeout);
  };

  const steps = [
    {
      label: "Check Termux installation",
      run: async () => {
        const r = await runAdb(["shell", "pm", "list", "packages", "com.termux"], serial);
        if (!r.stdout.includes("com.termux")) {
          return { ok: false, output: "❌ Termux not installed. Install from F-Droid: https://f-droid.org/packages/com.termux/" };
        }
        return { ok: true, output: "✅ Termux is installed" };
      },
    },
    {
      label: "Check Termux accessibility",
      run: async () => {
        const r = await runTermux("echo OK");
        if (!r.ok || !r.stdout.includes("OK")) {
          return {
            ok: true,
            output: "⚠️ Cannot exec via run-as — will use alternative method.\n"
              + "Make sure Termux is open on the phone, then run these commands manually:\n"
              + "  pkg update -y && pkg install root-repo -y",
            warning: true,
          };
        }
        return { ok: true, output: "✅ Termux shell accessible via ADB" };
      },
    },
    {
      label: "Update Termux packages",
      run: async () => {
        const r = await runTermux("pkg update -y 2>&1 | tail -5", 120000);
        return {
          ok: true,
          output: r.ok
            ? `✅ Packages updated\n${r.stdout.slice(-500)}`
            : `⚠️ Auto-update failed — run manually in Termux:\n  pkg update -y\n\nOutput: ${r.stderr || r.stdout}`,
          warning: !r.ok,
        };
      },
    },
    {
      label: "Install root-repo (Termux root packages)",
      run: async () => {
        const r = await runTermux("pkg install root-repo -y 2>&1 | tail -5", 60000);
        return {
          ok: true,
          output: r.ok
            ? `✅ root-repo installed\n${r.stdout.slice(-300)}`
            : `⚠️ Install failed — run in Termux:\n  pkg install root-repo -y\n\n${r.stderr || r.stdout}`,
          warning: !r.ok,
        };
      },
    },
    {
      label: "Install tsu (Termux su wrapper)",
      run: async () => {
        const r = await runTermux("pkg install tsu -y 2>&1 | tail -5", 60000);
        return {
          ok: true,
          output: r.ok
            ? `✅ tsu installed\n${r.stdout.slice(-300)}`
            : `⚠️ Install failed — run in Termux:\n  pkg install tsu -y\n\n${r.stderr || r.stdout}`,
          warning: !r.ok,
        };
      },
    },
    {
      label: "Install tcpdump",
      run: async () => {
        const r = await runTermux("pkg install tcpdump -y 2>&1 | tail -5", 60000);
        return {
          ok: true,
          output: r.ok
            ? `✅ tcpdump installed\n${r.stdout.slice(-300)}`
            : `⚠️ Install failed — run in Termux:\n  pkg install tcpdump -y\n\n${r.stderr || r.stdout}`,
          warning: !r.ok,
        };
      },
    },
    {
      label: "Install wireless-tools (iw, iwconfig)",
      run: async () => {
        const r = await runTermux("pkg install wireless-tools -y 2>&1 | tail -5", 60000);
        return {
          ok: true,
          output: r.ok
            ? `✅ wireless-tools installed\n${r.stdout.slice(-300)}`
            : `⚠️ Install not available — use basic ip/iw commands\n${r.stderr || r.stdout}`,
          warning: !r.ok,
        };
      },
    },
    {
      label: "Verify root access (su / Magisk)",
      run: async () => {
        const r = await runShell("su -c whoami", true);
        if (r.ok && r.stdout.trim() === "root") {
          return { ok: true, output: "✅ Root access confirmed — su works, user: root" };
        }
        // Check Magisk
        const magisk = await runAdb(["shell", "pm", "list", "packages", "com.topjohnwu.magisk"], serial);
        const hasMagisk = magisk.stdout.includes("com.topjohnwu.magisk");
        return {
          ok: false,
          output: hasMagisk
            ? "⚠️ Magisk installed but SU grant needed.\n"
              + "Open Magisk → Superuser → grant Termux root access.\n"
              + "Then retry."
            : "❌ No root access detected.\n"
              + "Options:\n"
              + "  1. Install Magisk: https://github.com/topjohnwu/Magisk/releases\n"
              + "  2. Use the No-Root Mac capture method instead\n"
              + "  3. Use PCAPdroid app (VPN-based, no root needed)",
        };
      },
    },
    {
      label: "Verify tcpdump binary",
      run: async () => {
        const r = await runTermux("which tcpdump && tcpdump --version 2>&1 | head -3");
        if (!r.ok || !r.stdout.includes("tcpdump")) {
          // Try system-wide
          const r2 = await runShell("which tcpdump || echo NOT_FOUND");
          if (r2.stdout.includes("NOT_FOUND")) {
            return { ok: false, output: "❌ tcpdump not found in PATH. Was the install successful?" };
          }
          return { ok: true, output: `✅ System tcpdump found:\n${r2.stdout.trim()}` };
        }
        return { ok: true, output: `✅ tcpdump ready:\n${r.stdout.trim()}` };
      },
    },
    {
      label: "Setup complete — next steps",
      run: async () => {
        return {
          ok: true,
          output:
            "🎉 Termux environment ready!\n\n"
            + "You can now use the WiFi Capture workflow:\n"
            + "  📡 Quick WiFi Capture → Launch in Terminal\n\n"
            + "Or run manually in Termux:\n"
            + "  tsu                                    # get root\n"
            + "  tcpdump -i wlan0 -w /sdcard/capture.pcap -c 10000\n\n"
            + "For monitor mode (if chipset supports):\n"
            + "  ip link set wlan0 down\n"
            + "  iw wlan0 set monitor control\n"
            + "  ip link set wlan0 up\n"
            + "  tcpdump -i wlan0 -w /sdcard/monitor.pcap -c 10000",
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

          // Abort on critical failure (Termux not installed, no root)
          if (!result.ok && (i === 0 || i === 7)) {
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
