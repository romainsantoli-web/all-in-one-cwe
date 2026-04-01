// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextRequest } from "next/server";
import { execFile } from "child_process";
import path from "path";
import os from "os";

export const dynamic = "force-dynamic";
export const maxDuration = 300;

/* ---------- ADB helpers (same as parent route) ---------- */

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

/* ---------- Validation ---------- */

const IFACE_RE = /^[a-zA-Z][a-zA-Z0-9_-]{0,15}$/;
const OUTFILE_RE = /^\/[a-zA-Z0-9/_.-]{1,200}$/;

/* ---------- POST /api/android/capture — SSE stream ---------- */

export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  const serial = body.serial ? String(body.serial) : undefined;
  const iface = String(body.iface || "wlan0");
  const packets = Math.min(Math.max(parseInt(String(body.packets || "10000"), 10) || 10000, 100), 100000);
  const outFile = String(body.outFile || "/sdcard/capture.pcap");

  // Validate inputs
  if (!IFACE_RE.test(iface)) {
    return new Response("Invalid interface name", { status: 400 });
  }
  if (!OUTFILE_RE.test(outFile) || outFile.includes("..")) {
    return new Response("Invalid output file path", { status: 400 });
  }

  const encoder = new TextEncoder();

  const steps = [
    { label: "Detect WiFi interfaces", cmd: "ip link show | grep -E 'wlan|wl'", root: false },
    { label: "Check tcpdump availability", cmd: "which tcpdump || echo NOT_FOUND", root: true },
    { label: `Disable interface ${iface}`, cmd: `ip link set ${iface} down`, root: true },
    { label: `Enable monitor mode on ${iface}`, cmd: `iw ${iface} set monitor control`, root: true },
    { label: `Bring ${iface} back up`, cmd: `ip link set ${iface} up`, root: true },
    { label: "Scan nearby networks", cmd: `iw dev ${iface} scan | grep -E 'SSID|signal|BSS ' | head -40`, root: true },
    { label: `Capture ${packets} packets`, cmd: `tcpdump -i ${iface} -w ${outFile} -c ${packets}`, root: true },
    { label: "Verify capture file", cmd: `ls -lh ${outFile}`, root: false },
    { label: "Pull capture to local", cmd: "__pull__", root: false },
  ];

  const stream = new ReadableStream({
    async start(controller) {
      const send = (data: Record<string, unknown>) => {
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
        } catch { /* closed */ }
      };

      send({ type: "init", totalSteps: steps.length, iface, packets, outFile });

      let aborted = false;

      for (let i = 0; i < steps.length; i++) {
        if (aborted) break;

        const step = steps[i];
        send({ type: "step-start", step: i, label: step.label, cmd: step.cmd, root: step.root });

        try {
          if (step.cmd === "__pull__") {
            // Pull the capture file
            const adb = findAdb();
            if (!adb) {
              send({ type: "step-end", step: i, ok: false, output: "ADB not found" });
              aborted = true;
              break;
            }
            const projectRoot = path.resolve(process.cwd(), "..");
            const fname = outFile.split("/").pop() || `capture_${Date.now()}.pcap`;
            const dest = path.join(projectRoot, "reports", "android", fname);
            if (!dest.startsWith(projectRoot)) {
              send({ type: "step-end", step: i, ok: false, output: "Path traversal blocked" });
              aborted = true;
              break;
            }
            const { mkdirSync } = require("fs");
            mkdirSync(path.dirname(dest), { recursive: true });
            const r = await runAdb(["pull", outFile, dest], serial, 120000);
            send({
              type: "step-end",
              step: i,
              ok: r.ok,
              output: r.ok ? `✅ Pulled to: ${dest}` : `${r.stdout}\n${r.stderr}`.trim(),
            });
            if (!r.ok) aborted = true;
          } else {
            const args = step.root
              ? ["shell", "su", "-c", step.cmd]
              : ["shell", step.cmd];
            const timeout = step.cmd.includes("tcpdump") ? 120000 : 30000;
            const r = await runAdb(args, serial, timeout);
            const output = ((r.stdout || "") + (r.stderr ? `\nstderr: ${r.stderr}` : "")).trim();

            // Step 1 (tcpdump check) — abort if not found
            if (i === 1 && (r.stdout || "").includes("NOT_FOUND")) {
              send({
                type: "step-end",
                step: i,
                ok: false,
                output: "tcpdump not installed on device. Install it or use airodump-ng.",
              });
              aborted = true;
              // Mark remaining as skipped
              for (let j = i + 1; j < steps.length; j++) {
                send({ type: "step-skip", step: j, label: steps[j].label });
              }
              break;
            }

            // Step 3 (monitor mode) — soft fail
            if (i === 3 && !r.ok) {
              send({
                type: "step-end",
                step: i,
                ok: true,
                output: output + "\n⚠️ Monitor mode not supported — continuing in managed mode",
                warning: true,
              });
            } else {
              send({ type: "step-end", step: i, ok: r.ok, output });
              if (!r.ok && i !== 3) {
                aborted = true;
                for (let j = i + 1; j < steps.length; j++) {
                  send({ type: "step-skip", step: j, label: steps[j].label });
                }
                break;
              }
            }
          }
        } catch (err) {
          send({
            type: "step-end",
            step: i,
            ok: false,
            output: `Error: ${err instanceof Error ? err.message : String(err)}`,
          });
          aborted = true;
          for (let j = i + 1; j < steps.length; j++) {
            send({ type: "step-skip", step: j, label: steps[j].label });
          }
          break;
        }
      }

      send({ type: "done", aborted });
      try { controller.close(); } catch { /* already closed */ }
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
