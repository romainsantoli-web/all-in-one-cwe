// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import path from "path";
import os from "os";

export const dynamic = "force-dynamic";
export const maxDuration = 120;

// --------------------------------------------------------------------------
// ADB binary discovery
// --------------------------------------------------------------------------

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

// --------------------------------------------------------------------------
// Validation
// --------------------------------------------------------------------------

const ALLOWED_ACTIONS = new Set([
  "devices", "connect", "pair", "status", "shell", "pull", "push",
]);

const BLOCKED_SHELL = [
  "rm -rf /", "dd if=", "mkfs.", "reboot", "flash",
  "fastboot", "wipe", "factory", "format /", "svc power shutdown",
];

function hasTraversal(val: string): boolean {
  return val.includes("..") || val.includes("\0");
}

const IP_PORT_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?$/;
const SERIAL_RE = /^[\w.:@[\]-]{1,100}$/;
const BSSID_RE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;

// --------------------------------------------------------------------------
// ADB runner
// --------------------------------------------------------------------------

function runAdb(
  args: string[],
  serial?: string,
  timeout = 30000,
): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const adb = findAdb();
    if (!adb) {
      resolve({
        ok: false,
        stdout: "",
        stderr: "ADB not found. Install: brew install android-platform-tools",
        code: -1,
      });
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

// --------------------------------------------------------------------------
// POST /api/android
// --------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const action = String(body.action || "").toLowerCase();
    const serial = body.serial ? String(body.serial) : undefined;

    if (!ALLOWED_ACTIONS.has(action)) {
      return NextResponse.json(
        { error: `Invalid action. Allowed: ${[...ALLOWED_ACTIONS].join(", ")}` },
        { status: 400 },
      );
    }

    // --- devices ---
    if (action === "devices") {
      const r = await runAdb(["devices", "-l"], serial);
      const devices = (r.stdout || "")
        .split("\n")
        .slice(1)
        .filter((l) => l.trim())
        .map((l) => {
          const parts = l.split(/\s+/);
          return {
            serial: parts[0],
            state: parts[1],
            info: parts.slice(2).join(" "),
          };
        });
      return NextResponse.json({ devices, count: devices.length });
    }

    // --- connect ---
    if (action === "connect") {
      const target = String(body.target || "");
      if (!IP_PORT_RE.test(target)) {
        return NextResponse.json(
          { error: "target must be IP:port (e.g. 192.168.1.100:5555)" },
          { status: 400 },
        );
      }
      const r = await runAdb(["connect", target], serial);
      return NextResponse.json(r);
    }

    // --- pair ---
    if (action === "pair") {
      const target = String(body.target || "");
      const code = String(body.pairing_code || "");
      if (!IP_PORT_RE.test(target)) {
        return NextResponse.json({ error: "target must be IP:port" }, { status: 400 });
      }
      if (!/^\d{6}$/.test(code)) {
        return NextResponse.json({ error: "pairing_code must be 6 digits" }, { status: 400 });
      }
      const r = await runAdb(["pair", target, code], serial);
      return NextResponse.json(r);
    }

    // --- status ---
    if (action === "status") {
      const [model, version, root, ifaces] = await Promise.all([
        runAdb(["shell", "getprop", "ro.product.model"], serial),
        runAdb(["shell", "getprop", "ro.build.version.release"], serial),
        runAdb(["shell", "su", "-c", "id"], serial, 10000),
        runAdb(["shell", "ip", "link", "show"], serial),
      ]);
      return NextResponse.json({
        model: model.stdout.trim(),
        android_version: version.stdout.trim(),
        rooted: root.stdout.includes("uid=0"),
        interfaces: ifaces.stdout,
      });
    }

    // --- shell ---
    if (action === "shell") {
      const command = String(body.command || "");
      if (!command || command.length > 2000) {
        return NextResponse.json({ error: "command required (max 2000 chars)" }, { status: 400 });
      }
      const lower = command.toLowerCase();
      for (const pat of BLOCKED_SHELL) {
        if (lower.includes(pat)) {
          return NextResponse.json({ error: `Blocked: ${pat}` }, { status: 403 });
        }
      }
      const asRoot = Boolean(body.as_root);
      const args = asRoot
        ? ["shell", "su", "-c", command]
        : ["shell", command];
      const r = await runAdb(args, serial);
      return NextResponse.json(r);
    }

    // --- pull ---
    if (action === "pull") {
      const devicePath = String(body.device_path || "");
      if (!devicePath || hasTraversal(devicePath)) {
        return NextResponse.json({ error: "device_path required, no traversal" }, { status: 400 });
      }
      const projectRoot = path.resolve(process.cwd(), "..");
      const fname = devicePath.split("/").pop() || `pulled_${Date.now()}`;
      const dest = path.join(projectRoot, "reports", "android", fname);
      // Validate dest under project
      if (!dest.startsWith(projectRoot)) {
        return NextResponse.json({ error: "Destination traversal blocked" }, { status: 400 });
      }
      const { mkdirSync } = require("fs");
      mkdirSync(path.dirname(dest), { recursive: true });
      const r = await runAdb(["pull", devicePath, dest], serial, 120000);
      return NextResponse.json({ ...r, local_file: r.ok ? dest : undefined });
    }

    // --- push ---
    if (action === "push") {
      const localPath = String(body.local_path || "");
      const devicePath = String(body.device_path || "");
      if (!localPath || !devicePath) {
        return NextResponse.json({ error: "local_path and device_path required" }, { status: 400 });
      }
      if (hasTraversal(localPath) || hasTraversal(devicePath)) {
        return NextResponse.json({ error: "Path traversal blocked" }, { status: 400 });
      }
      const projectRoot = path.resolve(process.cwd(), "..");
      const src = path.resolve(projectRoot, localPath);
      if (!src.startsWith(projectRoot)) {
        return NextResponse.json({ error: "Source traversal blocked" }, { status: 400 });
      }
      const { existsSync } = require("fs");
      if (!existsSync(src)) {
        return NextResponse.json({ error: `File not found: ${localPath}` }, { status: 404 });
      }
      const r = await runAdb(["push", src, devicePath], serial, 120000);
      return NextResponse.json(r);
    }

    return NextResponse.json({ error: "Unhandled action" }, { status: 400 });
  } catch (err) {
    return NextResponse.json(
      { error: `Android bridge error: ${err instanceof Error ? err.message : String(err)}` },
      { status: 500 },
    );
  }
}

// --------------------------------------------------------------------------
// GET /api/android — quick device list
// --------------------------------------------------------------------------

export async function GET() {
  const r = await runAdb(["devices", "-l"]);
  const devices = (r.stdout || "")
    .split("\n")
    .slice(1)
    .filter((l) => l.trim())
    .map((l) => {
      const parts = l.split(/\s+/);
      return { serial: parts[0], state: parts[1], info: parts.slice(2).join(" ") };
    });
  return NextResponse.json({ devices, count: devices.length, adb_available: r.code !== -1 });
}
