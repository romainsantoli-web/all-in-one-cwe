// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";

export const dynamic = "force-dynamic";

const execFileAsync = promisify(execFile);

const GENERATOR_PATH = path.resolve(
  process.cwd(),
  "..",
  "tools",
  "python-scanners",
  "smart_wordlist.py"
);

const PYTHON = process.env.PYTHON_BIN || "python3";

// Allowed profile fields (whitelist)
const ALLOWED_FIELDS = new Set([
  "first_name", "last_name", "nickname", "birth_date",
  "spouse_name", "children_names", "pet_names", "city",
  "postal_code", "country", "email", "usernames", "phone",
  "company", "keywords", "old_passwords", "ssid", "bssid", "isp",
]);

export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const profile = body.profile as Record<string, unknown> | undefined;
  const webSearch = body.web_search === true;

  if (!profile || typeof profile !== "object") {
    return NextResponse.json({ error: "Missing profile object" }, { status: 400 });
  }

  // Validate: no path traversal in any string field
  for (const [key, val] of Object.entries(profile)) {
    if (!ALLOWED_FIELDS.has(key)) continue;
    if (typeof val === "string" && val.includes("..")) {
      return NextResponse.json({ error: `Invalid value in ${key}` }, { status: 400 });
    }
    if (Array.isArray(val)) {
      for (const item of val) {
        if (typeof item === "string" && item.includes("..")) {
          return NextResponse.json({ error: `Invalid value in ${key}` }, { status: 400 });
        }
      }
    }
  }

  // Build CLI args
  const args: string[] = [];

  const strField = (key: string, flag: string) => {
    const val = profile[key];
    if (typeof val === "string" && val.trim()) {
      args.push(flag, val.trim());
    }
  };

  const listField = (key: string, flag: string) => {
    const val = profile[key];
    if (Array.isArray(val) && val.length > 0) {
      args.push(flag, ...val.filter((v: unknown) => typeof v === "string" && v.trim()));
    }
  };

  strField("first_name", "--first-name");
  strField("last_name", "--last-name");
  strField("birth_date", "--birth-date");
  strField("email", "--email");
  strField("city", "--city");
  strField("postal_code", "--postal-code");
  strField("ssid", "--ssid");
  strField("bssid", "--bssid");

  // ISP — validate enum
  const ispVal = profile.isp;
  if (typeof ispVal === "string" && ["orange", "sfr", "bouygues", "free"].includes(ispVal)) {
    args.push("--isp", ispVal);
  }

  listField("keywords", "--keywords");
  listField("old_passwords", "--old-passwords");

  if (webSearch) {
    args.push("--web-search");
  }

  try {
    const { stdout, stderr } = await execFileAsync(PYTHON, [GENERATOR_PATH, ...args], {
      timeout: 120000,  // 2 min for web OSINT
      maxBuffer: 50 * 1024 * 1024,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });

    // The generator writes a wordlist file and outputs stats to stderr/log
    // We need to also run the build_wordlist function via a small wrapper
    // For simplicity, exec with --json flag
    // Since our generator uses save_findings, parse the output

    // Quick approach: re-exec with a JSON wrapper
    const wrapperCode = `
import sys, json, os
sys.path.insert(0, os.path.dirname(${JSON.stringify(GENERATOR_PATH)}))
from smart_wordlist import build_wordlist
profile = json.loads(${JSON.stringify(JSON.stringify(
      Object.fromEntries(
        Object.entries(profile).filter(([k]) => ALLOWED_FIELDS.has(k))
      )
    ))})
result = build_wordlist(profile, web_search=${webSearch ? "True" : "False"})
print(json.dumps(result))
`;

    const { stdout: jsonOut } = await execFileAsync(PYTHON, ["-c", wrapperCode], {
      timeout: 120000,
      maxBuffer: 50 * 1024 * 1024,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });

    const result = JSON.parse(jsonOut.trim());
    return NextResponse.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
