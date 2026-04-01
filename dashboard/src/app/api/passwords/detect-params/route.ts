// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import { promisify } from "util";
import { existsSync } from "fs";
import path from "path";
import os from "os";

export const dynamic = "force-dynamic";

const execFileAsync = promisify(execFile);

const PYTHON = process.env.PYTHON_BIN || "python3";

function hasTraversal(val: string): boolean {
  return val.includes("..") || val.includes("\0");
}

function sanitizePath(raw: string): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  if (!trimmed || hasTraversal(trimmed)) return null;
  const resolved = path.resolve(trimmed);
  const home = os.homedir();
  if (!resolved.startsWith(home) && !resolved.startsWith("/tmp")) return null;
  return resolved;
}

/**
 * POST /api/passwords/detect-params
 * Body: { file_path: string }
 * Returns: { format_id, format_name, kdf, iterations, kdf_params, encrypted }
 */
export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const filePath = sanitizePath(body.file_path as string ?? "");
  if (!filePath) {
    return NextResponse.json({ error: "Invalid or missing file_path" }, { status: 400 });
  }
  if (!existsSync(filePath)) {
    return NextResponse.json({ error: "File not found" }, { status: 404 });
  }

  // Use a small inline Python script to detect params via vault_extractor
  const scriptPath = path.resolve(process.cwd(), "..", "tools", "python-scanners");
  const detectCode = `
import sys, json, os
sys.path.insert(0, ${JSON.stringify(scriptPath)})
from vault_extractor import _detect_vault_params, _get_format_defs, _read_head, _read_text

file_path = ${JSON.stringify(filePath)}

# Try to auto-detect format
format_id = ""
format_name = ""
defs = _get_format_defs()

for fmt in defs:
    if fmt.file_patterns:
        import fnmatch
        basename = os.path.basename(file_path)
        for pat in fmt.file_patterns:
            if fnmatch.fnmatch(basename, pat) or fnmatch.fnmatch(basename.lower(), pat.lower()):
                format_id = fmt.id
                format_name = fmt.name
                break
    if format_id:
        break

# Fallback: detect by extension
if not format_id:
    ext = os.path.splitext(file_path)[1].lower()
    ext_map = {
        ".kdbx": ("keepass", "KeePass"),
        ".kdb": ("keepass", "KeePass"),
        ".opvault": ("1password", "1Password"),
        ".json": ("metamask", "MetaMask/Vault"),
        ".vault": ("vault", "Vault File"),
        ".7z": ("7z", "7-Zip"),
        ".pdf": ("pdf", "PDF"),
        ".docx": ("office", "MS Office"),
        ".xlsx": ("office", "MS Office"),
        ".pptx": ("office", "MS Office"),
        ".dmg": ("dmg", "Encrypted DMG"),
        ".hc": ("veracrypt", "VeraCrypt"),
        ".tc": ("veracrypt", "VeraCrypt"),
        ".zip": ("zip", "ZIP"),
        ".rar": ("rar", "RAR"),
    }
    if ext in ext_map:
        format_id, format_name = ext_map[ext]

# Detect by content for keystore/ssh
if not format_id:
    text = _read_text(file_path, 1024)
    if '"crypto"' in text.lower() or '"kdf"' in text.lower():
        format_id, format_name = "ethereum-keystore", "Ethereum Keystore"
    elif "PRIVATE KEY" in text:
        format_id, format_name = "ssh", "SSH Key"

if format_id:
    kdf, iterations, kdf_params = _detect_vault_params(file_path, format_id)
    print(json.dumps({
        "format_id": format_id,
        "format_name": format_name,
        "kdf": kdf,
        "iterations": iterations,
        "kdf_params": kdf_params,
        "encrypted": True,
    }))
else:
    print(json.dumps({
        "format_id": "unknown",
        "format_name": "Unknown Format",
        "kdf": "",
        "iterations": 0,
        "kdf_params": "",
        "encrypted": False,
    }))
`;

  try {
    const { stdout } = await execFileAsync(PYTHON, ["-c", detectCode], {
      timeout: 10000,
      maxBuffer: 1 * 1024 * 1024,
      env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
    });

    const result = JSON.parse(stdout.trim());
    return NextResponse.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
