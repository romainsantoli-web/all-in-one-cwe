#!/usr/bin/env python3
"""Vault Extractor — Auto-detect and extract encrypted vault files.

Scans known paths for:
  - Crypto wallets (MetaMask, Electrum, Exodus, Bitcoin Core, Ethereum keystore)
  - Password managers (KeePass, 1Password, Bitwarden, LastPass)
  - Encrypted archives (ZIP, RAR, 7z, DMG, VeraCrypt, LUKS)
  - SSH keys, PDF, Office docs
  - .vault files (custom format)

Ported from: metamask-recovery-v4/packages/crackers/src/extractor.ts

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import glob
import json
import os
import struct
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable

sys.path.insert(0, os.path.dirname(__file__))

from lib import Finding, log, parse_base_args, save_findings

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class ExtractLocation:
    format_id: str
    format_name: str
    category: str  # wallet | password-manager | archive | document | disk | network | mobile
    file_path: str
    size: int = 0
    modified: str = ""
    encrypted: bool = False
    note: str = ""


@dataclass
class FormatDef:
    id: str
    name: str
    category: str
    paths: list[str] = field(default_factory=list)
    file_patterns: list[str] = field(default_factory=list)
    is_encrypted: Callable[[str], bool] | None = None
    note: str = ""


# ---------------------------------------------------------------------------
# Path definitions (macOS + Linux)
# ---------------------------------------------------------------------------

HOME = os.path.expanduser("~")
PLATFORM = sys.platform  # darwin, linux, win32

def _get_format_defs() -> list[FormatDef]:
    """Build format definitions for current platform."""
    defs: list[FormatDef] = []

    # ── Crypto Wallets ──
    mm_ext_ids = [
        "nkbihfbeogaeaoehlefnkodbefgpgknn",  # Chrome Web Store
        "ejbalbakoplchlghecdalmeeeajnimhm",  # Flask (dev)
    ]
    mm_paths = []
    for ext_id in mm_ext_ids:
        if PLATFORM == "darwin":
            mm_paths.extend([
                f"{HOME}/Library/Application Support/Google/Chrome/Default/Local Extension Settings/{ext_id}",
                f"{HOME}/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Extension Settings/{ext_id}",
                f"{HOME}/Library/Application Support/Microsoft Edge/Default/Local Extension Settings/{ext_id}",
                f"{HOME}/Library/Application Support/Vivaldi/Default/Local Extension Settings/{ext_id}",
            ])
        else:
            mm_paths.extend([
                f"{HOME}/.config/google-chrome/Default/Local Extension Settings/{ext_id}",
                f"{HOME}/.config/BraveSoftware/Brave-Browser/Default/Local Extension Settings/{ext_id}",
            ])
    defs.append(FormatDef("metamask", "MetaMask", "wallet", mm_paths, note="LevelDB vault"))

    btc_paths = ([f"{HOME}/Library/Application Support/Bitcoin"] if PLATFORM == "darwin"
                 else [f"{HOME}/.bitcoin"])
    defs.append(FormatDef("bitcoin-core", "Bitcoin Core", "wallet", btc_paths,
                          ["wallet.dat", "wallets/*/wallet.dat"],
                          lambda fp: b"mkey" in _read_head(fp, 4096)))

    eth_paths = ([f"{HOME}/Library/Ethereum/keystore"] if PLATFORM == "darwin"
                 else [f"{HOME}/.ethereum/keystore"])
    defs.append(FormatDef("ethereum-keystore", "Ethereum (Geth)", "wallet", eth_paths,
                          ["UTC--*", "*.json"],
                          lambda fp: '"crypto"' in _read_text(fp, 1024).lower()))

    elec_paths = [f"{HOME}/.electrum/wallets"]
    defs.append(FormatDef("electrum", "Electrum", "wallet", elec_paths, ["default_wallet", "*"]))

    exo_paths = ([f"{HOME}/Library/Application Support/Exodus/exodus.wallet"] if PLATFORM == "darwin"
                 else [f"{HOME}/.config/Exodus/exodus.wallet"])
    defs.append(FormatDef("exodus", "Exodus", "wallet", exo_paths, ["seed.seco", "*.seco"]))

    sol_paths = [f"{HOME}/.config/solana"]
    defs.append(FormatDef("multicoin", "Solana CLI", "wallet", sol_paths, ["id.json", "*.json"]))

    # ── Password Managers ──
    kp_paths = [f"{HOME}/Documents", f"{HOME}/Desktop", f"{HOME}/Downloads"]
    if PLATFORM == "darwin":
        kp_paths.append(f"{HOME}/Library/Application Support/KeePassXC")
    else:
        kp_paths.append(f"{HOME}/.config/keepassxc")
    defs.append(FormatDef("keepass", "KeePass / KeePassXC", "password-manager", kp_paths, ["*.kdbx", "*.kdb"]))

    bw_paths = ([f"{HOME}/Library/Application Support/Bitwarden", f"{HOME}/Downloads"]
                if PLATFORM == "darwin"
                else [f"{HOME}/.config/Bitwarden", f"{HOME}/Downloads"])
    defs.append(FormatDef("bitwarden", "Bitwarden", "password-manager", bw_paths,
                          ["bitwarden_export*.json", "bitwarden_encrypted_export*.json"]))

    lp_paths = ([f"{HOME}/Library/Application Support/LastPass"] if PLATFORM == "darwin"
                else [f"{HOME}/.config/lastpass"])
    defs.append(FormatDef("lastpass", "LastPass", "password-manager", lp_paths,
                          ["*.lpdata", "lastpass_vault*"]))

    op_paths = ([f"{HOME}/Library/Group Containers/2BUA8C4S2C.com.1password",
                 f"{HOME}/Library/Application Support/1Password"] if PLATFORM == "darwin"
                else [f"{HOME}/.config/1Password"])
    defs.append(FormatDef("1password", "1Password", "password-manager", op_paths,
                          ["*.opvault", "*.agilekeychain", "data.sqlite"]))

    # ── SSH Keys ──
    ssh_paths = [f"{HOME}/.ssh"]
    defs.append(FormatDef("ssh", "SSH Private Keys", "network", ssh_paths,
                          ["id_rsa", "id_ed25519", "id_ecdsa", "*.pem"],
                          lambda fp: "ENCRYPTED" in _read_text(fp, 512)))

    # ── Archives ──
    archive_dirs = [f"{HOME}/Downloads", f"{HOME}/Desktop", f"{HOME}/Documents"]
    defs.append(FormatDef("zip", "Encrypted ZIP", "archive", archive_dirs,
                          ["*.zip"], lambda fp: _zip_encrypted(fp)))
    defs.append(FormatDef("rar", "Encrypted RAR", "archive", archive_dirs, ["*.rar"]))
    defs.append(FormatDef("7z", "Encrypted 7-Zip", "archive", archive_dirs, ["*.7z"]))

    # ── Documents ──
    defs.append(FormatDef("pdf", "Password-protected PDF", "document", archive_dirs,
                          ["*.pdf"], lambda fp: b"/Encrypt" in _read_head(fp, 4096)))
    defs.append(FormatDef("office", "Encrypted Office", "document", archive_dirs,
                          ["*.docx", "*.xlsx", "*.pptx"]))

    # ── Disk Encryption ──
    defs.append(FormatDef("veracrypt", "VeraCrypt Container", "disk",
                          [f"{HOME}/Documents", f"{HOME}/Desktop"],
                          ["*.hc", "*.tc"]))
    if PLATFORM == "darwin":
        defs.append(FormatDef("dmg", "Encrypted DMG", "disk",
                              [f"{HOME}/Downloads", f"{HOME}/Desktop"],
                              ["*.dmg"]))

    # ── .vault files (custom/generic) ──
    vault_dirs = [
        f"{HOME}/Documents", f"{HOME}/Desktop", f"{HOME}/Downloads",
        f"{HOME}/.local/share", f"{HOME}/.config",
    ]
    defs.append(FormatDef("vault", "Vault File (.vault)", "wallet", vault_dirs,
                          ["*.vault", "vault.json", "*.vault.json"],
                          note="MetaMask / custom encrypted vault"))
    return defs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_head(filepath: str, n: int) -> bytes:
    """Read first n bytes of a file safely."""
    try:
        with open(filepath, "rb") as f:
            return f.read(n)
    except (OSError, PermissionError):
        return b""


def _read_text(filepath: str, n: int) -> str:
    """Read first n bytes as text safely."""
    try:
        with open(filepath, "r", errors="replace") as f:
            return f.read(n)
    except (OSError, PermissionError):
        return ""


def _zip_encrypted(filepath: str) -> bool:
    """Check if a ZIP file has encrypted entries."""
    try:
        import zipfile
        with zipfile.ZipFile(filepath, "r") as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    return True
    except Exception:
        pass
    return False


def _file_stat(filepath: str) -> tuple[int, str]:
    """Return (size_bytes, modified_iso)."""
    try:
        st = os.stat(filepath)
        return st.st_size, datetime.fromtimestamp(st.st_mtime).isoformat()
    except OSError:
        return 0, ""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_formats(
    extra_dirs: list[str] | None = None,
    include_categories: list[str] | None = None,
    dry_run: bool = False,
) -> list[ExtractLocation]:
    """Scan all known paths for encrypted files."""
    results: list[ExtractLocation] = []
    defs = _get_format_defs()

    # Add extra search directories for .vault files
    if extra_dirs:
        vault_def = FormatDef("vault-extra", "Vault File (extra)", "wallet",
                              extra_dirs, ["*.vault", "vault.json", "*.vault.json"])
        defs.append(vault_def)

    for fmt in defs:
        if include_categories and fmt.category not in include_categories:
            continue

        for base_path in fmt.paths:
            if not os.path.exists(base_path):
                continue

            if fmt.file_patterns:
                for pattern in fmt.file_patterns:
                    matches = glob.glob(os.path.join(base_path, pattern), recursive=False)
                    for match in matches:
                        if not os.path.isfile(match):
                            continue
                        size, modified = _file_stat(match)
                        encrypted = True
                        if fmt.is_encrypted:
                            try:
                                encrypted = fmt.is_encrypted(match)
                            except Exception:
                                encrypted = False

                        if dry_run:
                            log.info("[DRY-RUN] Found: %s (%s)", match, fmt.name)
                            continue

                        results.append(ExtractLocation(
                            format_id=fmt.id,
                            format_name=fmt.name,
                            category=fmt.category,
                            file_path=match,
                            size=size,
                            modified=modified,
                            encrypted=encrypted,
                            note=fmt.note,
                        ))
                        log.info("Found: %s — %s (%d bytes, encrypted=%s)",
                                 fmt.name, match, size, encrypted)
            else:
                # Directory itself is the target (e.g., LevelDB)
                if os.path.isdir(base_path):
                    size, modified = _file_stat(base_path)
                    results.append(ExtractLocation(
                        format_id=fmt.id,
                        format_name=fmt.name,
                        category=fmt.category,
                        file_path=base_path,
                        size=size,
                        modified=modified,
                        encrypted=True,
                        note=fmt.note,
                    ))
                    log.info("Found dir: %s — %s", fmt.name, base_path)

    return results


def parse_vault_json(json_string: str) -> dict:
    """Parse a MetaMask vault JSON into structured data."""
    LEGACY_ITERATIONS = 10_000

    raw = json.loads(json_string)
    if not all(k in raw for k in ("data", "iv", "salt")):
        raise ValueError("Invalid vault JSON: missing data, iv, or salt")

    root_iter = raw.get("iterations")
    meta_iter = None
    if "keyMetadata" in raw and "params" in raw["keyMetadata"]:
        meta_iter = raw["keyMetadata"]["params"].get("iterations")

    iterations = root_iter or meta_iter or LEGACY_ITERATIONS
    return {
        "data": raw["data"],
        "iv": raw["iv"],
        "salt": raw["salt"],
        "iterations": iterations,
        "is_legacy": iterations <= LEGACY_ITERATIONS,
    }


# ---------------------------------------------------------------------------
# CLI main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--extra-dirs", nargs="*", default=[],
                        help="Additional directories to scan for .vault files")
    parser.add_argument("--categories", nargs="*", default=None,
                        help="Filter by category: wallet, password-manager, archive, document, disk, network")
    parser.add_argument("--vault-json", type=str, default=None,
                        help="Path to a .vault JSON file to parse directly")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON array to stdout")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    log.info("=" * 60)
    log.info("Vault Extractor — Encrypted File Scanner")
    log.info("=" * 60)

    findings: list[Finding] = []

    # Direct vault parsing
    if args.vault_json:
        json_path = os.path.abspath(args.vault_json)
        if ".." in os.path.relpath(json_path):
            log.error("Path traversal blocked")
            sys.exit(1)
        try:
            with open(json_path, "r") as f:
                vault = parse_vault_json(f.read())
            log.info("Vault parsed: iterations=%d, legacy=%s", vault["iterations"], vault["is_legacy"])
            findings.append(Finding(
                title=f"Vault extracted: {os.path.basename(json_path)}",
                severity="info",
                cwe="CWE-312",
                endpoint=json_path,
                method="LOCAL",
                description=(
                    f"Encrypted vault extracted. Iterations: {vault['iterations']}. "
                    f"Legacy: {vault['is_legacy']}."
                ),
                evidence={"iterations": vault["iterations"], "is_legacy": vault["is_legacy"]},
            ))
        except Exception as exc:
            log.error("Failed to parse vault: %s", exc)

    # Scan filesystem
    results = scan_formats(
        extra_dirs=args.extra_dirs if args.extra_dirs else None,
        include_categories=args.categories,
        dry_run=args.dry_run,
    )

    for loc in results:
        findings.append(Finding(
            title=f"Encrypted file found: {loc.format_name}",
            severity="info",
            cwe="CWE-312",
            endpoint=loc.file_path,
            method="LOCAL",
            description=(
                f"{loc.format_name} ({loc.category}) at {loc.file_path}. "
                f"Size: {loc.size} bytes. Encrypted: {loc.encrypted}."
            ),
            evidence=asdict(loc),
        ))

    log.info("=" * 60)
    log.info("Total found: %d encrypted files", len(results))
    log.info("=" * 60)

    if getattr(args, "json", False):
        import json as _json
        print(_json.dumps([asdict(loc) for loc in results], default=str))
        return

    report_dir = getattr(args, "report_dir", "reports")
    save_findings(findings, "vault-extractor", report_dir)


if __name__ == "__main__":
    main()
