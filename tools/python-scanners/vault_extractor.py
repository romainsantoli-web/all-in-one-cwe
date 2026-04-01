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
    # Auto-detected crypto parameters
    kdf: str = ""           # e.g. "PBKDF2-SHA256", "scrypt", "argon2id"
    iterations: int = 0     # PBKDF2 iterations / scrypt N / argon2 time cost
    kdf_params: str = ""    # Extra params as JSON string (r, p for scrypt, etc.)


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
# Iteration / KDF auto-detection per format
# ---------------------------------------------------------------------------

def _detect_vault_params(filepath: str, format_id: str) -> tuple[str, int, str]:
    """Detect KDF type, iteration count, and extra params from a vault file.

    Returns (kdf_name, iterations, kdf_params_json).
    """
    try:
        if format_id in ("metamask", "vault", "vault-extra"):
            return _detect_metamask_params(filepath)
        elif format_id == "ethereum-keystore":
            return _detect_eth_keystore_params(filepath)
        elif format_id == "keepass":
            return _detect_keepass_params(filepath)
        elif format_id == "1password":
            return _detect_1password_params(filepath)
        elif format_id == "bitwarden":
            return _detect_bitwarden_params(filepath)
        elif format_id == "lastpass":
            return _detect_lastpass_params(filepath)
        elif format_id == "bitcoin-core":
            return _detect_bitcoin_core_params(filepath)
        elif format_id == "electrum":
            return _detect_electrum_params(filepath)
        elif format_id == "ssh":
            return _detect_ssh_params(filepath)
        elif format_id == "7z":
            return _detect_7z_params(filepath)
        elif format_id == "pdf":
            return _detect_pdf_params(filepath)
        elif format_id == "office":
            return _detect_office_params(filepath)
        elif format_id == "dmg":
            return ("PBKDF2-SHA1", 250000, "")
        elif format_id == "veracrypt":
            return ("PBKDF2-SHA512", 500000, json.dumps({"note": "varies by hash algo"}))
        elif format_id in ("zip", "rar"):
            return ("", 0, "")
    except Exception as exc:
        log.debug("Failed to detect params for %s (%s): %s", filepath, format_id, exc)
    return ("", 0, "")


def _detect_metamask_params(filepath: str) -> tuple[str, int, str]:
    """Detect MetaMask vault iterations from JSON vault file."""
    text = _read_text(filepath, 8192)
    if not text.strip():
        return ("PBKDF2-SHA256", 600000, json.dumps({"note": "LevelDB, needs extraction"}))
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Might be a LevelDB directory or non-JSON file
        if os.path.isdir(filepath):
            return ("PBKDF2-SHA256", 600000, json.dumps({"note": "LevelDB vault"}))
        return ("PBKDF2-SHA256", 600000, "")

    # MetaMask vault JSON: { data, iv, salt, iterations?, keyMetadata? }
    iterations = 10000  # Legacy default
    if "iterations" in data:
        iterations = int(data["iterations"])
    elif "keyMetadata" in data and isinstance(data.get("keyMetadata"), dict):
        params = data["keyMetadata"].get("params", {})
        if "iterations" in params:
            iterations = int(params["iterations"])

    is_legacy = iterations <= 10000
    return ("PBKDF2-SHA256", iterations, json.dumps({"legacy": is_legacy}))


def _detect_eth_keystore_params(filepath: str) -> tuple[str, int, str]:
    """Detect Ethereum keystore v3 params (scrypt or PBKDF2)."""
    text = _read_text(filepath, 4096)
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return ("", 0, "")

    crypto_block = data.get("crypto") or data.get("Crypto") or {}
    kdf_name = crypto_block.get("kdf", "")
    kdf_params = crypto_block.get("kdfparams", {})

    if kdf_name == "scrypt":
        n = kdf_params.get("n", 262144)
        r = kdf_params.get("r", 8)
        p = kdf_params.get("p", 1)
        return ("scrypt", n, json.dumps({"r": r, "p": p, "dklen": kdf_params.get("dklen", 32)}))
    elif kdf_name == "pbkdf2":
        c = kdf_params.get("c", 262144)
        prf = kdf_params.get("prf", "hmac-sha256")
        return (f"PBKDF2-{prf.split('-')[-1].upper()}", c, json.dumps({"dklen": kdf_params.get("dklen", 32)}))
    return ("", 0, "")


def _detect_keepass_params(filepath: str) -> tuple[str, int, str]:
    """Detect KeePass KDBX version and KDF params from file header."""
    head = _read_head(filepath, 2048)
    if len(head) < 12:
        return ("", 0, "")

    # KDBX magic: 0x9AA2D903 0xB54BFB67
    sig1 = struct.unpack("<I", head[0:4])[0] if len(head) >= 4 else 0
    sig2 = struct.unpack("<I", head[4:8])[0] if len(head) >= 8 else 0
    if sig1 != 0x9AA2D903 or sig2 != 0xB54BFB67:
        return ("AES-KDF", 60000, json.dumps({"note": "KDB format assumed"}))

    # Version field
    minor = struct.unpack("<H", head[8:10])[0] if len(head) >= 10 else 0
    major = struct.unpack("<H", head[10:12])[0] if len(head) >= 12 else 0

    if major >= 4:
        # KDBX 4.x — likely Argon2
        # The actual params are in the KDF header field, complex to parse
        return ("Argon2d/id", 0, json.dumps({"kdbx_version": f"{major}.{minor}", "note": "Argon2 params in header"}))
    else:
        # KDBX 3.x — AES-KDF with transform rounds
        # Rounds are at TLV offset; default is 60000 for older, 600000+ for newer
        # The transform rounds are stored in a TLV header field (ID=6, type uint64)
        rounds = _parse_kdbx3_rounds(head)
        return ("AES-KDF", rounds, json.dumps({"kdbx_version": f"{major}.{minor}"}))


def _parse_kdbx3_rounds(head: bytes) -> int:
    """Parse KDBX3 header TLV to find transform rounds (field ID 6)."""
    offset = 12  # After the 12-byte signature+version
    while offset < len(head) - 3:
        field_id = head[offset]
        field_size = struct.unpack("<H", head[offset + 1:offset + 3])[0] if offset + 3 <= len(head) else 0
        offset += 3
        if field_id == 6 and field_size == 8 and offset + 8 <= len(head):
            return struct.unpack("<Q", head[offset:offset + 8])[0]
        offset += field_size
        if field_id == 0:  # End of header
            break
    return 60000  # Fallback


def _detect_1password_params(filepath: str) -> tuple[str, int, str]:
    """Detect 1Password OPVault profile.js iterations."""
    target = filepath
    if os.path.isdir(filepath):
        candidate = os.path.join(filepath, "default", "profile.js")
        if os.path.isfile(candidate):
            target = candidate
        else:
            return ("PBKDF2-SHA512", 100000, "")
    text = _read_text(target, 8192)
    try:
        json_match = text[text.index("{"):text.rindex("}") + 1]
        data = json.loads(json_match)
        iterations = data.get("iterations", 100000)
        return ("PBKDF2-SHA512", iterations, "")
    except (ValueError, json.JSONDecodeError):
        return ("PBKDF2-SHA512", 100000, "")


def _detect_bitwarden_params(filepath: str) -> tuple[str, int, str]:
    """Detect Bitwarden vault KDF type and iterations."""
    text = _read_text(filepath, 16384)
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return ("PBKDF2-SHA256", 600000, "")

    kdf_type = data.get("kdfType", data.get("kdf", 0))
    iterations = data.get("kdfIterations", data.get("iterations", 600000))
    kdf_memory = data.get("kdfMemory")
    kdf_parallelism = data.get("kdfParallelism")

    if kdf_type == 1:  # Argon2id
        return ("Argon2id", iterations, json.dumps({"memory": kdf_memory, "parallelism": kdf_parallelism}))
    return ("PBKDF2-SHA256", iterations, "")


def _detect_lastpass_params(filepath: str) -> tuple[str, int, str]:
    """Detect LastPass iteration count."""
    # LastPass uses PBKDF2-SHA256 with configurable iterations (default 100100)
    text = _read_text(filepath, 4096)
    try:
        data = json.loads(text)
        iterations = data.get("iterations", data.get("iteration_count", 100100))
        return ("PBKDF2-SHA256", iterations, "")
    except (json.JSONDecodeError, ValueError):
        return ("PBKDF2-SHA256", 100100, "")


def _detect_bitcoin_core_params(filepath: str) -> tuple[str, int, str]:
    """Detect Bitcoin Core wallet.dat params."""
    head = _read_head(filepath, 8192)
    if b"mkey" not in head:
        return ("", 0, "")
    # Bitcoin Core uses Berkeley DB; the mkey record contains:
    # derivation_method (uint32), rounds (uint32)
    idx = head.find(b"mkey")
    if idx >= 0 and idx + 80 <= len(head):
        # After mkey: encrypted_key(48) + salt(8) + derivation_method(4) + rounds(4)
        try:
            offset = idx + 4  # after "mkey"
            # Skip key length prefix + encrypted key + salt
            # The structure varies; try finding rounds after salt
            # Default Bitcoin Core: SHA512, 25000 rounds (newer) or 1049 (older)
            return ("SHA512", 25000, json.dumps({"note": "default; actual rounds in mkey record"}))
        except Exception:
            pass
    return ("SHA512", 25000, "")


def _detect_electrum_params(filepath: str) -> tuple[str, int, str]:
    """Detect Electrum wallet version and iterations."""
    text = _read_text(filepath, 512)
    if not text.strip():
        return ("", 0, "")

    # Electrum 2.x+: JSON with "wallet_type" — uses PBKDF2-SHA512, 1024 rounds
    # Electrum 4.x: AES-256-GCM with PBKDF2-HMAC-SHA512
    try:
        data = json.loads(text)
        if "keystore" in data:
            return ("PBKDF2-SHA512", 1024, json.dumps({"version": 2}))
    except (json.JSONDecodeError, ValueError):
        pass
    # Old Electrum 1.x: first line is a hex-encoded encrypted blob
    if all(c in "0123456789abcdef" for c in text[:64]):
        return ("PBKDF2-SHA256", 1024, json.dumps({"version": 1}))
    return ("PBKDF2-SHA512", 1024, "")


def _detect_ssh_params(filepath: str) -> tuple[str, int, str]:
    """Detect SSH key encryption params."""
    text = _read_text(filepath, 2048)
    if "OPENSSH PRIVATE KEY" in text:
        # OpenSSH format: bcrypt KDF with 16 rounds
        return ("bcrypt", 16, "")
    elif "ENCRYPTED" in text:
        # Legacy PEM: no KDF iteration, single DES/3DES/AES pass
        if "AES-256" in text:
            return ("AES-256-CBC", 1, json.dumps({"note": "PEM legacy, single pass"}))
        elif "AES-128" in text:
            return ("AES-128-CBC", 1, json.dumps({"note": "PEM legacy, single pass"}))
        elif "DES-EDE3" in text:
            return ("3DES-CBC", 1, json.dumps({"note": "PEM legacy, weak"}))
    return ("", 0, "")


def _detect_7z_params(filepath: str) -> tuple[str, int, str]:
    """Detect 7-Zip encryption params from header."""
    head = _read_head(filepath, 64)
    # 7z magic: 37 7A BC AF 27 1C
    if len(head) >= 6 and head[:6] == b"7z\xbc\xaf\x27\x1c":
        # 7z uses AES-256-SHA-256, iterations = 2^numCyclesPower (default 19 = 524288)
        return ("AES-256-SHA256", 524288, json.dumps({"note": "2^19 default, actual in header"}))
    return ("", 0, "")


def _detect_pdf_params(filepath: str) -> tuple[str, int, str]:
    """Detect PDF encryption revision."""
    text = _read_text(filepath, 4096)
    if "/Encrypt" not in text:
        return ("", 0, "")
    # PDF revisions: R2 (40-bit RC4), R3 (128-bit RC4), R4 (128-bit AES), R5/R6 (256-bit AES)
    import re
    rev_match = re.search(r"/R\s*(\d+)", text)
    rev = int(rev_match.group(1)) if rev_match else 0
    if rev >= 6:
        return ("AES-256", 0, json.dumps({"revision": rev, "note": "PDF 2.0, no iterations"}))
    elif rev >= 4:
        return ("AES-128-CBC", 0, json.dumps({"revision": rev}))
    elif rev >= 3:
        return ("RC4-128", 0, json.dumps({"revision": rev}))
    return ("RC4-40", 0, json.dumps({"revision": rev}))


def _detect_office_params(filepath: str) -> tuple[str, int, str]:
    """Detect MS Office encryption (OOXML)."""
    try:
        import zipfile
        with zipfile.ZipFile(filepath, "r") as zf:
            if "EncryptionInfo" in zf.namelist():
                data = zf.read("EncryptionInfo")
                # Office 2013+: SHA512, 100000 rounds ; Office 2010: SHA1, 100000
                if b"SHA512" in data:
                    return ("SHA512", 100000, json.dumps({"version": "2013+"}))
                elif b"SHA1" in data or b"SHA-1" in data:
                    return ("SHA1", 100000, json.dumps({"version": "2010"}))
                return ("SHA512", 100000, json.dumps({"version": "unknown"}))
    except Exception:
        pass
    return ("SHA512", 100000, "")


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
                            **dict(zip(("kdf", "iterations", "kdf_params"),
                                       _detect_vault_params(match, fmt.id))),
                        ))
                        log.info("Found: %s — %s (%d bytes, encrypted=%s)",
                                 fmt.name, match, size, encrypted)
            else:
                # Directory itself is the target (e.g., LevelDB)
                if os.path.isdir(base_path):
                    size, modified = _file_stat(base_path)
                    kdf, iters, kdf_p = _detect_vault_params(base_path, fmt.id)
                    results.append(ExtractLocation(
                        format_id=fmt.id,
                        format_name=fmt.name,
                        category=fmt.category,
                        file_path=base_path,
                        size=size,
                        modified=modified,
                        encrypted=True,
                        note=fmt.note,
                        kdf=kdf,
                        iterations=iters,
                        kdf_params=kdf_p,
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
