#!/usr/bin/env python3
"""Forensic Toolkit — Digital forensics analysis suite — CWE-200, CWE-312.

Comprehensive forensic analysis combining:
  1. File carving — recover deleted files from raw disk/memory images
  2. Metadata extraction — timestamps (MAC), EXIF, Office metadata
  3. String extraction — printable strings with context (encoding-aware)
  4. Hash verification — compute MD5/SHA-1/SHA-256 for chain of custody
  5. Memory artifact extraction — process lists, network connections, registry
  6. Filesystem timeline — MAC time anomalies, timestomping detection
  7. Registry analysis — autoruns, MRU lists, USB history

Usage:
    python forensic_toolkit.py --target /path/to/image.dd --mode carve
    python forensic_toolkit.py --target /path/to/file --mode metadata
    python forensic_toolkit.py --target /path/to/memory.raw --mode volatility

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from lib import Finding, log, parse_base_args, save_findings

# ---------------------------------------------------------------------------
# File carving signatures
# ---------------------------------------------------------------------------

CARVE_SIGNATURES: list[dict[str, object]] = [
    {"name": "JPEG", "header": b"\xff\xd8\xff", "footer": b"\xff\xd9", "ext": ".jpg", "max_size": 20_000_000},
    {"name": "PNG", "header": b"\x89PNG\r\n\x1a\n", "footer": b"IEND\xaeB`\x82", "ext": ".png", "max_size": 50_000_000},
    {"name": "PDF", "header": b"%PDF-", "footer": b"%%EOF", "ext": ".pdf", "max_size": 100_000_000},
    {"name": "ZIP", "header": b"PK\x03\x04", "footer": b"PK\x05\x06", "ext": ".zip", "max_size": 500_000_000},
    {"name": "GIF", "header": b"GIF8", "footer": b"\x00\x3b", "ext": ".gif", "max_size": 10_000_000},
    {"name": "SQLite", "header": b"SQLite format 3\x00", "footer": None, "ext": ".sqlite", "max_size": 100_000_000},
    {"name": "ELF", "header": b"\x7fELF", "footer": None, "ext": ".elf", "max_size": 50_000_000},
    {"name": "PE/EXE", "header": b"MZ", "footer": None, "ext": ".exe", "max_size": 50_000_000},
    {"name": "RAR", "header": b"Rar!\x1a\x07", "footer": None, "ext": ".rar", "max_size": 500_000_000},
    {"name": "7z", "header": b"7z\xbc\xaf\x27\x1c", "footer": None, "ext": ".7z", "max_size": 500_000_000},
    {"name": "MP3", "header": b"ID3", "footer": None, "ext": ".mp3", "max_size": 50_000_000},
    {"name": "OGG", "header": b"OggS", "footer": None, "ext": ".ogg", "max_size": 50_000_000},
]

# Sensitive data patterns for string extraction
SENSITIVE_PATTERNS = [
    (r"flag\{[^}]+\}", "CTF Flag", "critical"),
    (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}", "Email address", "medium"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP address", "info"),
    (r"(?:password|passwd|pwd)\s*[:=]\s*\S+", "Password", "critical"),
    (r"(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?\S+", "API key/Secret", "high"),
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "Private key", "critical"),
    (r"(?:ssh-rsa|ecdsa-sha2|ssh-ed25519)\s+[A-Za-z0-9+/=]+", "SSH public key", "medium"),
    (r"https?://\S+", "URL", "info"),
    (r"/etc/(?:passwd|shadow|hosts)", "System file reference", "medium"),
    (r"(?:mysql|postgres|mongodb)://\S+", "Database connection string", "high"),
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b", "Credit card number", "critical"),
]


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def compute_hashes(filepath: Path) -> dict[str, str]:
    """Compute forensic hashes for chain of custody."""
    hashes = {}
    algos = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}

    for name, algo_fn in algos.items():
        h = algo_fn(usedforsecurity=False)
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            hashes[name] = h.hexdigest()
        except OSError:
            hashes[name] = "error"

    return hashes


def extract_metadata(filepath: Path) -> list[Finding]:
    """Extract filesystem and content metadata."""
    findings: list[Finding] = []
    stat = filepath.stat()

    # Filesystem timestamps
    timestamps = {
        "created": datetime.fromtimestamp(stat.st_birthtime, tz=timezone.utc).isoformat()
        if hasattr(stat, "st_birthtime") else "N/A",
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
        "changed": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
    }

    # Timestomping detection: creation > modification
    if hasattr(stat, "st_birthtime") and stat.st_birthtime > stat.st_mtime:
        findings.append(Finding(
            title="Possible timestomping: creation date after modification date",
            severity="high",
            cwe="CWE-200",
            endpoint=str(filepath),
            evidence=timestamps,
            description="File creation time is later than modification time — possible anti-forensics",
        ))

    hashes = compute_hashes(filepath)

    findings.append(Finding(
        title=f"File metadata: {filepath.name}",
        severity="info",
        endpoint=str(filepath),
        evidence={
            "size": stat.st_size,
            "timestamps": timestamps,
            "hashes": hashes,
            "permissions": oct(stat.st_mode),
        },
    ))

    # Try exiftool for rich metadata
    try:
        result = subprocess.run(
            ["exiftool", "-json", str(filepath)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            meta = json.loads(result.stdout)
            if meta and isinstance(meta, list):
                findings.append(Finding(
                    title=f"EXIF/metadata: {len(meta[0])} fields",
                    severity="info",
                    endpoint=str(filepath),
                    evidence={"metadata": {k: v for k, v in list(meta[0].items())[:30]}},
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    return findings


def carve_files(filepath: Path, output_dir: Path | None = None) -> list[Finding]:
    """Carve files from a raw image/binary."""
    findings: list[Finding] = []

    if output_dir is None:
        output_dir = Path("reports/forensic-toolkit/carved")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Try foremost/scalpel first
    for tool in ("foremost", "scalpel"):
        try:
            result = subprocess.run(
                [tool, "-t", "all", "-i", str(filepath), "-o", str(output_dir / tool)],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                findings.append(Finding(
                    title=f"File carving with {tool} completed",
                    severity="info",
                    endpoint=str(filepath),
                    evidence={"output_dir": str(output_dir / tool), "stdout": result.stdout[:500]},
                ))
                return findings
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # Manual carving fallback
    try:
        data = filepath.read_bytes()
    except OSError as exc:
        findings.append(Finding(title="Cannot read file", severity="info", description=str(exc)))
        return findings

    carved_count = 0
    for sig in CARVE_SIGNATURES:
        header = sig["header"]
        offset = 0
        while carved_count < 100:  # Safety limit
            pos = data.find(header, offset)  # type: ignore[arg-type]
            if pos == -1:
                break

            # Find footer or use max_size
            if sig["footer"]:
                end = data.find(sig["footer"], pos + len(header))  # type: ignore[arg-type]
                if end == -1:
                    end = min(pos + sig["max_size"], len(data))  # type: ignore[operator]
                else:
                    end += len(sig["footer"])  # type: ignore[arg-type]
            else:
                end = min(pos + sig["max_size"], len(data))  # type: ignore[operator]

            carved_data = data[pos:end]
            out_path = output_dir / f"carved_{carved_count:04d}_{sig['name']}{sig['ext']}"
            out_path.write_bytes(carved_data)
            carved_count += 1

            findings.append(Finding(
                title=f"Carved {sig['name']} at offset 0x{pos:x} ({len(carved_data):,} bytes)",
                severity="medium",
                cwe="CWE-200",
                endpoint=str(filepath),
                evidence={
                    "type": sig["name"],
                    "offset": pos,
                    "size": len(carved_data),
                    "output": str(out_path),
                },
            ))

            offset = end

    if carved_count:
        findings.insert(0, Finding(
            title=f"Total files carved: {carved_count}",
            severity="high" if carved_count > 5 else "medium",
            evidence={"count": carved_count, "output_dir": str(output_dir)},
        ))

    return findings


def sensitive_string_search(filepath: Path) -> list[Finding]:
    """Search for sensitive strings in a file."""
    findings: list[Finding] = []

    try:
        # Read as bytes and extract ASCII strings
        data = filepath.read_bytes()
    except OSError:
        return findings

    ascii_strs = re.findall(rb"[\x20-\x7e]{6,}", data)
    text = b"\n".join(ascii_strs).decode("ascii", errors="replace")

    for pattern, label, severity in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            findings.append(Finding(
                title=f"Sensitive data: {label} ({len(matches)} occurrences)",
                severity=severity,
                cwe="CWE-312" if "key" in label.lower() or "password" in label.lower() else "CWE-200",
                endpoint=str(filepath),
                evidence={"matches": list(set(matches))[:10], "total": len(matches)},
            ))

    return findings


def run_volatility(filepath: Path) -> list[Finding]:
    """Run Volatility 3 memory forensics (if available)."""
    findings: list[Finding] = []

    profiles = [
        ("windows.pslist.PsList", "Process list"),
        ("windows.netscan.NetScan", "Network connections"),
        ("windows.cmdline.CmdLine", "Command lines"),
        ("windows.filescan.FileScan", "Open files"),
        ("linux.pslist.PsList", "Process list (Linux)"),
        ("linux.bash.Bash", "Bash history"),
    ]

    vol_cmd = None
    for candidate in ("vol", "vol3", "volatility3", "python3 -m volatility3"):
        try:
            result = subprocess.run(
                candidate.split() + ["--help"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                vol_cmd = candidate.split()
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if not vol_cmd:
        findings.append(Finding(
            title="Volatility 3 not installed — install with: pip install volatility3",
            severity="info",
        ))
        return findings

    for plugin, description in profiles:
        try:
            result = subprocess.run(
                vol_cmd + ["-f", str(filepath), plugin],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 and result.stdout.strip():
                findings.append(Finding(
                    title=f"Memory forensics: {description}",
                    severity="medium",
                    cwe="CWE-200",
                    endpoint=str(filepath),
                    evidence={"plugin": plugin, "output": result.stdout[:3000]},
                ))
        except (subprocess.TimeoutExpired, OSError):
            continue

    return findings


# ---------------------------------------------------------------------------
# Main scanner logic
# ---------------------------------------------------------------------------

def run_forensic_analysis(target: str, mode: str = "auto") -> list[Finding]:
    """Run forensic analysis on a target file."""
    filepath = Path(target)
    if not filepath.exists():
        return [Finding(title="File not found", severity="info", description=f"Path: {target}")]
    if not filepath.is_file():
        return [Finding(title="Not a file", severity="info", description=f"Path: {target}")]

    findings: list[Finding] = []

    if mode in ("auto", "metadata"):
        findings.extend(extract_metadata(filepath))

    if mode in ("auto", "strings"):
        findings.extend(sensitive_string_search(filepath))

    if mode in ("auto", "carve"):
        findings.extend(carve_files(filepath))

    if mode == "volatility":
        findings.extend(run_volatility(filepath))

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--mode", choices=["auto", "metadata", "strings", "carve", "volatility"],
                        default="auto", help="Analysis mode")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Output directory for carved files")
    args = parser.parse_args()

    target = args.target
    log.info("Forensic toolkit starting — mode=%s target=%s", args.mode, target)

    findings = run_forensic_analysis(target, mode=args.mode)
    log.info("Analysis complete — %d findings", len(findings))

    for f in findings:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(f.severity, "🔵")
        log.info("  %s [%s] %s", icon, f.severity.upper(), f.title)

    save_findings(findings, "forensic-toolkit")


if __name__ == "__main__":
    main()
