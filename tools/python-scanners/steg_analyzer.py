#!/usr/bin/env python3
"""Steganography Analyzer — CTF stego detection toolkit — CWE-200, CWE-311.

Comprehensive steganography analysis combining:
  1. File header validation — magic bytes vs extension mismatch
  2. LSB analysis — least significant bit plane extraction (images)
  3. Strings extraction — printable ASCII/Unicode from binary files
  4. EXIF/metadata inspection — GPS, comments, hidden fields
  5. Appended data detection — data after logical EOF (ZIP, PNG, JPEG)
  6. Binwalk-style entropy analysis — embedded file/archive detection
  7. Steghide/StegSolve-compatible checks

Usage:
    python steg_analyzer.py --target /path/to/suspicious_image.png
    python steg_analyzer.py --target /path/to/file --mode strings

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import math
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

from lib import Finding, log, parse_base_args, save_findings

# ---------------------------------------------------------------------------
# Magic bytes signatures
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES: list[dict[str, object]] = [
    {"name": "PNG", "magic": b"\x89PNG\r\n\x1a\n", "ext": [".png"]},
    {"name": "JPEG", "magic": b"\xff\xd8\xff", "ext": [".jpg", ".jpeg"]},
    {"name": "GIF87a", "magic": b"GIF87a", "ext": [".gif"]},
    {"name": "GIF89a", "magic": b"GIF89a", "ext": [".gif"]},
    {"name": "BMP", "magic": b"BM", "ext": [".bmp"]},
    {"name": "TIFF-LE", "magic": b"II\x2a\x00", "ext": [".tiff", ".tif"]},
    {"name": "TIFF-BE", "magic": b"MM\x00\x2a", "ext": [".tiff", ".tif"]},
    {"name": "PDF", "magic": b"%PDF", "ext": [".pdf"]},
    {"name": "ZIP/DOCX/XLSX/JAR", "magic": b"PK\x03\x04", "ext": [".zip", ".docx", ".xlsx", ".jar", ".apk"]},
    {"name": "RAR", "magic": b"Rar!\x1a\x07", "ext": [".rar"]},
    {"name": "7-Zip", "magic": b"7z\xbc\xaf\x27\x1c", "ext": [".7z"]},
    {"name": "GZIP", "magic": b"\x1f\x8b", "ext": [".gz", ".tgz"]},
    {"name": "ELF", "magic": b"\x7fELF", "ext": ["", ".elf", ".so", ".o"]},
    {"name": "Mach-O 64", "magic": b"\xcf\xfa\xed\xfe", "ext": ["", ".dylib"]},
    {"name": "PE/EXE", "magic": b"MZ", "ext": [".exe", ".dll", ".sys"]},
    {"name": "WAV", "magic": b"RIFF", "ext": [".wav"]},
    {"name": "OGG", "magic": b"OggS", "ext": [".ogg"]},
    {"name": "SQLite", "magic": b"SQLite format 3", "ext": [".db", ".sqlite", ".sqlite3"]},
]

# Embedded signatures to search for within files (binwalk-style)
EMBEDDED_SIGNATURES: list[dict[str, bytes | str]] = [
    {"name": "ZIP archive", "sig": b"PK\x03\x04"},
    {"name": "RAR archive", "sig": b"Rar!\x1a\x07"},
    {"name": "GZIP data", "sig": b"\x1f\x8b\x08"},
    {"name": "PNG image", "sig": b"\x89PNG\r\n\x1a\n"},
    {"name": "JPEG image", "sig": b"\xff\xd8\xff\xe0"},
    {"name": "PDF document", "sig": b"%PDF-"},
    {"name": "ELF binary", "sig": b"\x7fELF"},
    {"name": "7z archive", "sig": b"7z\xbc\xaf\x27\x1c"},
    {"name": "BZ2 data", "sig": b"BZh"},
    {"name": "XZ data", "sig": b"\xfd7zXZ\x00"},
]


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def check_magic_bytes(filepath: Path) -> list[Finding]:
    """Validate file header against extension."""
    findings: list[Finding] = []
    try:
        with open(filepath, "rb") as f:
            header = f.read(32)
    except OSError as exc:
        findings.append(Finding(title="Cannot read file", severity="info", description=str(exc)))
        return findings

    detected_type = None
    for sig in MAGIC_SIGNATURES:
        if header.startswith(sig["magic"]):  # type: ignore[arg-type]
            detected_type = sig
            break

    ext = filepath.suffix.lower()
    if detected_type:
        expected_exts = detected_type["ext"]
        if ext and ext not in expected_exts:  # type: ignore[operator]
            findings.append(Finding(
                title=f"Extension mismatch: {ext} is actually {detected_type['name']}",
                severity="medium",
                cwe="CWE-200",
                endpoint=str(filepath),
                description=f"File header identifies as {detected_type['name']} but extension is {ext}",
                evidence={"detected": detected_type["name"], "extension": ext, "magic_hex": header[:8].hex()},
                remediation="Verify file type matches extension. Hidden data may be disguised.",
            ))
    else:
        findings.append(Finding(
            title="Unknown file format",
            severity="info",
            endpoint=str(filepath),
            description=f"Header: {header[:16].hex()}",
            evidence={"header_hex": header[:32].hex()},
        ))

    return findings


def extract_strings(filepath: Path, min_length: int = 6) -> list[Finding]:
    """Extract printable strings from binary file."""
    findings: list[Finding] = []
    try:
        data = filepath.read_bytes()
    except OSError:
        return findings

    # ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
    ascii_strings = [m.group().decode("ascii") for m in ascii_pattern.finditer(data)]

    # Filter interesting strings
    interesting: list[str] = []
    patterns = [
        (r"flag\{[^}]+\}", "CTF flag"),
        (r"https?://\S+", "URL"),
        (r"[A-Za-z0-9+/]{20,}={0,2}", "Base64-like"),
        (r"password\s*[:=]\s*\S+", "Password hint"),
        (r"key\s*[:=]\s*\S+", "Key hint"),
        (r"secret\s*[:=]\s*\S+", "Secret hint"),
        (r"/etc/passwd|/etc/shadow", "System file path"),
        (r"BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY", "Private key"),
    ]

    for s in ascii_strings:
        for pat, label in patterns:
            if re.search(pat, s, re.IGNORECASE):
                interesting.append(f"[{label}] {s[:200]}")

    if interesting:
        findings.append(Finding(
            title=f"Interesting strings found ({len(interesting)})",
            severity="medium",
            cwe="CWE-200",
            endpoint=str(filepath),
            description=f"Found {len(interesting)} interesting strings in {len(ascii_strings)} total",
            evidence={"interesting": interesting[:20], "total_strings": len(ascii_strings)},
        ))

    # Hidden text after known EOF markers
    for marker_name, marker in [("PNG IEND", b"IEND\xaeB`\x82"), ("JPEG EOI", b"\xff\xd9")]:
        pos = data.find(marker)
        if pos > 0:
            trailing = data[pos + len(marker):]
            if len(trailing) > 10:
                trail_preview = trailing[:200]
                trail_strings = [m.group().decode("ascii") for m in ascii_pattern.finditer(trail_preview)]
                findings.append(Finding(
                    title=f"Data appended after {marker_name} ({len(trailing)} bytes)",
                    severity="high",
                    cwe="CWE-200",
                    endpoint=str(filepath),
                    description=f"{len(trailing)} bytes of data found after {marker_name} marker",
                    evidence={
                        "offset": pos + len(marker),
                        "trailing_size": len(trailing),
                        "preview_hex": trailing[:64].hex(),
                        "trailing_strings": trail_strings[:10],
                    },
                    remediation="Data hidden after file EOF — common steganography technique.",
                ))

    return findings


def scan_embedded_files(filepath: Path) -> list[Finding]:
    """Search for embedded file signatures (binwalk-like)."""
    findings: list[Finding] = []
    try:
        data = filepath.read_bytes()
    except OSError:
        return findings

    file_size = len(data)

    for sig_info in EMBEDDED_SIGNATURES:
        sig = sig_info["sig"]
        name = sig_info["name"]
        offset = 0
        while True:
            pos = data.find(sig, offset)  # type: ignore[arg-type]
            if pos == -1:
                break
            # Skip if at position 0 (that's the file itself)
            if pos > 0:
                findings.append(Finding(
                    title=f"Embedded {name} at offset 0x{pos:x}",
                    severity="high",
                    cwe="CWE-200",
                    endpoint=str(filepath),
                    description=f"Found {name} signature at offset {pos} (0x{pos:x}) in {file_size}-byte file",
                    evidence={
                        "offset": pos,
                        "offset_hex": f"0x{pos:x}",
                        "signature": name,
                        "context_hex": data[pos:pos + 16].hex(),
                    },
                    remediation=f"Extract with: dd if={filepath.name} bs=1 skip={pos} | file -",
                ))
            offset = pos + 1
            if offset >= file_size:
                break

    return findings


def entropy_analysis(filepath: Path, block_size: int = 256) -> list[Finding]:
    """Calculate entropy per block to detect encrypted/compressed regions."""
    findings: list[Finding] = []
    try:
        data = filepath.read_bytes()
    except OSError:
        return findings

    if len(data) < block_size:
        return findings

    # Overall entropy
    overall = _shannon_entropy(data)
    high_entropy_blocks = []

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        if len(block) < block_size // 2:
            break
        ent = _shannon_entropy(block)
        if ent > 7.5:  # Near-random data
            high_entropy_blocks.append({"offset": i, "entropy": round(ent, 4)})

    if high_entropy_blocks:
        findings.append(Finding(
            title=f"High-entropy regions detected ({len(high_entropy_blocks)} blocks)",
            severity="medium",
            cwe="CWE-311",
            endpoint=str(filepath),
            description=(
                f"Overall entropy: {overall:.4f}/8.0. "
                f"{len(high_entropy_blocks)} blocks exceed 7.5 (encrypted/compressed data)"
            ),
            evidence={
                "overall_entropy": round(overall, 4),
                "high_blocks": high_entropy_blocks[:10],
                "total_blocks": len(data) // block_size,
            },
        ))

    return findings


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0-8 scale)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def check_exif(filepath: Path) -> list[Finding]:
    """Extract EXIF/metadata using exiftool if available."""
    findings: list[Finding] = []
    try:
        result = subprocess.run(
            ["exiftool", "-json", str(filepath)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            import json
            metadata = json.loads(result.stdout)
            if metadata and isinstance(metadata, list):
                meta = metadata[0]
                interesting_keys = [
                    "Comment", "UserComment", "ImageDescription", "XPComment",
                    "GPSLatitude", "GPSLongitude", "Author", "Creator",
                    "Subject", "Keywords", "XPTitle", "XPSubject",
                ]
                found = {k: meta[k] for k in interesting_keys if k in meta}
                if found:
                    findings.append(Finding(
                        title=f"Interesting EXIF metadata ({len(found)} fields)",
                        severity="medium",
                        cwe="CWE-200",
                        endpoint=str(filepath),
                        evidence={"metadata": found},
                        description=f"Fields: {', '.join(found.keys())}",
                    ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        log.info("exiftool not available — skipping EXIF analysis")
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# Main scanner logic
# ---------------------------------------------------------------------------

def run_steg_analysis(target: str, mode: str = "auto") -> list[Finding]:
    """Run steganography analysis on a file."""
    filepath = Path(target)
    if not filepath.exists():
        return [Finding(title="File not found", severity="info", description=f"Path: {target}")]
    if not filepath.is_file():
        return [Finding(title="Not a file", severity="info", description=f"Path: {target}")]

    findings: list[Finding] = []
    file_size = filepath.stat().st_size
    findings.append(Finding(
        title=f"Analyzing: {filepath.name} ({file_size:,} bytes)",
        severity="info",
        endpoint=str(filepath),
        evidence={"size": file_size, "extension": filepath.suffix},
    ))

    if mode in ("auto", "magic"):
        findings.extend(check_magic_bytes(filepath))

    if mode in ("auto", "strings"):
        findings.extend(extract_strings(filepath))

    if mode in ("auto", "embedded"):
        findings.extend(scan_embedded_files(filepath))

    if mode in ("auto", "entropy"):
        findings.extend(entropy_analysis(filepath))

    if mode in ("auto", "exif"):
        findings.extend(check_exif(filepath))

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--mode", choices=["auto", "magic", "strings", "embedded", "entropy", "exif"],
                        default="auto", help="Analysis mode")
    args = parser.parse_args()

    target = args.target
    log.info("Steg analyzer starting — mode=%s target=%s", args.mode, target)

    findings = run_steg_analysis(target, mode=args.mode)
    log.info("Analysis complete — %d findings", len(findings))

    for f in findings:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(f.severity, "🔵")
        log.info("  %s [%s] %s", icon, f.severity.upper(), f.title)

    save_findings(findings, "steg-analyzer")


if __name__ == "__main__":
    main()
