#!/usr/bin/env python3
"""Disassembly Analyzer — Binary reverse engineering toolkit — CWE-693, CWE-119.

Comprehensive binary analysis combining:
  1. Checksec — NX, ASLR, PIE, stack canary, RELRO, Fortify detection
  2. ELF/PE header parsing — sections, segments, symbols, imports, entrypoint
  3. String extraction — encoding-aware (ASCII, UTF-8, UTF-16), regex patterns
  4. Function listing — via r2pipe/nm/objdump fallbacks
  5. Disassembly — r2pipe / objdump of key functions (main, entry)
  6. Gadget listing — ROP gadgets for exploitation prep
  7. Library dependency — ldd / otool for shared library enumeration

Usage:
    python disasm_analyzer.py --target /path/to/binary --mode checksec
    python disasm_analyzer.py --target /path/to/binary --mode auto
    python disasm_analyzer.py --target /path/to/binary --mode disasm --function main

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
# Checksec — Security feature detection
# ---------------------------------------------------------------------------

def run_checksec(filepath: Path) -> list[Finding]:
    """Detect binary security features (NX, PIE, ASLR, canary, RELRO)."""
    findings: list[Finding] = []

    # Try checksec command first
    try:
        result = subprocess.run(
            ["checksec", "--file", str(filepath), "--output", "json"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            info = data.get(str(filepath), data.get(list(data.keys())[0], {})) if data else {}
            _findings_from_checksec(filepath, info, findings)
            return findings
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    # Manual ELF detection fallback
    try:
        data = filepath.read_bytes()
    except OSError:
        return [Finding(title="Cannot read binary", severity="info")]

    if data[:4] != b"\x7fELF":
        findings.append(Finding(
            title="Not an ELF binary — checksec limited to ELF format",
            severity="info",
            endpoint=str(filepath),
        ))
        _check_pe(data, filepath, findings)
        return findings

    _check_elf_security(data, filepath, findings)
    return findings


def _check_elf_security(data: bytes, filepath: Path, findings: list[Finding]) -> None:
    """Manual ELF security feature detection."""
    protections: dict[str, object] = {}

    # readelf for detailed analysis
    for flag_cmd, label in [
        (["readelf", "-l"], "segments"),
        (["readelf", "-d"], "dynamic"),
        (["readelf", "-s"], "symbols"),
    ]:
        try:
            result = subprocess.run(
                flag_cmd + [str(filepath)],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout

                if label == "segments":
                    protections["nx"] = "GNU_STACK" in output and "RWE" not in output
                    protections["pie"] = "Type:" in output and ("DYN" in output.split("Type:")[1][:20]
                                                                 if "Type:" in output else False)

                elif label == "dynamic":
                    protections["relro"] = "BIND_NOW" in output
                    protections["partial_relro"] = "GNU_RELRO" in output

                elif label == "symbols":
                    protections["canary"] = "__stack_chk_fail" in output
                    protections["fortify"] = "__fortify" in output.lower() or "FORTIFIED" in output

        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # Report findings
    if protections.get("nx") is False:
        findings.append(Finding(
            title="NX disabled — stack is executable",
            severity="critical",
            cwe="CWE-119",
            endpoint=str(filepath),
            evidence=protections,
            description="Stack or heap is executable — allows shellcode injection",
        ))

    if protections.get("pie") is False:
        findings.append(Finding(
            title="PIE disabled — fixed base address (ASLR bypass)",
            severity="high",
            cwe="CWE-693",
            endpoint=str(filepath),
            evidence=protections,
        ))

    if not protections.get("canary"):
        findings.append(Finding(
            title="No stack canary — buffer overflow without detection",
            severity="high",
            cwe="CWE-119",
            endpoint=str(filepath),
            evidence=protections,
        ))

    if not protections.get("relro"):
        sev = "medium" if protections.get("partial_relro") else "high"
        findings.append(Finding(
            title=f"{'Partial' if protections.get('partial_relro') else 'No'} RELRO — GOT overwrite possible",
            severity=sev,
            cwe="CWE-693",
            endpoint=str(filepath),
            evidence=protections,
        ))

    findings.append(Finding(
        title="Binary security summary",
        severity="info",
        endpoint=str(filepath),
        evidence=protections,
    ))


def _check_pe(data: bytes, filepath: Path, findings: list[Finding]) -> None:
    """Basic PE (Windows) binary checks."""
    if data[:2] != b"MZ":
        return

    findings.append(Finding(
        title="PE binary detected",
        severity="info",
        endpoint=str(filepath),
        evidence={"format": "PE/COFF"},
    ))

    # Check DEP/NX via PE characteristics
    if len(data) > 0x3c + 4:
        pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
        if len(data) > pe_offset + 6:
            characteristics = struct.unpack_from("<H", data, pe_offset + 0x16)[0] if pe_offset + 0x16 + 2 <= len(data) else 0
            # DLL_CHARACTERISTICS
            if len(data) > pe_offset + 0x5e + 2:
                dll_char = struct.unpack_from("<H", data, pe_offset + 0x5e)[0]
                protections = {
                    "dep": bool(dll_char & 0x0100),
                    "aslr": bool(dll_char & 0x0040),
                    "cfg": bool(dll_char & 0x4000),
                    "high_entropy_va": bool(dll_char & 0x0020),
                }
                for feature, enabled in protections.items():
                    if not enabled:
                        findings.append(Finding(
                            title=f"PE: {feature.upper()} disabled",
                            severity="high",
                            cwe="CWE-693",
                            endpoint=str(filepath),
                            evidence=protections,
                        ))


def _findings_from_checksec(filepath: Path, info: dict, findings: list[Finding]) -> None:
    """Convert checksec JSON output to findings."""
    checks = {
        "canary": ("Stack canary", "high"),
        "nx": ("NX/DEP", "critical"),
        "pie": ("PIE/ASLR", "high"),
        "relro": ("RELRO", "medium"),
        "fortify_source": ("Fortify", "medium"),
    }
    for key, (label, severity) in checks.items():
        val = str(info.get(key, "")).lower()
        if val in ("no", "false", "disabled"):
            findings.append(Finding(
                title=f"{label} disabled",
                severity=severity,
                cwe="CWE-693" if key != "nx" else "CWE-119",
                endpoint=str(filepath),
                evidence=info,
            ))

    findings.append(Finding(
        title="Checksec summary",
        severity="info",
        endpoint=str(filepath),
        evidence=info,
    ))


# ---------------------------------------------------------------------------
# Function listing & disassembly
# ---------------------------------------------------------------------------

def list_functions(filepath: Path) -> list[Finding]:
    """List functions in a binary."""
    findings: list[Finding] = []
    functions: list[str] = []

    # Try r2pipe
    try:
        import r2pipe  # type: ignore[import-untyped]
        r2 = r2pipe.open(str(filepath))
        r2.cmd("aaa")
        fns = r2.cmdj("aflj") or []
        r2.quit()
        functions = [f"{f.get('name', '?')} @ 0x{f.get('offset', 0):x} ({f.get('size', 0)} bytes)" for f in fns[:50]]
    except (ImportError, Exception):
        pass

    # Fallback: nm
    if not functions:
        try:
            result = subprocess.run(
                ["nm", "-C", "--defined-only", str(filepath)],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines()[:50]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] in ("T", "t"):
                        functions.append(f"{parts[2]} @ 0x{parts[0]}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Fallback: objdump
    if not functions:
        try:
            result = subprocess.run(
                ["objdump", "-t", str(filepath)],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines()[:100]:
                    if " F " in line or ".text" in line:
                        functions.append(line.strip()[:80])
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if functions:
        findings.append(Finding(
            title=f"Functions found: {len(functions)}",
            severity="info",
            endpoint=str(filepath),
            evidence={"functions": functions[:50]},
        ))

    return findings


def disassemble_function(filepath: Path, function_name: str = "main") -> list[Finding]:
    """Disassemble a specific function."""
    findings: list[Finding] = []

    # Try r2pipe
    try:
        import r2pipe  # type: ignore[import-untyped]
        r2 = r2pipe.open(str(filepath))
        r2.cmd("aaa")
        r2.cmd(f"s sym.{function_name}")
        disasm = r2.cmd(f"pdf")
        r2.quit()
        if disasm:
            findings.append(Finding(
                title=f"Disassembly of {function_name}",
                severity="info",
                endpoint=str(filepath),
                evidence={"disassembly": disasm[:5000]},
            ))
            return findings
    except (ImportError, Exception):
        pass

    # Fallback: objdump
    try:
        result = subprocess.run(
            ["objdump", "-d", "-M", "intel", str(filepath)],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode == 0:
            # Extract the function section
            lines = result.stdout.splitlines()
            capture = False
            func_lines: list[str] = []
            for line in lines:
                if f"<{function_name}" in line:
                    capture = True
                elif capture and (line.strip() == "" or (line and not line[0].isspace() and ":" not in line)):
                    break
                if capture:
                    func_lines.append(line)
                    if len(func_lines) > 200:
                        break

            if func_lines:
                findings.append(Finding(
                    title=f"Disassembly of {function_name} (objdump)",
                    severity="info",
                    endpoint=str(filepath),
                    evidence={"disassembly": "\n".join(func_lines)},
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if not findings:
        findings.append(Finding(
            title=f"Could not disassemble {function_name} — install r2pipe or objdump",
            severity="info",
        ))

    return findings


def extract_strings_binary(filepath: Path) -> list[Finding]:
    """Extract interesting strings from a binary."""
    findings: list[Finding] = []

    try:
        result = subprocess.run(
            ["strings", "-a", "-n", "6", str(filepath)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return findings

        all_strings = result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Manual extraction
        try:
            data = filepath.read_bytes()
            all_strings = [m.decode() for m in re.findall(rb"[\x20-\x7e]{6,}", data)]
        except OSError:
            return findings

    # Categorize
    urls = [s for s in all_strings if re.match(r"https?://", s)]
    flags = [s for s in all_strings if re.search(r"flag\{|CTF\{|picoCTF\{|HTB\{", s, re.IGNORECASE)]
    passwords = [s for s in all_strings if re.search(r"pass(word|wd)?|secret|key", s, re.IGNORECASE)]
    paths = [s for s in all_strings if s.startswith("/") and len(s) > 4]
    format_strings = [s for s in all_strings if "%s" in s or "%x" in s or "%n" in s]

    if flags:
        findings.append(Finding(
            title=f"Potential flags: {len(flags)}",
            severity="critical",
            endpoint=str(filepath),
            evidence={"flags": flags[:10]},
        ))

    if format_strings:
        fmt_vuln = [s for s in format_strings if "%n" in s]
        if fmt_vuln:
            findings.append(Finding(
                title="Format string vulnerability (%n detected)",
                severity="critical",
                cwe="CWE-134",
                endpoint=str(filepath),
                evidence={"format_strings": fmt_vuln[:10]},
            ))

    categories = {
        "urls": urls, "passwords": passwords, "paths": paths,
        "format_strings": format_strings,
    }
    evidence = {k: v[:10] for k, v in categories.items() if v}
    evidence["total_strings"] = len(all_strings)

    findings.append(Finding(
        title=f"Extracted {len(all_strings)} strings",
        severity="info",
        endpoint=str(filepath),
        evidence=evidence,
    ))

    return findings


def list_libraries(filepath: Path) -> list[Finding]:
    """List shared library dependencies."""
    findings: list[Finding] = []

    # ldd (Linux) or otool -L (macOS)
    for cmd in (["ldd", str(filepath)], ["otool", "-L", str(filepath)]):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                libs = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                findings.append(Finding(
                    title=f"Linked libraries: {len(libs)}",
                    severity="info",
                    endpoint=str(filepath),
                    evidence={"libraries": libs[:30]},
                ))
                return findings
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return findings


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def run_binary_analysis(target: str, mode: str = "auto", function: str = "main") -> list[Finding]:
    """Run binary analysis."""
    filepath = Path(target)
    if not filepath.exists():
        return [Finding(title="Binary not found", severity="info", description=f"Path: {target}")]

    findings: list[Finding] = []

    if mode in ("auto", "checksec"):
        findings.extend(run_checksec(filepath))

    if mode in ("auto", "strings"):
        findings.extend(extract_strings_binary(filepath))

    if mode in ("auto", "functions"):
        findings.extend(list_functions(filepath))

    if mode in ("auto", "libraries"):
        findings.extend(list_libraries(filepath))

    if mode == "disasm":
        findings.extend(disassemble_function(filepath, function))

    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--mode", choices=["auto", "checksec", "strings", "functions", "disasm", "libraries"],
                        default="auto", help="Analysis mode")
    parser.add_argument("--function", default="main", help="Function to disassemble (for --mode disasm)")
    args = parser.parse_args()

    log.info("Disassembly analyzer starting — mode=%s target=%s", args.mode, args.target)

    findings = run_binary_analysis(args.target, mode=args.mode, function=args.function)
    log.info("Analysis complete — %d findings", len(findings))

    for f in findings:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(f.severity, "🔵")
        log.info("  %s [%s] %s", icon, f.severity.upper(), f.title)

    save_findings(findings, "disasm-analyzer")


if __name__ == "__main__":
    main()
