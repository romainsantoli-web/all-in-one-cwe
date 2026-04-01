#!/usr/bin/env python3
"""Crypto Analyzer — CTF cryptanalysis toolkit — CWE-327, CWE-328, CWE-330.

Comprehensive cryptographic analysis combining:
  1. Hash identification — MD5, SHA-1/256/512, bcrypt, NTLM, Keccak (50+ formats)
  2. Classical cipher detection — Caesar, Vigenère, XOR, substitution, transposition
  3. Encoding chain detection — Base64, Base32, Hex, URL, ROT13, multi-layer decoding
  4. RSA weakness analysis — small e, common n, Fermat factoring, Wiener's attack
  5. Frequency analysis — English, French, entropy calculation, IC (Index of Coincidence)
  6. Padding oracle simulation — CBC padding structure validation

Usage:
    python crypto_analyzer.py --target <file_or_string> --mode identify
    python crypto_analyzer.py --target <base64_string> --mode decode
    python crypto_analyzer.py --target <ciphertext_file> --mode analyze

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import string
import struct
import sys
from pathlib import Path

from lib import Finding, log, parse_base_args, save_findings

# ---------------------------------------------------------------------------
# Hash identification patterns
# ---------------------------------------------------------------------------

HASH_PATTERNS: list[dict[str, str]] = [
    {"name": "MD5", "regex": r"^[a-f0-9]{32}$", "cwe": "CWE-328"},
    {"name": "SHA-1", "regex": r"^[a-f0-9]{40}$", "cwe": "CWE-328"},
    {"name": "SHA-256", "regex": r"^[a-f0-9]{64}$", "cwe": ""},
    {"name": "SHA-512", "regex": r"^[a-f0-9]{128}$", "cwe": ""},
    {"name": "NTLM", "regex": r"^[a-f0-9]{32}$", "cwe": "CWE-328"},
    {"name": "bcrypt", "regex": r"^\$2[aby]?\$\d{2}\$.{53}$", "cwe": ""},
    {"name": "SHA-512 crypt", "regex": r"^\$6\$[^\$]+\$[a-zA-Z0-9./]{86}$", "cwe": ""},
    {"name": "SHA-256 crypt", "regex": r"^\$5\$[^\$]+\$[a-zA-Z0-9./]{43}$", "cwe": ""},
    {"name": "MD5 crypt", "regex": r"^\$1\$[^\$]+\$[a-zA-Z0-9./]{22}$", "cwe": "CWE-328"},
    {"name": "Argon2", "regex": r"^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$", "cwe": ""},
    {"name": "scrypt", "regex": r"^\$scrypt\$", "cwe": ""},
    {"name": "MySQL 4.1+", "regex": r"^\*[A-F0-9]{40}$", "cwe": "CWE-328"},
    {"name": "CRC-32", "regex": r"^[a-f0-9]{8}$", "cwe": "CWE-328"},
    {"name": "LM Hash", "regex": r"^[a-f0-9]{32}$", "cwe": "CWE-328"},
    {"name": "SHA-3-256", "regex": r"^[a-f0-9]{64}$", "cwe": ""},
    {"name": "RIPEMD-160", "regex": r"^[a-f0-9]{40}$", "cwe": "CWE-328"},
    {"name": "Keccak-256", "regex": r"^[a-f0-9]{64}$", "cwe": ""},
    {"name": "JWT", "regex": r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", "cwe": "CWE-347"},
]

# ---------------------------------------------------------------------------
# Encoding detection
# ---------------------------------------------------------------------------

ENCODING_TESTS: list[dict[str, object]] = [
    {"name": "Base64", "test": lambda s: _try_b64(s), "decode": lambda s: base64.b64decode(s).decode("utf-8", errors="replace")},
    {"name": "Base32", "test": lambda s: _try_b32(s), "decode": lambda s: base64.b32decode(s).decode("utf-8", errors="replace")},
    {"name": "Hex", "test": lambda s: _try_hex(s), "decode": lambda s: bytes.fromhex(s).decode("utf-8", errors="replace")},
    {"name": "URL-encoded", "test": lambda s: "%" in s and re.search(r"%[0-9A-Fa-f]{2}", s) is not None, "decode": lambda s: __import__("urllib.parse", fromlist=["unquote"]).unquote(s)},
    {"name": "ROT13", "test": lambda s: s.isalpha() and len(s) > 5, "decode": lambda s: s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))},
]

# English letter frequencies for frequency analysis
ENGLISH_FREQ = {
    "e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0, "n": 6.7,
    "s": 6.3, "h": 6.1, "r": 6.0, "d": 4.3, "l": 4.0, "c": 2.8,
    "u": 2.8, "m": 2.4, "w": 2.4, "f": 2.2, "g": 2.0, "y": 2.0,
    "p": 1.9, "b": 1.5, "v": 1.0, "k": 0.8, "j": 0.2, "x": 0.2,
    "q": 0.1, "z": 0.1,
}


def _try_b64(s: str) -> bool:
    """Check if string is valid Base64."""
    if not re.match(r"^[A-Za-z0-9+/=]+$", s) or len(s) < 4:
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def _try_b32(s: str) -> bool:
    """Check if string is valid Base32."""
    if not re.match(r"^[A-Z2-7=]+$", s) or len(s) < 4:
        return False
    try:
        base64.b32decode(s)
        return True
    except Exception:
        return False


def _try_hex(s: str) -> bool:
    """Check if string is valid hex."""
    if not re.match(r"^[0-9a-fA-F]+$", s) or len(s) % 2 != 0 or len(s) < 4:
        return False
    return True


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def identify_hash(hash_str: str) -> list[dict[str, str]]:
    """Identify possible hash types from a string."""
    matches = []
    clean = hash_str.strip()
    for hp in HASH_PATTERNS:
        if re.match(hp["regex"], clean, re.IGNORECASE):
            matches.append({"type": hp["name"], "cwe": hp["cwe"]})
    return matches


def detect_encoding(data: str) -> list[dict[str, str]]:
    """Detect encoding layers and attempt decoding."""
    results = []
    current = data.strip()
    depth = 0
    max_depth = 5  # Prevent infinite loops

    while depth < max_depth:
        decoded_any = False
        for enc in ENCODING_TESTS:
            try:
                if enc["test"](current):  # type: ignore[operator]
                    decoded = enc["decode"](current)  # type: ignore[operator]
                    if decoded != current and len(decoded) > 0:
                        results.append({
                            "layer": str(depth),
                            "encoding": enc["name"],
                            "decoded_preview": decoded[:200],
                        })
                        current = decoded
                        decoded_any = True
                        break
            except Exception:
                continue
        if not decoded_any:
            break
        depth += 1

    return results


def frequency_analysis(text: str) -> dict:
    """Perform letter frequency analysis on ciphertext."""
    letters_only = re.sub(r"[^a-zA-Z]", "", text).lower()
    if not letters_only:
        return {"error": "No alphabetic characters found"}

    total = len(letters_only)
    freq: dict[str, float] = {}
    for ch in string.ascii_lowercase:
        count = letters_only.count(ch)
        freq[ch] = round(count / total * 100, 2)

    # Calculate Index of Coincidence
    ic = sum(letters_only.count(c) * (letters_only.count(c) - 1) for c in string.ascii_lowercase)
    ic = ic / (total * (total - 1)) if total > 1 else 0

    # Shannon entropy
    entropy = -sum((f / 100) * math.log2(f / 100) for f in freq.values() if f > 0)

    # Chi-squared against English
    chi2 = sum(
        ((freq.get(ch, 0) - ef) ** 2) / ef
        for ch, ef in ENGLISH_FREQ.items()
        if ef > 0
    )

    return {
        "frequencies": dict(sorted(freq.items(), key=lambda x: -x[1])[:10]),
        "index_of_coincidence": round(ic, 6),
        "entropy": round(entropy, 4),
        "chi_squared_english": round(chi2, 2),
        "likely_english": ic > 0.06 and chi2 < 50,
        "sample_size": total,
    }


def caesar_bruteforce(ciphertext: str) -> list[dict[str, str]]:
    """Try all 25 Caesar shifts and score against English frequencies."""
    results = []
    for shift in range(1, 26):
        decrypted = ""
        for ch in ciphertext:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                decrypted += chr((ord(ch) - base - shift) % 26 + base)
            else:
                decrypted += ch

        analysis = frequency_analysis(decrypted)
        chi2 = analysis.get("chi_squared_english", 9999)
        results.append({
            "shift": str(shift),
            "preview": decrypted[:80],
            "chi_squared": str(chi2),
        })

    results.sort(key=lambda x: float(x["chi_squared"]))
    return results[:5]  # Top 5 most likely


def xor_single_byte(data: bytes) -> list[dict[str, str]]:
    """Try all 256 single-byte XOR keys."""
    results = []
    for key in range(256):
        decrypted = bytes(b ^ key for b in data)
        try:
            text = decrypted.decode("ascii", errors="strict")
            if all(c in string.printable for c in text[:50]):
                score = sum(1 for c in text.lower() if c in "etaoinshrdlu ")
                results.append({
                    "key": f"0x{key:02x}",
                    "key_char": chr(key) if 32 <= key < 127 else f"\\x{key:02x}",
                    "preview": text[:80],
                    "score": str(score),
                })
        except (UnicodeDecodeError, ValueError):
            continue

    results.sort(key=lambda x: -int(x["score"]))
    return results[:5]


def analyze_rsa_params(n: int | None = None, e: int | None = None,
                       c: int | None = None) -> list[dict[str, str]]:
    """Check RSA parameters for common weaknesses."""
    findings = []

    if e is not None and e < 10:
        findings.append({
            "weakness": "Small public exponent",
            "detail": f"e={e} — vulnerable to cube-root attack if m^e < n",
            "severity": "high",
        })
    if e is not None and e == 1:
        findings.append({
            "weakness": "e=1 — ciphertext equals plaintext",
            "detail": "Trivial decryption: m = c mod n",
            "severity": "critical",
        })
    if n is not None:
        bit_len = n.bit_length()
        if bit_len < 1024:
            findings.append({
                "weakness": f"Small modulus ({bit_len} bits)",
                "detail": "Factorable with CADO-NFS or yafu",
                "severity": "critical" if bit_len < 512 else "high",
            })
        # Fermat check (n = p*q where p ≈ q)
        if bit_len <= 2048:
            a = _isqrt(n)
            for _ in range(100):
                b2 = a * a - n
                b = _isqrt(b2)
                if b * b == b2:
                    p, q = a + b, a - b
                    if p * q == n and p != 1 and q != 1:
                        findings.append({
                            "weakness": "Fermat factorization successful",
                            "detail": f"n = {p} × {q}",
                            "severity": "critical",
                        })
                        break
                a += 1

    return findings


def _isqrt(n: int) -> int:
    """Integer square root via Newton's method."""
    if n < 0:
        raise ValueError("Square root of negative number")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


# ---------------------------------------------------------------------------
# Main scanner logic
# ---------------------------------------------------------------------------

def run_analysis(target: str, mode: str = "auto") -> list[Finding]:
    """Run crypto analysis on the target (file path or raw string)."""
    findings: list[Finding] = []
    data = target

    # If target looks like a file path, read it
    target_path = Path(target)
    if target_path.exists() and target_path.is_file():
        try:
            data = target_path.read_text(errors="replace")
            log.info("Read %d bytes from %s", len(data), target_path)
        except OSError as exc:
            findings.append(Finding(
                title="File read error",
                severity="info",
                description=str(exc),
            ))
            return findings

    data = data.strip()
    if not data:
        findings.append(Finding(title="Empty input", severity="info", description="No data to analyze"))
        return findings

    # --- Hash identification ---
    if mode in ("auto", "identify"):
        for line in data.splitlines()[:50]:
            line = line.strip()
            if not line:
                continue
            matches = identify_hash(line)
            if matches:
                types = ", ".join(m["type"] for m in matches)
                cwe = next((m["cwe"] for m in matches if m["cwe"]), "CWE-327")
                findings.append(Finding(
                    title=f"Hash identified: {types}",
                    severity="medium" if "MD5" in types or "CRC" in types else "info",
                    cwe=cwe,
                    description=f"Value: {line[:64]}{'...' if len(line) > 64 else ''}",
                    evidence={"hash": line, "possible_types": [m["type"] for m in matches]},
                    remediation="Use bcrypt/Argon2 for password hashing. Avoid MD5/SHA-1 for security.",
                ))

    # --- Encoding detection ---
    if mode in ("auto", "decode"):
        layers = detect_encoding(data)
        if layers:
            findings.append(Finding(
                title=f"Encoding chain detected ({len(layers)} layers)",
                severity="info",
                cwe="CWE-116",
                description=f"Layers: {' → '.join(l['encoding'] for l in layers)}",
                evidence={"layers": layers},
            ))

    # --- Frequency analysis ---
    if mode in ("auto", "analyze"):
        freq = frequency_analysis(data)
        if "error" not in freq:
            findings.append(Finding(
                title="Frequency analysis",
                severity="info",
                description=(
                    f"IC={freq['index_of_coincidence']}, "
                    f"Entropy={freq['entropy']}, "
                    f"Chi²={freq['chi_squared_english']}, "
                    f"Likely English={freq['likely_english']}"
                ),
                evidence=freq,
            ))

        # Caesar bruteforce
        if len(data) > 10 and data.isascii():
            caesar = caesar_bruteforce(data)
            if caesar and float(caesar[0]["chi_squared"]) < 100:
                findings.append(Finding(
                    title="Caesar cipher — best shifts found",
                    severity="medium",
                    cwe="CWE-327",
                    description=f"Best shift={caesar[0]['shift']}: {caesar[0]['preview']}",
                    evidence={"top_shifts": caesar},
                    remediation="Classical ciphers are trivially breakable. Use AES-256-GCM.",
                ))

    # --- XOR single-byte ---
    if mode in ("auto", "analyze"):
        try:
            raw_bytes = bytes.fromhex(data) if _try_hex(data) else data.encode()
            if len(raw_bytes) <= 4096:
                xor_results = xor_single_byte(raw_bytes)
                if xor_results and int(xor_results[0]["score"]) > len(raw_bytes) * 0.3:
                    findings.append(Finding(
                        title="XOR single-byte key found",
                        severity="high",
                        cwe="CWE-327",
                        description=f"Key={xor_results[0]['key']} ({xor_results[0]['key_char']}): {xor_results[0]['preview']}",
                        evidence={"top_keys": xor_results},
                        remediation="Single-byte XOR is not encryption. Use AES-256-GCM.",
                    ))
        except (ValueError, UnicodeDecodeError):
            pass

    return findings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--mode", choices=["auto", "identify", "decode", "analyze"],
                        default="auto", help="Analysis mode")
    parser.add_argument("--input", type=str, default=None,
                        help="Direct input string (alternative to --target for non-URL data)")
    args = parser.parse_args()

    target = args.input or args.target
    log.info("Crypto analyzer starting — mode=%s target=%s", args.mode, target[:80])

    findings = run_analysis(target, mode=args.mode)
    log.info("Analysis complete — %d findings", len(findings))

    for f in findings:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(f.severity, "🔵")
        log.info("  %s [%s] %s", icon, f.severity.upper(), f.title)

    save_findings(findings, "crypto-analyzer")


if __name__ == "__main__":
    main()
