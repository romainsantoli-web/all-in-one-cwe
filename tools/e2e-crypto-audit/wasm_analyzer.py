"""
E2E Crypto Audit — Module 1: WASM Binary Analyzer

Reverse-engineer WASM crypto modules to detect:
- Algorithm choices (weak/deprecated ciphers)
- Hardcoded keys, IVs, or salts
- Missing randomness (static seeds)
- Known-vulnerable implementations
- Exportable crypto functions surface
"""

import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


# --- Crypto function signatures to detect ---
CRYPTO_SIGNATURES = {
    # Strong algorithms
    "aes": {"pattern": r"\b(aes|AES)[_\-.]?(128|192|256|gcm|cbc|ctr|ccm|siv)\b", "strength": "strong"},
    "chacha20": {"pattern": r"\bchacha20[\-_]?poly1305\b", "strength": "strong"},
    "xchacha20": {"pattern": r"\bxchacha20\b", "strength": "strong"},
    "ed25519": {"pattern": r"\bed25519\b", "strength": "strong"},
    "x25519": {"pattern": r"\bx25519\b", "strength": "strong"},
    "curve25519": {"pattern": r"\bcurve25519\b", "strength": "strong"},
    "argon2": {"pattern": r"\bargon2[id]?\b", "strength": "strong"},
    "sha256": {"pattern": r"\bsha[\-_]?256\b", "strength": "strong"},
    "sha384": {"pattern": r"\bsha[\-_]?384\b", "strength": "strong"},
    "sha512": {"pattern": r"\bsha[\-_]?512\b", "strength": "strong"},
    "blake2": {"pattern": r"\bblake2[bs]?\b", "strength": "strong"},
    "hkdf": {"pattern": r"\bhkdf\b", "strength": "strong"},
    "pbkdf2": {"pattern": r"\bpbkdf2\b", "strength": "moderate"},
    "ecdsa": {"pattern": r"\becdsa\b", "strength": "strong"},
    "ecdh": {"pattern": r"\becdh\b", "strength": "strong"},
    "p256": {"pattern": r"\b(p[\-_]?256|secp256r1|prime256v1)\b", "strength": "strong"},
    "p384": {"pattern": r"\b(p[\-_]?384|secp384r1)\b", "strength": "strong"},
    "rsa": {"pattern": r"\brsa[\-_]?(2048|3072|4096|oaep|pss)\b", "strength": "strong"},

    # Weak/deprecated algorithms — CRITICAL findings
    "md5": {"pattern": r"\bmd5\b", "strength": "broken", "severity": "CRITICAL"},
    "sha1": {"pattern": r"\bsha[\-_]?1\b", "strength": "deprecated", "severity": "HIGH"},
    "des": {"pattern": r"\b(des|3des|triple[\-_]?des)\b", "strength": "broken", "severity": "CRITICAL"},
    "rc4": {"pattern": r"\b(rc4|arcfour)\b", "strength": "broken", "severity": "CRITICAL"},
    "blowfish": {"pattern": r"\bblowfish\b", "strength": "deprecated", "severity": "MEDIUM"},
    "ecb_mode": {"pattern": r"\b(aes[\-_]?ecb|ecb[\-_]?mode|ECB)\b", "strength": "broken", "severity": "CRITICAL"},
    "rsa_1024": {"pattern": r"\brsa[\-_]?1024\b", "strength": "deprecated", "severity": "HIGH"},
    "rsa_512": {"pattern": r"\brsa[\-_]?512\b", "strength": "broken", "severity": "CRITICAL"},
    "pkcs1v15": {"pattern": r"\bpkcs1[\-_]?v1[\-_]?5\b", "strength": "deprecated", "severity": "HIGH"},
}

# Hardcoded value patterns
HARDCODED_PATTERNS = {
    "hex_key_128": {"pattern": r'["\x27]([0-9a-fA-F]{32})["\x27]', "desc": "Potential 128-bit hex key"},
    "hex_key_256": {"pattern": r'["\x27]([0-9a-fA-F]{64})["\x27]', "desc": "Potential 256-bit hex key"},
    "base64_key": {"pattern": r'["\x27]([A-Za-z0-9+/]{32,}={0,2})["\x27]', "desc": "Potential base64 key"},
    "static_iv": {"pattern": r'\b(iv|nonce|salt)\s*=\s*["\x27]([^"\']{8,})["\x27]', "desc": "Static IV/nonce/salt"},
    "zero_iv": {"pattern": r'(\\x00){8,}|(\x00){8,}|0{24,}', "desc": "Zero IV/key (all zeros)"},
    "test_key": {"pattern": r'["\x27](test|demo|example|default|dummy)[\-_]?(key|secret|password|iv|nonce)', "desc": "Test/demo key"},
}

# WASM-specific patterns
WASM_CRYPTO_EXPORTS = {
    "encrypt": r"export\s+\"(.*?encrypt.*?)\"",
    "decrypt": r"export\s+\"(.*?decrypt.*?)\"",
    "sign": r"export\s+\"(.*?sign.*?)\"",
    "verify": r"export\s+\"(.*?verify.*?)\"",
    "hash": r"export\s+\"(.*?hash.*?)\"",
    "derive": r"export\s+\"(.*?derive.*?)\"",
    "random": r"export\s+\"(.*?random.*?)\"",
    "key": r"export\s+\"(.*?key.*?)\"",
    "seal": r"export\s+\"(.*?seal.*?)\"",
    "open": r"export\s+\"(.*?open.*?)\"",
}


def download_wasm(url: str, output_dir: str) -> list[str]:
    """Download WASM files from a web application."""
    import requests

    wasm_files = []
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Try direct WASM URL
    if url.endswith(".wasm"):
        try:
            r = requests.get(url, timeout=30, stream=True)
            if r.status_code == 200 and len(r.content) > 100:
                fpath = output_path / Path(url).name
                fpath.write_bytes(r.content)
                wasm_files.append(str(fpath))
                print(f"  [+] Downloaded: {fpath.name} ({len(r.content):,} bytes)")
        except Exception as e:
            print(f"  [-] Failed to download {url}: {e}")
        return wasm_files

    # Crawl page for .wasm references
    try:
        r = requests.get(url, timeout=15)
        # Find .wasm URLs in HTML/JS
        wasm_urls = set(re.findall(r'["\']([^"\']*?\.wasm)["\']', r.text))
        # Also search for fetch/importScripts patterns
        wasm_urls.update(re.findall(r'fetch\(["\']([^"\']*?\.wasm)', r.text))

        for wasm_url in wasm_urls:
            if not wasm_url.startswith("http"):
                from urllib.parse import urljoin
                wasm_url = urljoin(url, wasm_url)
            try:
                wr = requests.get(wasm_url, timeout=30, stream=True)
                if wr.status_code == 200 and len(wr.content) > 100:
                    fname = Path(wasm_url).name or "module.wasm"
                    fpath = output_path / fname
                    fpath.write_bytes(wr.content)
                    wasm_files.append(str(fpath))
                    print(f"  [+] Downloaded: {fname} ({len(wr.content):,} bytes)")
            except Exception as e:
                print(f"  [-] Failed: {wasm_url}: {e}")
    except Exception as e:
        print(f"  [-] Failed to crawl {url}: {e}")

    return wasm_files


def decompile_wasm(wasm_path: str, output_dir: str = None) -> str:
    """Decompile WASM to WAT (text format) using wasm2wat."""
    if output_dir is None:
        output_dir = os.path.dirname(wasm_path)
    wat_path = os.path.join(output_dir, Path(wasm_path).stem + ".wat")

    # Try wasm2wat
    for tool in ["wasm2wat", "/opt/homebrew/bin/wasm2wat", "/usr/local/bin/wasm2wat"]:
        try:
            result = subprocess.run(
                [tool, wasm_path, "-o", wat_path],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                print(f"  [+] Decompiled: {wat_path} ({os.path.getsize(wat_path):,} bytes)")
                return wat_path
            else:
                print(f"  [-] wasm2wat error: {result.stderr[:200]}")
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            print(f"  [-] wasm2wat timeout (>120s)")

    print("  [-] wasm2wat not found. Install: brew install wabt")
    return ""


def analyze_wat(wat_path: str) -> dict:
    """Analyze a WAT file for crypto patterns."""
    findings = {
        "algorithms": [],
        "hardcoded": [],
        "exports": [],
        "imports": [],
        "functions": {"total": 0, "crypto_related": 0},
        "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "raw_stats": {},
    }

    try:
        content = Path(wat_path).read_text(errors="replace")
    except Exception as e:
        print(f"  [-] Cannot read {wat_path}: {e}")
        return findings

    file_size = len(content)
    findings["raw_stats"]["wat_size"] = file_size
    findings["raw_stats"]["line_count"] = content.count("\n")

    # Count functions
    func_count = len(re.findall(r'\(func\s', content))
    findings["functions"]["total"] = func_count

    # --- Detect crypto algorithms ---
    content_lower = content.lower()
    crypto_func_count = 0
    for name, spec in CRYPTO_SIGNATURES.items():
        matches = re.findall(spec["pattern"], content_lower)
        if matches:
            count = len(matches)
            crypto_func_count += count
            severity = spec.get("severity", "INFO")
            finding = {
                "algorithm": name,
                "strength": spec["strength"],
                "occurrences": count,
                "severity": severity,
                "samples": [m if isinstance(m, str) else m[0] for m in matches[:5]],
            }
            findings["algorithms"].append(finding)
            findings["severity_counts"][severity] += 1

            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "✅")
            print(f"  {icon} {name}: {spec['strength']} ({count} occurrences) [{severity}]")

    findings["functions"]["crypto_related"] = crypto_func_count

    # --- Detect hardcoded values ---
    for name, spec in HARDCODED_PATTERNS.items():
        matches = re.findall(spec["pattern"], content)
        if matches:
            # Filter out common false positives (repeated chars, all zeros in WAT)
            real_matches = []
            for m in matches:
                val = m if isinstance(m, str) else m[0] if isinstance(m, tuple) else str(m)
                # Skip WAT noise (memory offsets, etc)
                if len(set(val)) > 3 and not val.startswith("0000"):
                    real_matches.append(val[:40])
            if real_matches:
                finding = {
                    "type": name,
                    "description": spec["desc"],
                    "count": len(real_matches),
                    "severity": "HIGH",
                    "samples": real_matches[:5],
                }
                findings["hardcoded"].append(finding)
                findings["severity_counts"]["HIGH"] += 1
                print(f"  🟠 Hardcoded: {spec['desc']} ({len(real_matches)} found)")

    # --- Detect exports (crypto API surface) ---
    for category, pattern in WASM_CRYPTO_EXPORTS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        for m in matches:
            findings["exports"].append({"category": category, "name": m})
            print(f"  📤 Export: {category} → {m}")

    # --- Detect imports ---
    import_pattern = r'\(import\s+"([^"]+)"\s+"([^"]+)"'
    imports = re.findall(import_pattern, content)
    for module, name in imports:
        if any(k in name.lower() for k in ["crypto", "random", "key", "hash", "sign", "seal"]):
            findings["imports"].append({"module": module, "name": name})
            print(f"  📥 Import: {module}.{name}")

    # --- Detect memory patterns ---
    # Look for large data sections that could be lookup tables or constants
    data_sections = re.findall(r'\(data\s+.*?"(.{20,})"', content)
    if data_sections:
        findings["raw_stats"]["data_sections"] = len(data_sections)
        # Check for S-box patterns (AES, DES)
        for ds in data_sections:
            entropy = len(set(ds)) / max(len(ds), 1)
            if 0.5 < entropy < 0.9 and len(ds) >= 64:
                findings["raw_stats"].setdefault("potential_sbox", 0)
                findings["raw_stats"]["potential_sbox"] += 1

    # --- String extraction ---
    strings = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{3,50})"', content)
    crypto_strings = [s for s in strings if any(
        k in s.lower() for k in [
            "crypt", "cipher", "key", "sign", "hash", "rand", "seal",
            "nonce", "salt", "iv", "hmac", "pbkdf", "derive", "secret",
            "aes", "rsa", "ecdh", "ecdsa", "ed25519", "chacha", "poly"
        ]
    )]
    if crypto_strings:
        unique_cs = list(set(crypto_strings))
        findings["raw_stats"]["crypto_strings"] = unique_cs[:50]
        print(f"  🔍 Crypto-related strings: {len(unique_cs)} unique")

    return findings


def analyze_wasm_binary(wasm_path: str) -> dict:
    """Direct binary analysis of WASM file (without decompilation)."""
    findings = {"binary_analysis": {}}

    try:
        data = Path(wasm_path).read_bytes()
    except Exception as e:
        print(f"  [-] Cannot read binary: {e}")
        return findings

    findings["binary_analysis"]["size"] = len(data)

    # WASM magic number check
    if data[:4] != b'\x00asm':
        print("  [-] Not a valid WASM file")
        return findings

    version = int.from_bytes(data[4:8], "little")
    findings["binary_analysis"]["wasm_version"] = version
    print(f"  [+] WASM version: {version}")

    # Search for readable strings in binary
    strings = re.findall(rb'[\x20-\x7e]{6,}', data)
    crypto_strings = []
    for s in strings:
        decoded = s.decode("ascii", errors="replace")
        if any(k in decoded.lower() for k in [
            "aes", "rsa", "chacha", "poly1305", "sha", "md5", "hmac",
            "encrypt", "decrypt", "sign", "verify", "key", "cipher",
            "nonce", "salt", "pbkdf", "hkdf", "argon", "blake",
            "curve25519", "ed25519", "x25519", "ecdh", "ecdsa",
            "gcm", "cbc", "ctr", "ecb", "pkcs", "oaep",
            "secretbox", "box_open", "crypto_box", "nacl",
            "sodium", "libsodium", "tweetnacl",
        ]):
            crypto_strings.append(decoded)

    unique_strings = sorted(set(crypto_strings))
    findings["binary_analysis"]["crypto_strings"] = unique_strings
    print(f"  [+] Binary crypto strings: {len(unique_strings)}")
    for s in unique_strings[:20]:
        print(f"      → {s[:80]}")

    # Detect known crypto library signatures
    lib_sigs = {
        "libsodium": [b"libsodium", b"sodium_init", b"crypto_secretbox"],
        "tweetnacl": [b"tweetnacl", b"crypto_box_keypair"],
        "openssl": [b"OpenSSL", b"EVP_Encrypt", b"EVP_Digest"],
        "ring": [b"ring::aead", b"ring::digest"],
        "rustcrypto": [b"aes_gcm", b"chacha20poly1305"],
        "webcrypto_shim": [b"SubtleCrypto", b"CryptoKey"],
        "sjcl": [b"sjcl", b"sjcl.codec"],
        "nacl": [b"crypto_box", b"crypto_sign", b"crypto_hash"],
    }

    detected_libs = []
    for lib_name, sigs in lib_sigs.items():
        for sig in sigs:
            if sig in data:
                detected_libs.append(lib_name)
                break

    findings["binary_analysis"]["detected_libraries"] = list(set(detected_libs))
    if detected_libs:
        print(f"  [+] Detected crypto libraries: {', '.join(set(detected_libs))}")

    # Entropy analysis (sections with high entropy = encrypted/compressed data)
    chunk_size = 4096
    high_entropy_chunks = 0
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) < chunk_size:
            break
        byte_counts = Counter(chunk)
        entropy = -sum(
            (c / chunk_size) * (c / chunk_size).__class__(2).__rpow__(c / chunk_size)
            if c > 0 else 0
            for c in byte_counts.values()
        )
        # Simplified: just count unique bytes ratio
        unique_ratio = len(byte_counts) / 256
        if unique_ratio > 0.9:
            high_entropy_chunks += 1

    total_chunks = len(data) // chunk_size
    findings["binary_analysis"]["high_entropy_ratio"] = (
        high_entropy_chunks / total_chunks if total_chunks > 0 else 0
    )

    return findings


def run_wasm_analysis(target_url: str = None, wasm_path: str = None,
                      output_dir: str = "/tmp/e2e-audit") -> dict:
    """Main entry point for WASM analysis."""
    print("=" * 70)
    print("WASM CRYPTO ANALYZER")
    print("=" * 70)

    results = {
        "module": "wasm_analyzer",
        "findings": [],
        "summary": {},
    }

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    wasm_files = []
    if wasm_path:
        wasm_files = [wasm_path]
    elif target_url:
        print(f"\n[*] Downloading WASM from {target_url}...")
        wasm_files = download_wasm(target_url, str(output_path / "wasm"))

    if not wasm_files:
        print("  [-] No WASM files found. Provide --wasm-path or --url with .wasm files")
        return results

    all_findings = []
    for wf in wasm_files:
        print(f"\n[*] Analyzing: {wf}")

        # Binary analysis
        print("\n  --- Binary Analysis ---")
        bin_findings = analyze_wasm_binary(wf)
        all_findings.append(bin_findings)

        # Decompile + WAT analysis
        print("\n  --- Decompilation ---")
        wat_path = decompile_wasm(wf, str(output_path / "wat"))
        if wat_path:
            print("\n  --- WAT Analysis ---")
            wat_findings = analyze_wat(wat_path)
            all_findings.append({"wat_analysis": wat_findings})

    results["findings"] = all_findings

    # Summary
    total_critical = sum(
        f.get("wat_analysis", {}).get("severity_counts", {}).get("CRITICAL", 0)
        for f in all_findings
    )
    total_high = sum(
        f.get("wat_analysis", {}).get("severity_counts", {}).get("HIGH", 0)
        for f in all_findings
    )
    results["summary"] = {
        "files_analyzed": len(wasm_files),
        "critical": total_critical,
        "high": total_high,
    }

    # Save results
    report_path = output_path / "wasm_analysis.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[+] Report saved: {report_path}")

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="WASM Crypto Analyzer")
    parser.add_argument("--url", help="Target URL to crawl for WASM files")
    parser.add_argument("--wasm-path", help="Path to local WASM file")
    parser.add_argument("--output", default="/tmp/e2e-audit", help="Output directory")
    args = parser.parse_args()
    run_wasm_analysis(target_url=args.url, wasm_path=args.wasm_path, output_dir=args.output)
