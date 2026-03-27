"""
E2E Crypto Audit — Module 4: IV/Key Reuse Analyzer

Detect initialization vector and key reuse vulnerabilities:
- Duplicate IVs/nonces across encryptions (catastrophic for GCM/CTR)
- Counter reuse in stream ciphers
- Predictable IV generation (sequential, time-based)
- XOR analysis for key reuse detection (two-time pad)
- Static key detection across sessions
"""

import base64
import hashlib
import json
import math
import os
import re
import struct
import time
from collections import Counter
from pathlib import Path


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0-8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values() if c > 0)


def hamming_distance(a: bytes, b: bytes) -> int:
    """Bit-level Hamming distance between two byte strings."""
    dist = 0
    for x, y in zip(a, b):
        dist += bin(x ^ y).count('1')
    return dist


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (truncates to shorter)."""
    return bytes(x ^ y for x, y in zip(a, b))


def is_printable_ratio(data: bytes, threshold: float = 0.6) -> float:
    """Return ratio of printable ASCII bytes."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7e)
    return printable / len(data)


def detect_iv_reuse(iv_list: list[bytes]) -> dict:
    """Analyze a collection of IVs/nonces for reuse and weak patterns."""
    results = {
        "total_ivs": len(iv_list),
        "unique_ivs": len(set(iv_list)),
        "findings": [],
    }

    if not iv_list:
        return results

    # --- Duplicate detection (CRITICAL for GCM/CTR) ---
    iv_counts = Counter(iv_list)
    duplicates = {iv.hex(): count for iv, count in iv_counts.items() if count > 1}
    if duplicates:
        results["findings"].append({
            "severity": "CRITICAL",
            "type": "iv_reuse",
            "description": f"IV/nonce reuse detected: {len(duplicates)} unique IV(s) used multiple times",
            "impact": "For AES-GCM: authentication key recovery + plaintext XOR leak. For CTR: two-time pad.",
            "duplicates": {k: v for k, v in list(duplicates.items())[:10]},
        })

    # --- Zero IV detection ---
    zero_ivs = sum(1 for iv in iv_list if all(b == 0 for b in iv))
    if zero_ivs:
        results["findings"].append({
            "severity": "CRITICAL",
            "type": "zero_iv",
            "description": f"{zero_ivs} all-zero IV(s) detected — deterministic encryption",
        })

    # --- Entropy analysis ---
    if len(iv_list) >= 5:
        entropies = [entropy(iv) for iv in iv_list]
        avg_ent = sum(entropies) / len(entropies)
        min_ent = min(entropies)

        results["entropy"] = {
            "average": round(avg_ent, 3),
            "min": round(min_ent, 3),
            "max": round(max(entropies), 3),
        }

        if avg_ent < 5.0:
            results["findings"].append({
                "severity": "HIGH",
                "type": "low_iv_entropy",
                "description": f"Average IV entropy {avg_ent:.2f}/8.0 — IVs may be predictable",
            })

    # --- Sequential detection (counter mode) ---
    if len(iv_list) >= 3:
        sequential = 0
        for i in range(1, min(len(iv_list), 50)):
            if len(iv_list[i]) == len(iv_list[i - 1]):
                # Check if IVs are sequential (incrementing by 1)
                iv_a = int.from_bytes(iv_list[i - 1], "big")
                iv_b = int.from_bytes(iv_list[i], "big")
                if iv_b - iv_a == 1:
                    sequential += 1

        if sequential > len(iv_list) * 0.7:
            results["findings"].append({
                "severity": "MEDIUM",
                "type": "sequential_iv",
                "description": f"IVs appear sequential (counter-based): {sequential}/{min(len(iv_list), 50)} pairs incrementing by 1",
                "note": "Sequential IVs are acceptable with AES-GCM if the counter space is not exhausted. CRITICAL if combined with key reuse.",
            })

    # --- Time-based IV detection ---
    if len(iv_list) >= 2 and all(len(iv) >= 8 for iv in iv_list):
        # Check if IVs contain timestamps
        now = int(time.time())
        time_based = 0
        for iv in iv_list:
            # Check first 4 or 8 bytes as unix timestamp
            for offset in (0, 4):
                try:
                    ts = struct.unpack(">I", iv[offset:offset + 4])[0]
                    if abs(ts - now) < 86400 * 365:  # Within a year
                        time_based += 1
                        break
                except Exception:
                    pass

        if time_based > len(iv_list) * 0.5:
            results["findings"].append({
                "severity": "HIGH",
                "type": "time_based_iv",
                "description": f"IVs appear to contain timestamps: {time_based}/{len(iv_list)} — predictable generation",
                "impact": "Attacker with known plaintext can predict future IVs",
            })

    # --- Hamming distance analysis (detect low-entropy source) ---
    if len(iv_list) >= 10:
        distances = []
        for i in range(min(len(iv_list) - 1, 50)):
            if len(iv_list[i]) == len(iv_list[i + 1]):
                distances.append(hamming_distance(iv_list[i], iv_list[i + 1]))

        if distances:
            avg_dist = sum(distances) / len(distances)
            iv_bits = len(iv_list[0]) * 8
            expected_dist = iv_bits / 2  # Expected for random: half the bits differ

            results["hamming"] = {
                "avg_distance": round(avg_dist, 1),
                "expected_random": round(expected_dist, 1),
                "ratio": round(avg_dist / expected_dist, 3) if expected_dist > 0 else 0,
            }

            if avg_dist < expected_dist * 0.5:
                results["findings"].append({
                    "severity": "HIGH",
                    "type": "low_hamming_distance",
                    "description": f"Average Hamming distance {avg_dist:.0f} bits (expected ~{expected_dist:.0f}) — IVs too similar",
                })

    return results


def detect_key_reuse_xor(ciphertexts: list[bytes], known_plaintexts: list[bytes] = None) -> dict:
    """Detect key reuse via XOR analysis of ciphertexts (two-time pad attack)."""
    results = {
        "total_ciphertexts": len(ciphertexts),
        "findings": [],
        "xor_analysis": [],
    }

    if len(ciphertexts) < 2:
        return results

    # XOR all pairs and check for structure in the result
    pairs_checked = 0
    suspicious_pairs = 0

    for i in range(min(len(ciphertexts), 50)):
        for j in range(i + 1, min(len(ciphertexts), 50)):
            ct_a = ciphertexts[i]
            ct_b = ciphertexts[j]

            if len(ct_a) < 16 or len(ct_b) < 16:
                continue

            xored = xor_bytes(ct_a, ct_b)
            pairs_checked += 1

            # If XOR of two ciphertexts has high printable ratio,
            # it means XOR of plaintexts leaked (same key used)
            printable = is_printable_ratio(xored)

            # All zeros in XOR = identical ciphertexts (same key + same plaintext)
            zero_ratio = sum(1 for b in xored if b == 0) / len(xored)

            analysis = {
                "pair": (i, j),
                "xor_printable_ratio": round(printable, 3),
                "xor_zero_ratio": round(zero_ratio, 3),
                "xor_entropy": round(entropy(xored), 3),
            }

            if zero_ratio > 0.8:
                analysis["verdict"] = "IDENTICAL"
                suspicious_pairs += 1
                results["findings"].append({
                    "severity": "CRITICAL",
                    "type": "identical_ciphertexts",
                    "description": f"Ciphertexts [{i}] and [{j}] are nearly identical — same key AND same plaintext",
                    "zero_ratio": round(zero_ratio, 3),
                })
            elif printable > 0.5:
                analysis["verdict"] = "TWO_TIME_PAD"
                suspicious_pairs += 1
                results["findings"].append({
                    "severity": "CRITICAL",
                    "type": "two_time_pad",
                    "description": f"XOR of ciphertexts [{i}] and [{j}] has {printable:.0%} printable chars — key reuse detected (two-time pad)",
                    "sample_xor": xored[:32].hex(),
                })
            elif entropy(xored) < 4.0:
                analysis["verdict"] = "LOW_ENTROPY"
                suspicious_pairs += 1
                results["findings"].append({
                    "severity": "HIGH",
                    "type": "low_xor_entropy",
                    "description": f"XOR of ciphertexts [{i}] and [{j}] has abnormally low entropy ({entropy(xored):.2f}) — potential key reuse",
                })

            results["xor_analysis"].append(analysis)

    results["summary"] = {
        "pairs_checked": pairs_checked,
        "suspicious_pairs": suspicious_pairs,
    }

    # Known plaintext attack
    if known_plaintexts and ciphertexts:
        for i, (ct, pt) in enumerate(zip(ciphertexts, known_plaintexts)):
            if len(ct) >= len(pt):
                key_candidate = xor_bytes(ct, pt)
                # Try decrypting other ciphertexts with this key
                for j, ct2 in enumerate(ciphertexts):
                    if i != j and len(ct2) >= len(key_candidate):
                        decrypted = xor_bytes(ct2, key_candidate)
                        if is_printable_ratio(decrypted) > 0.7:
                            results["findings"].append({
                                "severity": "CRITICAL",
                                "type": "key_recovery",
                                "description": f"Key recovered from ciphertext[{i}]+plaintext → decrypted ciphertext[{j}]",
                                "decrypted_sample": decrypted[:64].hex(),
                            })

    return results


def collect_ciphertexts_http(target_url: str, headers: dict, count: int = 20) -> list[dict]:
    """
    Collect multiple encrypted responses/files from the target.
    
    Collects HTTP responses from operations that involve encrypted data
    (file uploads, message sends, etc.)
    """
    import requests

    collected = []

    # API endpoints that may return encrypted data
    endpoints = [
        "/api/spaces",
        "/api/files",
        "/api/messages",
        "/api/deposit-boxes",
    ]

    for endpoint in endpoints:
        url = f"{target_url.rstrip('/')}{endpoint}"
        for attempt in range(min(count, 10)):
            try:
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code == 200 and len(r.content) > 0:
                    collected.append({
                        "endpoint": endpoint,
                        "attempt": attempt,
                        "status": r.status_code,
                        "content": r.content,
                        "content_type": r.headers.get("Content-Type", ""),
                        "headers": dict(r.headers),
                    })
            except Exception:
                pass
            time.sleep(0.2)  # Rate limiting

    return collected


def extract_encrypted_blobs(responses: list[dict]) -> list[bytes]:
    """Extract encrypted data blobs from HTTP responses."""
    blobs = []

    for resp in responses:
        content = resp.get("content", b"")
        content_type = resp.get("content_type", "")

        # JSON responses — look for base64 encoded fields
        if "json" in content_type:
            try:
                data = json.loads(content)
                for key in ("ciphertext", "encrypted", "data", "payload", "body", "content"):
                    if key in data:
                        val = data[key]
                        if isinstance(val, str):
                            try:
                                decoded = base64.b64decode(val)
                                if len(decoded) >= 16:
                                    blobs.append(decoded)
                            except Exception:
                                pass
                    # Also check nested objects
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict) and key in item:
                                val = item[key]
                                if isinstance(val, str):
                                    try:
                                        decoded = base64.b64decode(val)
                                        if len(decoded) >= 16:
                                            blobs.append(decoded)
                                    except Exception:
                                        pass
            except Exception:
                pass

        # Binary responses — treat entire body as potential ciphertext
        elif "octet-stream" in content_type or "application/encrypted" in content_type:
            if len(content) >= 16:
                blobs.append(content)

    return blobs


def extract_ivs_from_blobs(blobs: list[bytes], iv_size: int = 12) -> list[bytes]:
    """Extract IVs from encrypted blobs (typically prepended to ciphertext)."""
    ivs = []
    for blob in blobs:
        if len(blob) >= iv_size + 16:
            # IVs are typically prepended
            iv = blob[:iv_size]
            ivs.append(iv)
    return ivs


def run_iv_analysis(target_url: str = None, session_headers: dict = None,
                    ciphertext_dir: str = None, iv_size: int = 12,
                    output_dir: str = "/tmp/e2e-audit") -> dict:
    """Main entry point for IV/key reuse analysis."""
    print("=" * 70)
    print("IV / KEY REUSE ANALYZER")
    print("=" * 70)

    results = {
        "module": "iv_analysis",
        "findings": [],
        "summary": {},
    }

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    ciphertexts = []
    ivs = []

    # Phase 1: Collect from HTTP
    if target_url and session_headers:
        print(f"\n[*] Collecting encrypted data from {target_url}...")
        responses = collect_ciphertexts_http(target_url, session_headers, count=20)
        print(f"  [+] Collected {len(responses)} responses")

        blobs = extract_encrypted_blobs(responses)
        ciphertexts.extend(blobs)
        print(f"  [+] Extracted {len(blobs)} encrypted blobs")

        ivs.extend(extract_ivs_from_blobs(blobs, iv_size))
        print(f"  [+] Extracted {len(ivs)} potential IVs ({iv_size} bytes each)")

    # Phase 2: Analyze local ciphertext files
    if ciphertext_dir:
        print(f"\n[*] Loading ciphertexts from {ciphertext_dir}...")
        ct_path = Path(ciphertext_dir)
        for f in sorted(ct_path.glob("*")):
            if f.is_file() and f.stat().st_size >= 16:
                data = f.read_bytes()
                ciphertexts.append(data)
                ivs.append(data[:iv_size])
        print(f"  [+] Loaded {len(ciphertexts)} ciphertext files")

    # Phase 3: IV analysis
    if ivs:
        print(f"\n[*] Analyzing {len(ivs)} IVs...")
        iv_results = detect_iv_reuse(ivs)
        results["findings"].append({"iv_analysis": iv_results})
        for f in iv_results.get("findings", []):
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "ℹ️")
            print(f"  {icon} [{f['severity']}] {f['description']}")
    else:
        print("\n  [-] No IVs collected for analysis")

    # Phase 4: XOR/key-reuse analysis
    if len(ciphertexts) >= 2:
        print(f"\n[*] Running XOR analysis on {len(ciphertexts)} ciphertexts...")
        xor_results = detect_key_reuse_xor(ciphertexts)
        results["findings"].append({"xor_analysis": xor_results})
        for f in xor_results.get("findings", []):
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f.get("severity", ""), "ℹ️")
            print(f"  {icon} [{f.get('severity', '')}] {f['description']}")
    else:
        print("\n  [-] Need at least 2 ciphertexts for XOR analysis")

    # Summary
    all_findings = []
    for f in results["findings"]:
        if isinstance(f, dict):
            for v in f.values():
                if isinstance(v, dict) and "findings" in v:
                    all_findings.extend(v["findings"])

    sevs = [f.get("severity") for f in all_findings if f.get("severity")]
    results["summary"] = {
        "ciphertexts_analyzed": len(ciphertexts),
        "ivs_analyzed": len(ivs),
        "critical": sevs.count("CRITICAL"),
        "high": sevs.count("HIGH"),
        "medium": sevs.count("MEDIUM"),
    }

    # Save
    report_path = output_path / "iv_analysis.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[+] Report saved: {report_path}")

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="IV/Key Reuse Analyzer")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--ct-dir", help="Directory of ciphertext files")
    parser.add_argument("--iv-size", type=int, default=12, help="IV size in bytes (default: 12 for GCM)")
    parser.add_argument("--output", default="/tmp/e2e-audit", help="Output directory")
    args = parser.parse_args()

    session_headers = {}
    if args.url:
        session_headers = {
            "Authorization": 'Cryptonuage-SIGMA sigma_session_id="_VeuDbodovgjvZE4hvPSwA"',
            "Cryptobox-Version": "v4.40",
            "Cryptobox-User-Agent": "Cryptobox-WebClient/4.40",
        }

    run_iv_analysis(
        target_url=args.url, session_headers=session_headers,
        ciphertext_dir=args.ct_dir, iv_size=args.iv_size, output_dir=args.output
    )
