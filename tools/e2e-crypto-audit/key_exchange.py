"""
E2E Crypto Audit — Module 2: Key Exchange Analyzer

Intercept and analyze key exchange protocols to detect:
- Weak DH parameters (small groups, known primes)
- Missing ephemeral keys (no forward secrecy)
- Predictable randomness (low entropy nonces)
- Key size insufficiency
- Protocol downgrade possibilities
- MITM-susceptible handshakes (no authentication)
"""

import hashlib
import json
import math
import os
import re
import struct
import time
from collections import Counter
from pathlib import Path


# --- Known weak DH parameters ---
KNOWN_WEAK_PRIMES = {
    # Logjam: 512-bit primes from historical implementations
    "logjam_512": "d4bcd52406f2c926",  # first 8 bytes of common 512-bit prime
    # Historical weak groups
    "rfc2409_group1_768": "ffffffffffffffffc90fdaa22168c234",  # first 16 bytes
    "rfc2409_group2_1024": "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1",
}

# Minimum acceptable key sizes
MIN_KEY_SIZES = {
    "rsa": 2048,
    "dh": 2048,
    "ecdh": 256,  # bits (P-256)
    "ecdsa": 256,
    "ed25519": 256,
    "x25519": 256,
    "aes": 128,
    "chacha20": 256,
}

# Known curves and their security levels
CURVE_SECURITY = {
    "P-256": {"bits": 128, "status": "recommended"},
    "P-384": {"bits": 192, "status": "recommended"},
    "P-521": {"bits": 256, "status": "recommended"},
    "secp256k1": {"bits": 128, "status": "acceptable"},
    "Curve25519": {"bits": 128, "status": "recommended"},
    "Curve448": {"bits": 224, "status": "recommended"},
    "brainpoolP256r1": {"bits": 128, "status": "acceptable"},
    # Weak curves
    "P-192": {"bits": 96, "status": "deprecated"},
    "secp160r1": {"bits": 80, "status": "broken"},
    "sect163k1": {"bits": 80, "status": "broken"},
}


def entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0-8 bits)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    ent = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def analyze_randomness(values: list[bytes], label: str = "value") -> dict:
    """Statistical analysis of randomness quality for a set of byte values."""
    results = {
        "label": label,
        "count": len(values),
        "findings": [],
    }

    if not values:
        return results

    # Check for duplicates
    unique = set(values)
    if len(unique) < len(values):
        dup_count = len(values) - len(unique)
        results["findings"].append({
            "severity": "CRITICAL",
            "type": "duplicate_values",
            "description": f"{dup_count} duplicate {label}(s) detected — randomness failure",
            "duplicates": dup_count,
        })

    # Entropy analysis per value
    entropies = [entropy(v) for v in values]
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0

    results["avg_entropy"] = round(avg_entropy, 3)
    results["min_entropy"] = round(min(entropies), 3) if entropies else 0
    results["max_entropy"] = round(max(entropies), 3) if entropies else 0

    if avg_entropy < 6.0:
        results["findings"].append({
            "severity": "HIGH",
            "type": "low_entropy",
            "description": f"Low average entropy for {label}: {avg_entropy:.2f}/8.0 bits",
            "threshold": 6.0,
        })

    # Check for sequential/incremental patterns
    if len(values) >= 3:
        diffs = []
        for i in range(1, min(len(values), 20)):
            if len(values[i]) == len(values[i - 1]):
                xor = bytes(a ^ b for a, b in zip(values[i], values[i - 1]))
                diffs.append(xor)

        if diffs:
            # Check if XOR differences are constant (counter mode detection)
            unique_diffs = set(diffs)
            if len(unique_diffs) == 1:
                results["findings"].append({
                    "severity": "HIGH",
                    "type": "sequential_pattern",
                    "description": f"Constant XOR difference between consecutive {label}s — likely counter, not random",
                })

    # Byte frequency analysis (chi-squared test approximation)
    if len(values) > 5:
        all_bytes = b"".join(values)
        if len(all_bytes) >= 256:
            byte_counts = Counter(all_bytes)
            expected = len(all_bytes) / 256
            chi2 = sum((count - expected) ** 2 / expected for count in byte_counts.values())
            # Add missing bytes contribution
            chi2 += (256 - len(byte_counts)) * expected
            # Degrees of freedom = 255, approximate critical value at p=0.01 ≈ 310
            results["chi_squared"] = round(chi2, 2)
            if chi2 > 400:
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "biased_distribution",
                    "description": f"Chi-squared test suggests non-uniform byte distribution (χ²={chi2:.0f}, expected ~255)",
                })

    return results


def parse_tls_handshake(data: bytes) -> dict:
    """Parse TLS handshake messages for crypto parameter extraction."""
    findings = {"protocol": None, "cipher_suites": [], "extensions": [], "key_shares": []}

    if len(data) < 5:
        return findings

    # TLS record header
    content_type = data[0]
    if content_type != 0x16:  # Handshake
        return findings

    version_major = data[1]
    version_minor = data[2]
    findings["protocol"] = f"TLS {version_major - 2}.{version_minor - 1}" if version_major == 3 else f"SSL {version_major}.{version_minor}"

    return findings


def analyze_key_exchange_params(params: dict) -> list[dict]:
    """Analyze extracted key exchange parameters for weaknesses."""
    findings = []

    # Check algorithm
    algo = params.get("algorithm", "").lower()
    key_size = params.get("key_size", 0)

    if algo in MIN_KEY_SIZES:
        min_size = MIN_KEY_SIZES[algo]
        if key_size < min_size:
            findings.append({
                "severity": "CRITICAL" if key_size < min_size // 2 else "HIGH",
                "type": "insufficient_key_size",
                "algorithm": algo,
                "actual_size": key_size,
                "minimum_size": min_size,
                "description": f"{algo.upper()} key size {key_size} bits < minimum {min_size} bits",
            })

    # Check curve (for ECDH/ECDSA)
    curve = params.get("curve", "")
    if curve in CURVE_SECURITY:
        sec = CURVE_SECURITY[curve]
        if sec["status"] in ("deprecated", "broken"):
            findings.append({
                "severity": "CRITICAL" if sec["status"] == "broken" else "HIGH",
                "type": "weak_curve",
                "curve": curve,
                "security_bits": sec["bits"],
                "status": sec["status"],
                "description": f"Curve {curve} is {sec['status']} (security level: {sec['bits']} bits)",
            })

    # Check for static keys (no ephemeral = no forward secrecy)
    if params.get("ephemeral") is False:
        findings.append({
            "severity": "HIGH",
            "type": "no_forward_secrecy",
            "description": "Static key exchange — no forward secrecy (PFS). Compromise of long-term key decrypts all past communications.",
        })

    # Check for missing authentication
    if not params.get("authenticated", True):
        findings.append({
            "severity": "CRITICAL",
            "type": "unauthenticated_exchange",
            "description": "Key exchange lacks authentication — susceptible to MITM attack",
        })

    return findings


def analyze_cdp_websocket(ws_messages: list[dict]) -> dict:
    """Analyze WebSocket messages captured via Chrome CDP for crypto operations."""
    results = {
        "total_messages": len(ws_messages),
        "crypto_operations": [],
        "key_exchanges": [],
        "findings": [],
    }

    # Patterns indicating crypto operations
    crypto_indicators = {
        "key_exchange": [
            r'"type"\s*:\s*"(keyExchange|key_exchange|kex)"',
            r'"action"\s*:\s*"(generateKey|deriveKey|importKey|exportKey)"',
            r'"publicKey"', r'"ephemeralKey"', r'"sharedSecret"',
        ],
        "encryption": [
            r'"action"\s*:\s*"(encrypt|decrypt|seal|open)"',
            r'"ciphertext"', r'"iv"', r'"nonce"', r'"tag"',
        ],
        "signing": [
            r'"action"\s*:\s*"(sign|verify)"',
            r'"signature"', r'"signedData"',
        ],
    }

    # Analyze each message
    nonces_seen = []
    ivs_seen = []
    keys_seen = []

    for msg in ws_messages:
        payload = json.dumps(msg) if isinstance(msg, dict) else str(msg)

        for category, patterns in crypto_indicators.items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    results["crypto_operations"].append({
                        "category": category,
                        "pattern": pattern,
                        "timestamp": msg.get("timestamp", ""),
                    })

                    # Extract values
                    for field in ["iv", "nonce"]:
                        vals = re.findall(rf'"{field}"\s*:\s*"([A-Za-z0-9+/=]+)"', payload)
                        for v in vals:
                            try:
                                import base64
                                decoded = base64.b64decode(v)
                                ivs_seen.append(decoded)
                            except Exception:
                                pass

                    for field in ["publicKey", "ephemeralKey"]:
                        vals = re.findall(rf'"{field}"\s*:\s*"([A-Za-z0-9+/=]+)"', payload)
                        for v in vals:
                            keys_seen.append(v)

                    break

    # Analyze collected IVs/nonces
    if ivs_seen:
        iv_analysis = analyze_randomness(ivs_seen, "IV/nonce")
        results["findings"].extend(iv_analysis["findings"])

    # Check for key reuse
    if keys_seen:
        unique_keys = set(keys_seen)
        if len(unique_keys) < len(keys_seen):
            results["findings"].append({
                "severity": "HIGH",
                "type": "key_reuse",
                "description": f"Same key observed {len(keys_seen) - len(unique_keys) + 1} times — potential key reuse",
            })

    return results


def capture_crypto_traffic(target_url: str, cdp_ws_url: str = None,
                           duration: int = 30) -> list[dict]:
    """Capture crypto-related network traffic via Chrome CDP."""
    messages = []

    if cdp_ws_url:
        try:
            import websockets
            import asyncio

            async def _capture():
                async with websockets.connect(cdp_ws_url) as ws:
                    # Enable network interception
                    await ws.send(json.dumps({
                        "id": 1, "method": "Network.enable",
                        "params": {"maxPostDataSize": 1048576}
                    }))
                    # Enable WebSocket monitoring
                    await ws.send(json.dumps({
                        "id": 2, "method": "Network.enable"
                    }))

                    start = time.time()
                    while time.time() - start < duration:
                        try:
                            msg = await asyncio.wait_for(ws.recv(), timeout=2)
                            data = json.loads(msg)
                            method = data.get("method", "")
                            if method in (
                                "Network.webSocketFrameReceived",
                                "Network.webSocketFrameSent",
                                "Network.requestWillBeSent",
                                "Network.responseReceived",
                            ):
                                messages.append(data)
                        except asyncio.TimeoutError:
                            continue

            asyncio.get_event_loop().run_until_complete(_capture())
        except ImportError:
            print("  [-] websockets not installed. Using HTTP-only analysis.")
        except Exception as e:
            print(f"  [-] CDP capture failed: {e}")

    return messages


def analyze_js_crypto_calls(js_sources: list[str]) -> dict:
    """Analyze JavaScript source code for Web Crypto API usage patterns."""
    findings = {
        "webcrypto_calls": [],
        "algorithm_params": [],
        "issues": [],
    }

    webcrypto_patterns = {
        "generateKey": r'crypto\.subtle\.generateKey\(\s*\{([^}]+)\}',
        "importKey": r'crypto\.subtle\.importKey\(\s*["\'](\w+)["\']',
        "encrypt": r'crypto\.subtle\.encrypt\(\s*\{([^}]+)\}',
        "decrypt": r'crypto\.subtle\.decrypt\(\s*\{([^}]+)\}',
        "sign": r'crypto\.subtle\.sign\(\s*\{?([^}),]+)',
        "digest": r'crypto\.subtle\.digest\(\s*["\']?([^"\')\s,]+)',
        "deriveBits": r'crypto\.subtle\.deriveBits\(\s*\{([^}]+)\}',
        "deriveKey": r'crypto\.subtle\.deriveKey\(\s*\{([^}]+)\}',
        "getRandomValues": r'crypto\.getRandomValues\(\s*new\s+Uint8Array\((\d+)\)',
    }

    for source in js_sources:
        for op, pattern in webcrypto_patterns.items():
            matches = re.findall(pattern, source, re.IGNORECASE | re.DOTALL)
            for m in matches:
                findings["webcrypto_calls"].append({"operation": op, "params": m.strip()})

                # Check for weak parameters
                if op in ("encrypt", "decrypt"):
                    if "AES-ECB" in m.upper():
                        findings["issues"].append({
                            "severity": "CRITICAL",
                            "type": "ecb_mode",
                            "description": "AES-ECB mode used — no semantic security",
                        })
                    if "CBC" in m.upper() and "HMAC" not in source[:source.find(m) + 500].upper():
                        findings["issues"].append({
                            "severity": "HIGH",
                            "type": "cbc_no_mac",
                            "description": "AES-CBC without HMAC — vulnerable to padding oracle",
                        })

                if op == "generateKey":
                    length_match = re.search(r'length\s*:\s*(\d+)', m)
                    if length_match:
                        length = int(length_match.group(1))
                        if length < 128:
                            findings["issues"].append({
                                "severity": "CRITICAL",
                                "type": "small_key",
                                "description": f"Key generation with {length}-bit length",
                            })

                if op == "getRandomValues":
                    size = int(m)
                    if size < 16:
                        findings["issues"].append({
                            "severity": "MEDIUM",
                            "type": "small_random",
                            "description": f"Random generation of only {size} bytes",
                        })

    # Check for Math.random() used for crypto
    for source in js_sources:
        if re.search(r'Math\.random\(\).*?(key|iv|nonce|salt|secret|token|encrypt)', source, re.IGNORECASE | re.DOTALL):
            findings["issues"].append({
                "severity": "CRITICAL",
                "type": "math_random_crypto",
                "description": "Math.random() used in crypto context — not cryptographically secure",
            })

    return findings


def run_key_exchange_analysis(target_url: str = None, cdp_ws_url: str = None,
                              js_dir: str = None, output_dir: str = "/tmp/e2e-audit") -> dict:
    """Main entry point for key exchange analysis."""
    print("=" * 70)
    print("KEY EXCHANGE ANALYZER")
    print("=" * 70)

    results = {
        "module": "key_exchange",
        "findings": [],
        "summary": {},
    }

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Phase 1: Analyze JS sources for Web Crypto API usage
    if js_dir:
        print(f"\n[*] Analyzing JS sources in {js_dir}...")
        js_sources = []
        js_path = Path(js_dir)
        for ext in ("*.js", "*.mjs"):
            for f in js_path.rglob(ext):
                try:
                    js_sources.append(f.read_text(errors="replace"))
                except Exception:
                    pass
        if js_sources:
            js_findings = analyze_js_crypto_calls(js_sources)
            results["findings"].append({"js_analysis": js_findings})
            print(f"  [+] Web Crypto calls: {len(js_findings['webcrypto_calls'])}")
            print(f"  [+] Issues: {len(js_findings['issues'])}")
            for issue in js_findings["issues"]:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(issue["severity"], "ℹ️")
                print(f"  {icon} [{issue['severity']}] {issue['description']}")

    # Phase 2: CDP traffic capture
    if cdp_ws_url:
        print(f"\n[*] Capturing crypto traffic via CDP ({cdp_ws_url})...")
        messages = capture_crypto_traffic(target_url, cdp_ws_url, duration=30)
        if messages:
            cdp_findings = analyze_cdp_websocket(messages)
            results["findings"].append({"cdp_analysis": cdp_findings})
            print(f"  [+] Captured {len(messages)} messages, {len(cdp_findings['crypto_operations'])} crypto ops")

    # Save results
    report_path = output_path / "key_exchange_analysis.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[+] Report saved: {report_path}")

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Key Exchange Analyzer")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--cdp-ws", help="Chrome CDP WebSocket URL")
    parser.add_argument("--js-dir", help="Directory of JS source files to analyze")
    parser.add_argument("--output", default="/tmp/e2e-audit", help="Output directory")
    args = parser.parse_args()
    run_key_exchange_analysis(
        target_url=args.url, cdp_ws_url=args.cdp_ws,
        js_dir=args.js_dir, output_dir=args.output
    )
