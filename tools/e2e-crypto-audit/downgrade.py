"""
E2E Crypto Audit — Module 3: Downgrade Attack Detector

Detect protocol/cipher downgrade vulnerabilities:
- Algorithm negotiation manipulation
- Version rollback attacks
- Cipher suite stripping
- Extension removal/modification
- Fallback mechanism abuse
"""

import json
import re
import time
from pathlib import Path


# --- Cipher suite rankings ---
CIPHER_STRENGTH = {
    # Strong (AEAD)
    "AES-256-GCM": {"bits": 256, "tier": "A", "aead": True},
    "AES-128-GCM": {"bits": 128, "tier": "A", "aead": True},
    "CHACHA20-POLY1305": {"bits": 256, "tier": "A", "aead": True},
    "XCHACHA20-POLY1305": {"bits": 256, "tier": "A", "aead": True},
    "AES-256-CCM": {"bits": 256, "tier": "A", "aead": True},
    # Acceptable (non-AEAD but OK)
    "AES-256-CBC": {"bits": 256, "tier": "B", "aead": False},
    "AES-128-CBC": {"bits": 128, "tier": "B", "aead": False},
    "AES-256-CTR": {"bits": 256, "tier": "B", "aead": False},
    "AES-128-CTR": {"bits": 128, "tier": "B", "aead": False},
    # Weak/deprecated
    "3DES": {"bits": 112, "tier": "D", "aead": False},
    "DES": {"bits": 56, "tier": "F", "aead": False},
    "RC4": {"bits": 128, "tier": "F", "aead": False},
    "AES-ECB": {"bits": 128, "tier": "F", "aead": False},
    "BLOWFISH": {"bits": 128, "tier": "D", "aead": False},
    "NULL": {"bits": 0, "tier": "F", "aead": False},
}

# Protocol version strengths
PROTOCOL_STRENGTH = {
    "TLS 1.3": {"tier": "A", "status": "current"},
    "TLS 1.2": {"tier": "B", "status": "acceptable"},
    "TLS 1.1": {"tier": "D", "status": "deprecated"},
    "TLS 1.0": {"tier": "F", "status": "broken"},
    "SSL 3.0": {"tier": "F", "status": "broken"},
    "SSL 2.0": {"tier": "F", "status": "broken"},
}


def analyze_advertised_algorithms(config: dict) -> list[dict]:
    """Analyze which algorithms a client/server advertises and check for weak options."""
    findings = []

    # Check cipher suites
    suites = config.get("cipher_suites", [])
    if not suites:
        suites = config.get("algorithms", [])

    weak_suites = []
    no_aead_suites = []

    for suite in suites:
        suite_upper = suite.upper().replace("-", "_").replace(" ", "_")

        for cipher_name, info in CIPHER_STRENGTH.items():
            normalized = cipher_name.upper().replace("-", "_")
            if normalized in suite_upper:
                if info["tier"] in ("D", "F"):
                    weak_suites.append({"suite": suite, "cipher": cipher_name, "tier": info["tier"]})
                elif not info["aead"]:
                    no_aead_suites.append({"suite": suite, "cipher": cipher_name})
                break

    if weak_suites:
        findings.append({
            "severity": "CRITICAL",
            "type": "weak_cipher_advertised",
            "description": f"Server/client advertises {len(weak_suites)} weak cipher suite(s)",
            "weak_suites": weak_suites,
        })

    if no_aead_suites and len(no_aead_suites) == len(suites):
        findings.append({
            "severity": "HIGH",
            "type": "no_aead_available",
            "description": "No AEAD cipher suites offered — all suites lack authenticated encryption",
            "non_aead_suites": no_aead_suites,
        })

    # Check if the strongest available cipher is negotiated first
    if suites:
        first = suites[0].upper()
        if any(weak in first for weak in ["RC4", "DES", "3DES", "NULL", "ECB"]):
            findings.append({
                "severity": "HIGH",
                "type": "weak_cipher_preferred",
                "description": f"Weak cipher preferred (first in list): {suites[0]}",
            })

    return findings


def test_version_downgrade(target_url: str, headers: dict = None) -> list[dict]:
    """Test if the server accepts downgraded protocol versions."""
    import requests

    findings = []

    if not headers:
        headers = {}

    # Test various version headers that Cryptobox uses
    version_tests = [
        {"header": "Cryptobox-Version", "values": [
            ("v4.40", "current"),
            ("v4.0", "old"),
            ("v3.0", "very_old"),
            ("v2.0", "ancient"),
            ("v1.0", "initial"),
            ("v0.1", "pre_release"),
        ]},
    ]

    for test in version_tests:
        header_name = test["header"]
        for value, label in test["values"]:
            test_headers = {**headers, header_name: value}
            try:
                r = requests.get(target_url, headers=test_headers, timeout=10)
                findings.append({
                    "test": f"{header_name}: {value}",
                    "label": label,
                    "status_code": r.status_code,
                    "response_size": len(r.content),
                    "accepted": r.status_code < 400,
                })
                if r.status_code < 400 and label in ("ancient", "initial", "pre_release"):
                    findings.append({
                        "severity": "HIGH",
                        "type": "version_downgrade",
                        "description": f"Server accepts very old version {value} — potential downgrade path",
                        "header": header_name,
                        "value": value,
                    })
            except Exception as e:
                pass

    return findings


def test_algorithm_negotiation(target_url: str, session_headers: dict) -> list[dict]:
    """Test if server negotiation can be manipulated to use weaker algorithms."""
    import requests

    findings = []

    # Test algorithm preference headers
    algo_tests = [
        # Try to force weak algorithms via common negotiation headers
        {"Cryptobox-Preferred-Cipher": "AES-128-ECB"},
        {"Cryptobox-Preferred-Cipher": "DES"},
        {"Cryptobox-Preferred-Cipher": "RC4"},
        {"Cryptobox-Preferred-Cipher": "NULL"},
        {"Cryptobox-Preferred-Cipher": "none"},
        {"Accept-Crypto": "weak"},
        {"X-Crypto-Level": "legacy"},
        {"X-Crypto-Level": "export"},
        {"X-Downgrade": "true"},
        {"Cryptobox-Algo": "3DES-CBC"},
    ]

    baseline = None
    try:
        r = requests.get(target_url, headers=session_headers, timeout=10)
        baseline = {
            "status": r.status_code,
            "size": len(r.content),
            "headers": dict(r.headers),
        }
    except Exception:
        pass

    for test_headers in algo_tests:
        merged = {**session_headers, **test_headers}
        try:
            r = requests.get(target_url, headers=merged, timeout=10)
            result = {
                "test_headers": test_headers,
                "status_code": r.status_code,
                "response_size": len(r.content),
            }

            # Compare to baseline
            if baseline and r.status_code == baseline["status"]:
                # Check if response differs (algorithm negotiation may have changed)
                for h_name, h_val in r.headers.items():
                    if h_name.lower() not in baseline["headers"]:
                        result["new_header"] = {h_name: h_val}
                    elif baseline["headers"].get(h_name.lower()) != h_val:
                        result["changed_header"] = {
                            h_name: {"before": baseline["headers"].get(h_name.lower()), "after": h_val}
                        }

                if "new_header" in result or "changed_header" in result:
                    findings.append({
                        "severity": "HIGH",
                        "type": "negotiation_manipulation",
                        "description": f"Response headers changed when sending {test_headers}",
                        "details": result,
                    })

            findings.append(result)

        except Exception as e:
            pass

    return findings


def analyze_crypto_config(config_data: dict) -> list[dict]:
    """Analyze a crypto configuration for downgrade vulnerabilities."""
    findings = []

    # Check if fallback is enabled
    fallback = config_data.get("fallback", config_data.get("allow_fallback"))
    if fallback:
        findings.append({
            "severity": "HIGH",
            "type": "fallback_enabled",
            "description": "Crypto fallback mechanism enabled — allows downgrade to weaker algorithms",
        })

    # Check minimum version
    min_version = config_data.get("min_version", config_data.get("minimum_protocol"))
    if min_version and any(old in str(min_version).lower() for old in ["ssl", "tls1.0", "tls1.1", "tls 1.0", "tls 1.1"]):
        findings.append({
            "severity": "CRITICAL",
            "type": "old_protocol_allowed",
            "description": f"Minimum protocol version allows deprecated: {min_version}",
        })

    # Check for export ciphers
    if config_data.get("allow_export", False):
        findings.append({
            "severity": "CRITICAL",
            "type": "export_ciphers",
            "description": "Export-grade ciphers allowed — trivially breakable (40/56-bit keys)",
        })

    # Check compression (BREACH/CRIME)
    if config_data.get("compression", config_data.get("allow_compression")):
        findings.append({
            "severity": "MEDIUM",
            "type": "compression_enabled",
            "description": "TLS compression enabled — vulnerable to BREACH/CRIME attacks",
        })

    # Check renegotiation
    if config_data.get("allow_renegotiation", config_data.get("renegotiation")):
        findings.append({
            "severity": "MEDIUM",
            "type": "renegotiation_allowed",
            "description": "TLS renegotiation allowed — potential DoS and triple-handshake attack vector",
        })

    return findings


def run_downgrade_analysis(target_url: str = None, session_headers: dict = None,
                           config_path: str = None, output_dir: str = "/tmp/e2e-audit") -> dict:
    """Main entry point for downgrade attack detection."""
    print("=" * 70)
    print("DOWNGRADE ATTACK DETECTOR")
    print("=" * 70)

    results = {
        "module": "downgrade",
        "findings": [],
        "summary": {},
    }

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if not session_headers:
        session_headers = {}

    # Phase 1: Config analysis
    if config_path:
        print(f"\n[*] Analyzing config: {config_path}")
        try:
            config = json.loads(Path(config_path).read_text())
            config_findings = analyze_crypto_config(config)
            results["findings"].extend(config_findings)
            for f in config_findings:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "ℹ️")
                print(f"  {icon} [{f['severity']}] {f['description']}")
        except Exception as e:
            print(f"  [-] Config read error: {e}")

    # Phase 2: Version downgrade testing
    if target_url:
        print(f"\n[*] Testing version downgrade on {target_url}...")
        version_findings = test_version_downgrade(target_url, session_headers)
        vuln_findings = [f for f in version_findings if f.get("severity")]
        results["findings"].extend(version_findings)
        for f in vuln_findings:
            print(f"  🟠 [{f['severity']}] {f['description']}")

    # Phase 3: Algorithm negotiation testing
    if target_url:
        print(f"\n[*] Testing algorithm negotiation manipulation...")
        algo_findings = test_algorithm_negotiation(target_url, session_headers)
        vuln_algo = [f for f in algo_findings if f.get("severity")]
        results["findings"].extend(algo_findings)
        for f in vuln_algo:
            print(f"  🟠 [{f['severity']}] {f['description']}")

    # Summary
    sevs = [f.get("severity") for f in results["findings"] if f.get("severity")]
    results["summary"] = {
        "critical": sevs.count("CRITICAL"),
        "high": sevs.count("HIGH"),
        "medium": sevs.count("MEDIUM"),
        "total_tests": len(results["findings"]),
    }

    # Save
    report_path = output_path / "downgrade_analysis.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[+] Report saved: {report_path}")

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Downgrade Attack Detector")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--config", help="Path to crypto config JSON")
    parser.add_argument("--output", default="/tmp/e2e-audit", help="Output directory")
    args = parser.parse_args()
    run_downgrade_analysis(target_url=args.url, config_path=args.config, output_dir=args.output)
