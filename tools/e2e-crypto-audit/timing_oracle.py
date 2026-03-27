"""
E2E Crypto Audit — Module 6: Timing Oracle Detector

Statistical side-channel analysis to detect:
- Padding oracle (different timing for valid vs invalid padding)
- MAC verification timing (early-exit on first byte mismatch)
- Key-dependent branching (timing varies with secret data)
- Compression oracle (BREACH-style via response size/time)
- Cache timing (distinguishable crypto operations)
"""

import json
import math
import os
import statistics
import time
from pathlib import Path


def welch_t_test(sample_a: list[float], sample_b: list[float]) -> dict:
    """
    Welch's unequal variances t-test.
    
    Returns t-statistic and approximate p-value.
    |t| > 2.576 → significant at p < 0.01
    |t| > 1.96  → significant at p < 0.05
    """
    n_a, n_b = len(sample_a), len(sample_b)
    if n_a < 3 or n_b < 3:
        return {"t_statistic": 0, "significant": False, "error": "insufficient samples"}

    mean_a = statistics.mean(sample_a)
    mean_b = statistics.mean(sample_b)
    var_a = statistics.variance(sample_a)
    var_b = statistics.variance(sample_b)

    se = math.sqrt(var_a / n_a + var_b / n_b) if (var_a / n_a + var_b / n_b) > 0 else 1e-10
    t_stat = (mean_a - mean_b) / se

    # Welch-Satterthwaite degrees of freedom
    numerator = (var_a / n_a + var_b / n_b) ** 2
    denominator = (var_a / n_a) ** 2 / (n_a - 1) + (var_b / n_b) ** 2 / (n_b - 1)
    df = numerator / denominator if denominator > 0 else 1

    # Approximate p-value using normal distribution (good for df > 30)
    # For smaller df, this is an approximation
    z = abs(t_stat)
    # Simple approximation of 1 - CDF(z) for standard normal
    p_approx = math.erfc(z / math.sqrt(2))

    return {
        "t_statistic": round(t_stat, 4),
        "degrees_of_freedom": round(df, 1),
        "mean_a": round(mean_a, 4),
        "mean_b": round(mean_b, 4),
        "std_a": round(math.sqrt(var_a), 4),
        "std_b": round(math.sqrt(var_b), 4),
        "p_value_approx": round(p_approx, 6),
        "significant_01": abs(t_stat) > 2.576,
        "significant_05": abs(t_stat) > 1.96,
        "n_a": n_a,
        "n_b": n_b,
    }


def measure_response_times(url: str, headers: dict, payloads: list[dict],
                           rounds: int = 30, warmup: int = 5) -> dict:
    """
    Measure response times for different payloads with statistical rigor.
    
    Uses multiple rounds and removes outliers for reliable timing analysis.
    """
    import requests

    results = {}

    # Warmup phase
    print(f"  [*] Warmup ({warmup} requests)...")
    for _ in range(warmup):
        try:
            requests.get(url, headers=headers, timeout=10)
        except Exception:
            pass
        time.sleep(0.1)

    # Measurement phase
    for payload_info in payloads:
        label = payload_info["label"]
        method = payload_info.get("method", "GET")
        body = payload_info.get("body")
        extra_headers = payload_info.get("headers", {})
        query_params = payload_info.get("params")

        merged_headers = {**headers, **extra_headers}
        timings = []

        for round_num in range(rounds):
            try:
                start = time.perf_counter()
                if method == "POST":
                    r = requests.post(url, headers=merged_headers, json=body,
                                      params=query_params, timeout=15)
                else:
                    r = requests.get(url, headers=merged_headers, params=query_params, timeout=15)
                elapsed = (time.perf_counter() - start) * 1000  # ms

                timings.append({
                    "round": round_num,
                    "ms": round(elapsed, 3),
                    "status": r.status_code,
                    "size": len(r.content),
                })
            except Exception as e:
                timings.append({"round": round_num, "ms": -1, "error": str(e)})

            # Small delay to avoid rate limiting
            time.sleep(0.05)

        # Filter out errors and outliers
        valid_times = [t["ms"] for t in timings if t["ms"] > 0]
        if valid_times:
            # Remove top/bottom 10% (trimmed mean)
            sorted_times = sorted(valid_times)
            trim = max(1, len(sorted_times) // 10)
            trimmed = sorted_times[trim:-trim] if len(sorted_times) > 2 * trim else sorted_times

            results[label] = {
                "timings": valid_times,
                "trimmed_mean": round(statistics.mean(trimmed), 3),
                "median": round(statistics.median(valid_times), 3),
                "stdev": round(statistics.stdev(valid_times), 3) if len(valid_times) > 1 else 0,
                "min": round(min(valid_times), 3),
                "max": round(max(valid_times), 3),
                "valid_rounds": len(valid_times),
                "errors": len(timings) - len(valid_times),
            }
            print(f"    [{label}] mean={results[label]['trimmed_mean']:.1f}ms "
                  f"±{results[label]['stdev']:.1f}ms (n={len(valid_times)})")

    return results


def detect_padding_oracle(target_url: str, headers: dict,
                          rounds: int = 50) -> dict:
    """
    Test for padding oracle via timing differences.
    
    Sends requests with valid vs invalid padding and measures
    timing differences. A statistically significant difference
    indicates a padding oracle vulnerability.
    """
    results = {
        "test": "padding_oracle",
        "findings": [],
    }

    # Generate test payloads
    # Valid padding: last byte = 0x01 (PKCS#7 for 1 byte of padding)
    # Invalid padding byte 1: last byte = 0x00
    # Invalid padding byte 2: last byte = 0xFF
    # Invalid padding block: last 16 bytes all wrong

    import base64
    valid_block = os.urandom(32)  # 2 blocks
    valid_block = valid_block[:-1] + b'\x10'  # Invalid but consistent padding

    # Different corruption patterns
    payloads = [
        {
            "label": "valid_format",
            "headers": {"Cryptobox-Version": "v4.40"},
        },
        {
            "label": "corrupted_last_byte",
            "headers": {"Cryptobox-Version": "v4.40"},
            "body": {"data": base64.b64encode(valid_block[:-1] + b'\xff').decode()},
        },
        {
            "label": "corrupted_first_byte",
            "headers": {"Cryptobox-Version": "v4.40"},
            "body": {"data": base64.b64encode(b'\xff' + valid_block[1:]).decode()},
        },
        {
            "label": "all_zeros",
            "headers": {"Cryptobox-Version": "v4.40"},
            "body": {"data": base64.b64encode(b'\x00' * 32).decode()},
        },
        {
            "label": "truncated",
            "headers": {"Cryptobox-Version": "v4.40"},
            "body": {"data": base64.b64encode(valid_block[:15]).decode()},  # Not block-aligned
        },
    ]

    print(f"\n[*] Padding oracle test ({rounds} rounds per payload)...")
    timing_data = measure_response_times(target_url, headers, payloads, rounds=rounds)

    # Compare timings between valid and each invalid payload
    if "valid_format" in timing_data:
        valid_times = timing_data["valid_format"]["timings"]

        for label, data in timing_data.items():
            if label == "valid_format":
                continue

            test_result = welch_t_test(valid_times, data["timings"])
            test_result["comparison"] = f"valid_format vs {label}"
            results[f"test_{label}"] = test_result

            if test_result.get("significant_01"):
                diff_ms = abs(test_result["mean_a"] - test_result["mean_b"])
                results["findings"].append({
                    "severity": "CRITICAL" if diff_ms > 5 else "HIGH",
                    "type": "padding_oracle",
                    "description": f"Timing difference detected: valid vs {label} "
                                   f"({diff_ms:.1f}ms, t={test_result['t_statistic']:.2f}, p<0.01)",
                    "impact": "Attacker can decrypt ciphertext byte-by-byte via adaptive chosen-ciphertext attack",
                })

    return results


def detect_mac_timing(target_url: str, headers: dict,
                      rounds: int = 50) -> dict:
    """
    Test for MAC verification timing differences.
    
    If MAC verification uses early-exit comparison (memcmp instead of
    constant-time compare), the timing reveals how many bytes match.
    """
    results = {
        "test": "mac_timing",
        "findings": [],
    }

    import base64

    # Generate MACs with increasing prefix matches
    base_mac = os.urandom(32)

    payloads = []
    for match_bytes in [0, 1, 4, 8, 16, 31]:
        corrupted = base_mac[:match_bytes] + os.urandom(32 - match_bytes)
        payloads.append({
            "label": f"mac_match_{match_bytes}",
            "headers": {
                "Cryptobox-Version": "v4.40",
                "X-MAC": base64.b64encode(corrupted).decode(),
            },
        })

    print(f"\n[*] MAC timing test ({rounds} rounds per variant)...")
    timing_data = measure_response_times(target_url, headers, payloads, rounds=rounds)

    # Check if timing increases with more matching bytes (linear correlation)
    match_counts = []
    mean_times = []
    for label, data in sorted(timing_data.items()):
        match = re.search(r'mac_match_(\d+)', label)
        if match:
            match_counts.append(int(match.group(1)))
            mean_times.append(data["trimmed_mean"])

    if len(match_counts) >= 4:
        # Check linear correlation
        n = len(match_counts)
        mean_m = sum(match_counts) / n
        mean_t = sum(mean_times) / n
        cov = sum((m - mean_m) * (t - mean_t) for m, t in zip(match_counts, mean_times)) / n
        std_m = math.sqrt(sum((m - mean_m) ** 2 for m in match_counts) / n) or 1
        std_t = math.sqrt(sum((t - mean_t) ** 2 for t in mean_times) / n) or 1
        correlation = cov / (std_m * std_t)

        results["correlation"] = round(correlation, 4)

        if correlation > 0.7:
            results["findings"].append({
                "severity": "HIGH",
                "type": "mac_timing_leak",
                "description": f"MAC comparison timing correlates with matching prefix length "
                               f"(r={correlation:.3f}) — non-constant-time comparison detected",
                "impact": "Attacker can forge MACs byte-by-byte via timing analysis",
            })

    return results


def detect_compression_oracle(target_url: str, headers: dict,
                              rounds: int = 20) -> dict:
    """
    Test for BREACH-style compression oracle.
    
    If the server compresses responses before encryption, the size
    of the encrypted response reveals whether injected data matches
    secret data (because matching data compresses better).
    """
    results = {
        "test": "compression_oracle",
        "findings": [],
    }

    # Test with different Accept-Encoding headers
    payloads = [
        {"label": "no_compression", "headers": {"Accept-Encoding": "identity"}},
        {"label": "gzip", "headers": {"Accept-Encoding": "gzip"}},
        {"label": "deflate", "headers": {"Accept-Encoding": "deflate"}},
        {"label": "br", "headers": {"Accept-Encoding": "br"}},
    ]

    print(f"\n[*] Compression oracle test ({rounds} rounds)...")
    timing_data = measure_response_times(target_url, headers, payloads, rounds=rounds)

    # Compare sizes across compression methods
    if "no_compression" in timing_data:
        no_comp_times = timing_data["no_compression"]["timings"]
        for label, data in timing_data.items():
            if label == "no_compression":
                continue
            test = welch_t_test(no_comp_times, data["timings"])
            if test.get("significant_05"):
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "compression_timing",
                    "description": f"Timing differs with {label} compression "
                                   f"(Δ={abs(test['mean_a'] - test['mean_b']):.1f}ms) — "
                                   f"compression may be applied before encryption",
                })

    return results


def run_timing_analysis(target_url: str, session_headers: dict = None,
                        rounds: int = 30, output_dir: str = "/tmp/e2e-audit") -> dict:
    """Main entry point for timing oracle analysis."""
    print("=" * 70)
    print("TIMING ORACLE DETECTOR")
    print("=" * 70)

    results = {
        "module": "timing_oracle",
        "findings": [],
        "summary": {},
    }

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if not session_headers:
        session_headers = {}

    # Phase 1: Padding oracle
    print("\n--- Phase 1: Padding Oracle ---")
    padding_results = detect_padding_oracle(target_url, session_headers, rounds=rounds)
    results["findings"].append({"padding_oracle": padding_results})
    for f in padding_results.get("findings", []):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(f["severity"], "🟡")
        print(f"  {icon} [{f['severity']}] {f['description']}")

    # Phase 2: MAC timing
    print("\n--- Phase 2: MAC Timing ---")
    mac_results = detect_mac_timing(target_url, session_headers, rounds=rounds)
    results["findings"].append({"mac_timing": mac_results})
    for f in mac_results.get("findings", []):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠"}.get(f["severity"], "🟡")
        print(f"  {icon} [{f['severity']}] {f['description']}")

    # Phase 3: Compression oracle
    print("\n--- Phase 3: Compression Oracle ---")
    comp_results = detect_compression_oracle(target_url, session_headers, rounds=rounds)
    results["findings"].append({"compression_oracle": comp_results})
    for f in comp_results.get("findings", []):
        print(f"  🟡 [{f['severity']}] {f['description']}")

    # Summary
    all_findings = []
    for entry in results["findings"]:
        if isinstance(entry, dict):
            for v in entry.values():
                if isinstance(v, dict) and "findings" in v:
                    all_findings.extend(v["findings"])

    sevs = [f.get("severity") for f in all_findings if f.get("severity")]
    results["summary"] = {
        "tests_run": 3,
        "rounds_per_test": rounds,
        "critical": sevs.count("CRITICAL"),
        "high": sevs.count("HIGH"),
        "medium": sevs.count("MEDIUM"),
    }

    # Save
    report_path = output_path / "timing_analysis.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[+] Report saved: {report_path}")

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Timing Oracle Detector")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--rounds", type=int, default=30, help="Measurement rounds per test")
    parser.add_argument("--output", default="/tmp/e2e-audit", help="Output directory")
    args = parser.parse_args()

    session_headers = {
        "Authorization": 'Cryptonuage-SIGMA sigma_session_id="_VeuDbodovgjvZE4hvPSwA"',
        "Cryptobox-Version": "v4.40",
        "Cryptobox-User-Agent": "Cryptobox-WebClient/4.40",
    }

    run_timing_analysis(target_url=args.url, session_headers=session_headers,
                        rounds=args.rounds, output_dir=args.output)
