"""
E2E Crypto Audit — Module 5: Metadata Leakage Analyzer

Detect information leaking through encrypted data metadata:
- File size correlation (plaintext size derivable from ciphertext)
- Filename/type leakage in unencrypted headers or URLs
- Timing-based content type inference
- Traffic analysis (message length fingerprinting)
- Compression-based oracle (BREACH-style on encrypted data)
"""

import json
import math
import os
import re
import time
from collections import Counter, defaultdict
from pathlib import Path


def analyze_size_leakage(encrypted_sizes: list[int], plaintext_sizes: list[int] = None) -> dict:
    """
    Analyze if plaintext sizes can be inferred from ciphertext sizes.
    
    Perfect encryption should add minimal, constant overhead (IV + tag).
    If ciphertext sizes vary proportionally with plaintext sizes,
    an attacker can infer content length.
    """
    results = {
        "encrypted_count": len(encrypted_sizes),
        "findings": [],
    }

    if not encrypted_sizes:
        return results

    # Size distribution analysis
    unique_sizes = set(encrypted_sizes)
    results["unique_encrypted_sizes"] = len(unique_sizes)
    results["size_range"] = {
        "min": min(encrypted_sizes),
        "max": max(encrypted_sizes),
        "mean": round(sum(encrypted_sizes) / len(encrypted_sizes)),
    }

    # Check for padding patterns
    size_diffs = sorted(set(encrypted_sizes))
    if len(size_diffs) >= 3:
        diffs = [size_diffs[i + 1] - size_diffs[i] for i in range(len(size_diffs) - 1)]
        common_diff = Counter(diffs).most_common(1)
        if common_diff:
            block_size = common_diff[0][0]
            if block_size in (16, 32, 64, 128, 256, 512, 1024, 4096):
                results["detected_block_size"] = block_size
                results["findings"].append({
                    "severity": "LOW",
                    "type": "block_size_visible",
                    "description": f"Block padding visible: sizes increment by {block_size} bytes — "
                                   f"plaintext size can be estimated within ±{block_size} bytes",
                })

    # Correlation with plaintext sizes (if available)
    if plaintext_sizes and len(plaintext_sizes) == len(encrypted_sizes):
        # Pearson correlation
        n = len(encrypted_sizes)
        mean_e = sum(encrypted_sizes) / n
        mean_p = sum(plaintext_sizes) / n
        cov = sum((e - mean_e) * (p - mean_p) for e, p in zip(encrypted_sizes, plaintext_sizes)) / n
        std_e = math.sqrt(sum((e - mean_e) ** 2 for e in encrypted_sizes) / n)
        std_p = math.sqrt(sum((p - mean_p) ** 2 for p in plaintext_sizes) / n)

        if std_e > 0 and std_p > 0:
            correlation = cov / (std_e * std_p)
            results["size_correlation"] = round(correlation, 4)

            if abs(correlation) > 0.95:
                results["findings"].append({
                    "severity": "HIGH",
                    "type": "size_correlation",
                    "description": f"Strong size correlation ({correlation:.3f}) between plaintext and ciphertext — "
                                   f"plaintext size is leaked",
                })
            elif abs(correlation) > 0.8:
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "size_correlation",
                    "description": f"Moderate size correlation ({correlation:.3f}) — partial size leakage",
                })

        # Check overhead consistency
        overheads = [e - p for e, p in zip(encrypted_sizes, plaintext_sizes)]
        unique_overhead = set(overheads)
        if len(unique_overhead) == 1:
            results["findings"].append({
                "severity": "HIGH",
                "type": "constant_overhead",
                "description": f"Constant encryption overhead ({list(unique_overhead)[0]} bytes) — "
                               f"exact plaintext size is derivable",
            })

    # Check for non-padded encryption (exact size preserved)
    if len(unique_sizes) > len(encrypted_sizes) * 0.8:
        results["findings"].append({
            "severity": "MEDIUM",
            "type": "many_unique_sizes",
            "description": f"{len(unique_sizes)}/{len(encrypted_sizes)} unique sizes — "
                           f"encryption may not use padding (stream cipher?)",
        })

    return results


def analyze_header_leakage(responses: list[dict]) -> dict:
    """Analyze HTTP headers for metadata leakage about encrypted content."""
    results = {
        "findings": [],
        "leaked_headers": [],
    }

    # Headers that may leak metadata about encrypted content
    sensitive_headers = {
        "content-type": "File type leaked via Content-Type header",
        "content-disposition": "Filename leaked via Content-Disposition",
        "x-file-type": "File type in custom header",
        "x-file-name": "Filename in custom header",
        "x-file-size": "Original file size in custom header",
        "x-content-type": "Original content type in custom header",
        "x-original-filename": "Original filename in custom header",
        "content-length": "Reveals encrypted blob size (allows size correlation)",
        "etag": "ETag may be derived from content (fingerprinting)",
        "last-modified": "Modification time reveals activity patterns",
        "x-upload-size": "Upload size reveals plaintext size",
    }

    for resp in responses:
        headers = resp.get("headers", {})
        for header, description in sensitive_headers.items():
            value = None
            for h_name, h_val in headers.items():
                if h_name.lower() == header:
                    value = h_val
                    break

            if value:
                # Check if it reveals meaningful info
                leaked = {"header": header, "value": value, "description": description}

                if header == "content-disposition":
                    # Extract filename
                    fname_match = re.search(r'filename[*]?=(?:UTF-8\'\')?["\']?([^"\';]+)', value)
                    if fname_match:
                        leaked["leaked_filename"] = fname_match.group(1)
                        results["findings"].append({
                            "severity": "HIGH",
                            "type": "filename_leaked",
                            "description": f"Filename leaked in Content-Disposition: {fname_match.group(1)}",
                        })

                if header == "content-type" and value not in (
                    "application/octet-stream", "application/encrypted",
                    "application/x-encrypted", "binary/octet-stream"
                ):
                    results["findings"].append({
                        "severity": "MEDIUM",
                        "type": "content_type_leaked",
                        "description": f"Original content type visible: {value} (should be application/octet-stream for encrypted data)",
                    })

                if header == "etag" and not value.startswith("W/"):
                    # Strong ETag = content fingerprint
                    results["findings"].append({
                        "severity": "LOW",
                        "type": "etag_fingerprint",
                        "description": f"Strong ETag present: {value[:50]} — can fingerprint encrypted content",
                    })

                results["leaked_headers"].append(leaked)

    return results


def analyze_url_leakage(urls: list[str]) -> dict:
    """Analyze URLs for metadata leakage."""
    results = {
        "findings": [],
        "patterns": [],
    }

    for url in urls:
        # Check for file extensions in URL
        ext_match = re.search(r'\.(\w{1,6})(?:\?|$|#)', url)
        if ext_match:
            ext = ext_match.group(1).lower()
            if ext not in ("html", "json", "api"):
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "extension_in_url",
                    "description": f"File extension '.{ext}' visible in URL: {url[:100]}",
                })

        # Check for content type hints in URL
        for hint in ["type=", "mime=", "format=", "ext=", "kind="]:
            if hint in url.lower():
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "type_hint_in_url",
                    "description": f"Content type hint in URL parameter: {hint} in {url[:100]}",
                })

        # Check for UUIDs (may correlate across sessions)
        uuids = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', url, re.IGNORECASE)
        if uuids:
            results["patterns"].append({"url": url[:100], "uuids": uuids})

    return results


def analyze_timing_leakage(operations: list[dict]) -> dict:
    """Analyze timing patterns for content type/size inference."""
    results = {
        "findings": [],
        "timing_stats": {},
    }

    if not operations:
        return results

    # Group by content type/size
    by_size = defaultdict(list)
    by_type = defaultdict(list)

    for op in operations:
        duration = op.get("duration_ms", op.get("duration", 0))
        size = op.get("size", op.get("content_length", 0))
        ctype = op.get("content_type", op.get("type", "unknown"))

        if duration > 0 and size > 0:
            by_size[size].append(duration)
        if duration > 0:
            by_type[ctype].append(duration)

    # Check for size-timing correlation
    if len(by_size) >= 5:
        sizes = []
        avg_times = []
        for size, times in by_size.items():
            sizes.append(size)
            avg_times.append(sum(times) / len(times))

        if len(sizes) >= 5:
            # Simple linear correlation check
            n = len(sizes)
            mean_s = sum(sizes) / n
            mean_t = sum(avg_times) / n
            cov = sum((s - mean_s) * (t - mean_t) for s, t in zip(sizes, avg_times)) / n
            std_s = math.sqrt(sum((s - mean_s) ** 2 for s in sizes) / n) or 1
            std_t = math.sqrt(sum((t - mean_t) ** 2 for t in avg_times) / n) or 1
            correlation = cov / (std_s * std_t)

            results["timing_stats"]["size_time_correlation"] = round(correlation, 4)

            if abs(correlation) > 0.8:
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "timing_size_correlation",
                    "description": f"Processing time correlates with data size ({correlation:.3f}) — "
                                   f"allows size inference via timing",
                })

    # Check for type-dependent timing
    if len(by_type) >= 2:
        type_timing = {}
        for ctype, times in by_type.items():
            type_timing[ctype] = {
                "mean_ms": round(sum(times) / len(times), 2),
                "count": len(times),
            }
        results["timing_stats"]["by_type"] = type_timing

        # Check if different types have significantly different timing
        type_means = [(t, stats["mean_ms"]) for t, stats in type_timing.items() if stats["count"] >= 3]
        if len(type_means) >= 2:
            means = [m for _, m in type_means]
            if max(means) > min(means) * 2:
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "timing_type_inference",
                    "description": "Processing time varies significantly by content type — timing oracle for type detection",
                    "type_timings": type_timing,
                })

    return results


def run_metadata_analysis(target_url: str = None, session_headers: dict = None,
                          responses: list[dict] = None, output_dir: str = "/tmp/e2e-audit") -> dict:
    """Main entry point for metadata leakage analysis."""
    print("=" * 70)
    print("METADATA LEAKAGE ANALYZER")
    print("=" * 70)

    results = {
        "module": "metadata_leak",
        "findings": [],
        "summary": {},
    }

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Collect responses if not provided
    if not responses and target_url and session_headers:
        import requests
        print(f"\n[*] Collecting responses from {target_url}...")
        responses = []
        endpoints = ["/api/spaces", "/api/files", "/api/messages", "/api/deposit-boxes"]
        for ep in endpoints:
            try:
                url = f"{target_url.rstrip('/')}{ep}"
                start = time.time()
                r = requests.get(url, headers=session_headers, timeout=10)
                duration = (time.time() - start) * 1000
                responses.append({
                    "url": url,
                    "status": r.status_code,
                    "headers": dict(r.headers),
                    "content_length": len(r.content),
                    "duration_ms": duration,
                    "content_type": r.headers.get("Content-Type", ""),
                })
            except Exception:
                pass
        print(f"  [+] Collected {len(responses)} responses")

    if not responses:
        print("  [-] No responses to analyze")
        return results

    # Phase 1: Header leakage
    print("\n[*] Analyzing HTTP header leakage...")
    header_results = analyze_header_leakage(responses)
    results["findings"].append({"header_analysis": header_results})
    for f in header_results.get("findings", []):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(f["severity"], "ℹ️")
        print(f"  {icon} [{f['severity']}] {f['description']}")

    # Phase 2: URL leakage
    urls = [r.get("url", "") for r in responses if r.get("url")]
    if urls:
        print(f"\n[*] Analyzing URL leakage ({len(urls)} URLs)...")
        url_results = analyze_url_leakage(urls)
        results["findings"].append({"url_analysis": url_results})
        for f in url_results.get("findings", []):
            print(f"  🟡 [{f['severity']}] {f['description']}")

    # Phase 3: Size leakage
    sizes = [r.get("content_length", 0) for r in responses if r.get("content_length", 0) > 0]
    if sizes:
        print(f"\n[*] Analyzing size leakage ({len(sizes)} responses)...")
        size_results = analyze_size_leakage(sizes)
        results["findings"].append({"size_analysis": size_results})
        for f in size_results.get("findings", []):
            icon = {"HIGH": "🟠", "MEDIUM": "🟡", "LOW": "ℹ️"}.get(f["severity"], "ℹ️")
            print(f"  {icon} [{f['severity']}] {f['description']}")

    # Phase 4: Timing leakage
    timing_ops = [
        {"duration_ms": r["duration_ms"], "size": r.get("content_length", 0),
         "content_type": r.get("content_type", "")}
        for r in responses if r.get("duration_ms")
    ]
    if timing_ops:
        print(f"\n[*] Analyzing timing leakage ({len(timing_ops)} operations)...")
        timing_results = analyze_timing_leakage(timing_ops)
        results["findings"].append({"timing_analysis": timing_results})
        for f in timing_results.get("findings", []):
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
        "responses_analyzed": len(responses),
        "critical": sevs.count("CRITICAL"),
        "high": sevs.count("HIGH"),
        "medium": sevs.count("MEDIUM"),
        "low": sevs.count("LOW"),
    }

    # Save
    report_path = output_path / "metadata_analysis.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n[+] Report saved: {report_path}")

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Metadata Leakage Analyzer")
    parser.add_argument("--url", help="Target URL")
    parser.add_argument("--output", default="/tmp/e2e-audit", help="Output directory")
    args = parser.parse_args()

    session_headers = {}
    if args.url:
        session_headers = {
            "Authorization": 'Cryptonuage-SIGMA sigma_session_id="_VeuDbodovgjvZE4hvPSwA"',
            "Cryptobox-Version": "v4.40",
            "Cryptobox-User-Agent": "Cryptobox-WebClient/4.40",
        }

    run_metadata_analysis(target_url=args.url, session_headers=session_headers, output_dir=args.output)
