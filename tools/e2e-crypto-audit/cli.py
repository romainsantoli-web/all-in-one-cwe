#!/usr/bin/env python3
"""
E2E Crypto Audit — Unified CLI

Comprehensive end-to-end cryptography audit tool targeting:
- WASM binary reverse engineering (crypto algorithm detection)
- Key exchange weakness analysis
- Protocol downgrade attack detection
- IV/nonce reuse and key reuse detection
- Encrypted metadata leakage
- Timing oracle side-channels

Usage:
    # Run all modules against a target
    python cli.py --url https://bounty.cryptobox.com --all

    # Run specific modules
    python cli.py --url https://bounty.cryptobox.com --modules wasm,timing,iv

    # Analyze local WASM file
    python cli.py --wasm-path ./libcryptobox.wasm --modules wasm

    # Analyze JS sources for Web Crypto API usage
    python cli.py --js-dir ./source_maps/ --modules keyexchange

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path


# Module imports
from wasm_analyzer import run_wasm_analysis
from key_exchange import run_key_exchange_analysis
from downgrade import run_downgrade_analysis
from iv_analysis import run_iv_analysis
from metadata_leak import run_metadata_analysis
from timing_oracle import run_timing_analysis


MODULES = {
    "wasm": {
        "name": "WASM Crypto Analyzer",
        "description": "Reverse-engineer WASM binaries for crypto weaknesses",
        "function": "run_wasm",
    },
    "keyexchange": {
        "name": "Key Exchange Analyzer",
        "description": "Analyze key exchange protocols and Web Crypto API usage",
        "function": "run_keyexchange",
    },
    "downgrade": {
        "name": "Downgrade Attack Detector",
        "description": "Test for protocol/cipher downgrade vulnerabilities",
        "function": "run_downgrade",
    },
    "iv": {
        "name": "IV/Key Reuse Analyzer",
        "description": "Detect nonce reuse, key reuse, and predictable IVs",
        "function": "run_iv",
    },
    "metadata": {
        "name": "Metadata Leakage Analyzer",
        "description": "Find information leaking through encrypted data metadata",
        "function": "run_metadata",
    },
    "timing": {
        "name": "Timing Oracle Detector",
        "description": "Statistical side-channel analysis (padding oracle, MAC timing)",
        "function": "run_timing",
    },
}

# Default Cryptobox session headers
DEFAULT_HEADERS = {
    "Authorization": 'Cryptonuage-SIGMA sigma_session_id="_VeuDbodovgjvZE4hvPSwA"',
    "Cryptobox-Version": "v4.40",
    "Cryptobox-User-Agent": "Cryptobox-WebClient/4.40",
}


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║           E2E CRYPTO AUDIT TOOLKIT v1.0.0                   ║
║     End-to-End Encryption Security Assessment Tool          ║
╠══════════════════════════════════════════════════════════════╣
║  Modules:                                                    ║
║    1. WASM Binary Analyzer        (reverse engineering)      ║
║    2. Key Exchange Analyzer       (protocol weaknesses)      ║
║    3. Downgrade Attack Detector   (cipher stripping)         ║
║    4. IV/Key Reuse Analyzer       (nonce reuse / XOR)        ║
║    5. Metadata Leakage Analyzer   (size/timing/headers)      ║
║    6. Timing Oracle Detector      (statistical analysis)     ║
╚══════════════════════════════════════════════════════════════╝
    """)


def run_wasm(args, output_dir):
    return run_wasm_analysis(
        target_url=args.url,
        wasm_path=args.wasm_path,
        output_dir=output_dir,
    )


def run_keyexchange(args, output_dir):
    return run_key_exchange_analysis(
        target_url=args.url,
        cdp_ws_url=args.cdp_ws,
        js_dir=args.js_dir,
        output_dir=output_dir,
    )


def run_downgrade(args, output_dir):
    headers = DEFAULT_HEADERS.copy()
    if args.session_id:
        headers["Authorization"] = f'Cryptonuage-SIGMA sigma_session_id="{args.session_id}"'
    return run_downgrade_analysis(
        target_url=args.url,
        session_headers=headers,
        config_path=args.crypto_config,
        output_dir=output_dir,
    )


def run_iv(args, output_dir):
    headers = DEFAULT_HEADERS.copy()
    if args.session_id:
        headers["Authorization"] = f'Cryptonuage-SIGMA sigma_session_id="{args.session_id}"'
    return run_iv_analysis(
        target_url=args.url,
        session_headers=headers,
        ciphertext_dir=args.ct_dir,
        iv_size=args.iv_size,
        output_dir=output_dir,
    )


def run_metadata(args, output_dir):
    headers = DEFAULT_HEADERS.copy()
    if args.session_id:
        headers["Authorization"] = f'Cryptonuage-SIGMA sigma_session_id="{args.session_id}"'
    return run_metadata_analysis(
        target_url=args.url,
        session_headers=headers,
        output_dir=output_dir,
    )


def run_timing(args, output_dir):
    headers = DEFAULT_HEADERS.copy()
    if args.session_id:
        headers["Authorization"] = f'Cryptonuage-SIGMA sigma_session_id="{args.session_id}"'
    return run_timing_analysis(
        target_url=args.url,
        session_headers=headers,
        rounds=args.rounds,
        output_dir=output_dir,
    )


MODULE_RUNNERS = {
    "wasm": run_wasm,
    "keyexchange": run_keyexchange,
    "downgrade": run_downgrade,
    "iv": run_iv,
    "metadata": run_metadata,
    "timing": run_timing,
}


def generate_report(all_results: dict, output_dir: str) -> str:
    """Generate a consolidated Markdown report from all module results."""
    report_lines = [
        "# E2E Crypto Audit Report",
        f"\n**Date**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"**Target**: {all_results.get('target', 'N/A')}",
        f"**Modules Run**: {', '.join(all_results.get('modules_run', []))}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    total_critical = 0
    total_high = 0
    total_medium = 0

    for module_name, result in all_results.get("results", {}).items():
        summary = result.get("summary", {})
        c = summary.get("critical", 0)
        h = summary.get("high", 0)
        m = summary.get("medium", 0)
        total_critical += c
        total_high += h
        total_medium += m

    report_lines.extend([
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 CRITICAL | {total_critical} |",
        f"| 🟠 HIGH | {total_high} |",
        f"| 🟡 MEDIUM | {total_medium} |",
        "",
    ])

    # Per-module details
    for module_name, result in all_results.get("results", {}).items():
        module_info = MODULES.get(module_name, {})
        report_lines.extend([
            f"## {module_info.get('name', module_name)}",
            "",
            f"_{module_info.get('description', '')}_",
            "",
        ])

        findings = result.get("findings", [])
        if not findings:
            report_lines.append("No findings.")
        else:
            for finding_group in findings:
                if isinstance(finding_group, dict):
                    for category, details in finding_group.items():
                        if isinstance(details, dict):
                            sub_findings = details.get("findings", [])
                            if sub_findings:
                                report_lines.append(f"### {category}")
                                report_lines.append("")
                                for f in sub_findings:
                                    sev = f.get("severity", "INFO")
                                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "ℹ️"}.get(sev, "ℹ️")
                                    report_lines.append(f"- {icon} **[{sev}]** {f.get('description', f.get('type', ''))}")
                                    if f.get("impact"):
                                        report_lines.append(f"  - **Impact**: {f['impact']}")
                                report_lines.append("")

        report_lines.append("---")
        report_lines.append("")

    # Disclaimer
    report_lines.extend([
        "",
        "---",
        "",
        "⚠️ Contenu généré par IA — validation humaine requise avant utilisation.",
        "",
    ])

    report_content = "\n".join(report_lines)

    # Save
    report_path = os.path.join(output_dir, "AUDIT-REPORT.md")
    with open(report_path, "w") as f:
        f.write(report_content)

    # Also save JSON
    json_path = os.path.join(output_dir, "audit-report.json")
    with open(json_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    return report_path


def main():
    parser = argparse.ArgumentParser(
        description="E2E Crypto Audit Toolkit — End-to-End Encryption Security Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://bounty.cryptobox.com --all
  %(prog)s --url https://target.com --modules wasm,timing,iv
  %(prog)s --wasm-path ./module.wasm --modules wasm
  %(prog)s --js-dir ./sources/ --modules keyexchange
        """
    )

    # Target options
    parser.add_argument("--url", help="Target base URL (e.g., https://bounty.cryptobox.com)")
    parser.add_argument("--session-id", help="Session ID for authenticated requests")

    # Module selection
    parser.add_argument("--all", action="store_true", help="Run all modules")
    parser.add_argument("--modules", help=f"Comma-separated module list: {','.join(MODULES.keys())}")
    parser.add_argument("--list-modules", action="store_true", help="List available modules")

    # Module-specific options
    parser.add_argument("--wasm-path", help="Path to local WASM file")
    parser.add_argument("--js-dir", help="Directory of JS source files")
    parser.add_argument("--cdp-ws", help="Chrome CDP WebSocket URL for traffic capture")
    parser.add_argument("--ct-dir", help="Directory of ciphertext files for IV analysis")
    parser.add_argument("--iv-size", type=int, default=12, help="IV size in bytes (default: 12)")
    parser.add_argument("--crypto-config", help="Path to crypto config JSON file")
    parser.add_argument("--rounds", type=int, default=30, help="Timing test rounds (default: 30)")

    # Output options
    parser.add_argument("--output", default="/tmp/e2e-audit", help="Output directory")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    # List modules
    if args.list_modules:
        print("\nAvailable modules:\n")
        for key, info in MODULES.items():
            print(f"  {key:15s} — {info['description']}")
        print(f"\nUse --all or --modules {','.join(MODULES.keys())}")
        return

    if not args.quiet:
        banner()

    # Determine which modules to run
    if args.all:
        modules_to_run = list(MODULES.keys())
    elif args.modules:
        modules_to_run = [m.strip().lower() for m in args.modules.split(",")]
        invalid = [m for m in modules_to_run if m not in MODULES]
        if invalid:
            print(f"Unknown modules: {', '.join(invalid)}")
            print(f"Available: {', '.join(MODULES.keys())}")
            sys.exit(1)
    else:
        # Auto-detect based on provided arguments
        modules_to_run = []
        if args.wasm_path:
            modules_to_run.append("wasm")
        if args.js_dir or args.cdp_ws:
            modules_to_run.append("keyexchange")
        if args.ct_dir:
            modules_to_run.append("iv")
        if args.url and not modules_to_run:
            # Default: run all network-based modules
            modules_to_run = ["downgrade", "metadata", "timing"]

    if not modules_to_run:
        print("No modules selected. Use --all, --modules, or provide target-specific options.")
        parser.print_help()
        sys.exit(1)

    # Create output directory
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    # Run selected modules
    all_results = {
        "target": args.url or args.wasm_path or args.js_dir or "local",
        "modules_run": modules_to_run,
        "start_time": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        "results": {},
    }

    for module in modules_to_run:
        print(f"\n{'=' * 70}")
        print(f"  Running: {MODULES[module]['name']}")
        print(f"{'=' * 70}")

        runner = MODULE_RUNNERS.get(module)
        if runner:
            try:
                result = runner(args, output_dir)
                all_results["results"][module] = result
            except Exception as e:
                print(f"\n  [ERROR] Module {module} failed: {e}")
                all_results["results"][module] = {"error": str(e)}
        else:
            print(f"  [SKIP] Module {module} has no runner")

    # Generate consolidated report
    all_results["end_time"] = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
    report_path = generate_report(all_results, output_dir)

    # Final summary
    total_c = sum(r.get("summary", {}).get("critical", 0) for r in all_results["results"].values())
    total_h = sum(r.get("summary", {}).get("high", 0) for r in all_results["results"].values())
    total_m = sum(r.get("summary", {}).get("medium", 0) for r in all_results["results"].values())

    print(f"\n{'=' * 70}")
    print(f"  AUDIT COMPLETE")
    print(f"{'=' * 70}")
    print(f"  Modules run: {len(modules_to_run)}")
    print(f"  Findings: {total_c} CRITICAL, {total_h} HIGH, {total_m} MEDIUM")
    print(f"  Report: {report_path}")
    print(f"  JSON:   {output_dir}/audit-report.json")
    print(f"{'=' * 70}")

    if args.json:
        print(json.dumps(all_results, indent=2, default=str))

    # Exit code based on severity
    if total_c > 0:
        sys.exit(2)
    elif total_h > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
