"""Prefect task: retrieve smart payloads based on scan findings.

Runs between scan waves — uses PayloadEngine to select relevant payloads
based on CWEs found so far, and exports them for downstream scanners.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from prefect import task

from orchestrator.tasks.docker_task import ScanResult

logger = logging.getLogger("orchestrator.payload_task")


@task(log_prints=True)
def get_smart_payloads(
    results: list[ScanResult],
    scan_ctx: dict,
) -> dict[str, list[str]]:
    """Analyze scan results and retrieve relevant payloads.

    Returns: dict mapping scanner-name → list of payload strings.
    Payloads are also exported to reports/payloads/ for Docker scanners.
    """
    from payloads.engine import PayloadEngine
    from payloads.index import CATEGORY_CWE_MAP

    include_high = scan_ctx.get("payload_include_high", False)
    engine = PayloadEngine(include_high=include_high)

    # Collect CWEs from findings
    found_cwes: set[str] = set()
    for result in results:
        for f in result.findings:
            cwe = f.get("cwe") or f.get("cwe_normalized") or ""
            if cwe:
                found_cwes.add(str(cwe).upper())

    if not found_cwes:
        logger.info("No CWEs found in results — skipping payload enrichment")
        return {}

    logger.info("Found CWEs: %s — retrieving targeted payloads", ", ".join(sorted(found_cwes)))

    # Map CWEs to payload categories and retrieve payloads
    scanner_payloads: dict[str, list[str]] = {}

    for cwe in sorted(found_cwes):
        payload_sets = engine.get_payloads_for_cwe(cwe)
        if not payload_sets:
            continue

        # Map CWE to the appropriate downstream scanner
        scanner = _cwe_to_scanner(cwe)
        if scanner not in scanner_payloads:
            scanner_payloads[scanner] = []

        for ps in payload_sets:
            scanner_payloads[scanner].extend(ps.payloads)

    # Deduplicate per scanner
    for scanner in scanner_payloads:
        scanner_payloads[scanner] = list(dict.fromkeys(scanner_payloads[scanner]))

    # Export to disk for Docker scanners to pick up
    _export_payloads(scanner_payloads, scan_ctx)

    total = sum(len(v) for v in scanner_payloads.values())
    logger.info(
        "Payload enrichment: %d payloads for %d scanners from %d CWEs",
        total,
        len(scanner_payloads),
        len(found_cwes),
    )

    return scanner_payloads


def _cwe_to_scanner(cwe: str) -> str:
    """Map a CWE to the most relevant downstream scanner name."""
    mapping = {
        "CWE-79": "xss-scanner",
        "CWE-89": "sqlmap",
        "CWE-918": "ssrf-scanner",
        "CWE-78": "command-injection",
        "CWE-22": "directory-traversal",
        "CWE-94": "ssti-scanner",
        "CWE-611": "xxe-scanner",
        "CWE-502": "deserialization",
        "CWE-601": "open-redirect",
        "CWE-352": "csrf-scanner",
        "CWE-444": "smuggler",
        "CWE-524": "cache-deception",
        "CWE-400": "slowloris-check",
        "CWE-943": "nosql-injection",
        "CWE-90": "ldap-injection",
        "CWE-434": "upload-scanner",
        "CWE-639": "idor-scanner",
        "CWE-347": "jwt-tool",
        "CWE-1321": "ppmap",
    }
    return mapping.get(cwe, "generic")


def _export_payloads(scanner_payloads: dict[str, list[str]], scan_ctx: dict) -> None:
    """Write payload files to reports/payloads/ for Docker scanners."""
    out_dir = Path(scan_ctx.get("workdir", ".")) / "reports" / "payloads"
    out_dir.mkdir(parents=True, exist_ok=True)

    for scanner, payloads in scanner_payloads.items():
        # Write as TXT (one per line) for tools like ffuf/nuclei
        txt_path = out_dir / f"{scanner}-payloads.txt"
        txt_path.write_text("\n".join(payloads) + "\n")

        # Also write as JSON for programmatic consumers
        json_path = out_dir / f"{scanner}-payloads.json"
        json_path.write_text(json.dumps(payloads, indent=2, ensure_ascii=False))

    # Summary file
    summary = {
        scanner: len(payloads)
        for scanner, payloads in scanner_payloads.items()
    }
    summary_path = out_dir / "payload-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    logger.info("Payloads exported to %s", out_dir)
