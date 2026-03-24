"""Conditional routing: trigger downstream tools based on CWE findings."""

from __future__ import annotations

import logging

from prefect import task

from orchestrator.config import CWE_TRIGGERS, ENDPOINT_PRODUCERS
from orchestrator.tasks.docker_task import ScanResult, run_docker_tool

logger = logging.getLogger("orchestrator.conditional")


@task(log_prints=True)
def route_findings(results: list[ScanResult], scan_ctx: dict) -> list[ScanResult]:
    """Analyze completed results and trigger conditional downstream scans.

    Rules:
    - If nuclei/zap find CWE-918 → launch ssrf-scanner
    - If nuclei/zap find CWE-79 → launch xss-scanner
    - If api-discovery/katana find endpoints → inject into DAST tools
    - If secret-leak finds keys → log CRITICAL alert immediately
    """
    triggered: list[ScanResult] = []
    already_ran = {r.tool for r in results}

    # ── CWE-based triggers ────────────────────────────────────────
    for result in results:
        if not result.findings:
            continue

        for cwe_id, downstream_tools in CWE_TRIGGERS.items():
            if result.has_cwe(cwe_id):
                for tool in downstream_tools:
                    if tool not in already_ran:
                        logger.info(
                            "Conditional trigger: %s found %s → launching %s",
                            result.tool, cwe_id, tool,
                        )
                        res = run_docker_tool.fn(tool, scan_ctx)
                        triggered.append(res)
                        already_ran.add(tool)

    # ── Secret leak alert ─────────────────────────────────────────
    for result in results:
        if result.tool == "secret-leak" and result.findings:
            critical_secrets = [
                f for f in result.findings
                if f.get("severity", "").lower() in ("critical", "high")
            ]
            if critical_secrets:
                logger.critical(
                    "SECRET LEAK ALERT: %d high/critical secrets found! "
                    "Review reports/secret-leak/ immediately.",
                    len(critical_secrets),
                )

    # ── Endpoint enrichment (log for now, Phase 3 will inject) ───
    all_endpoints: list[str] = []
    for result in results:
        if result.tool in ENDPOINT_PRODUCERS:
            for f in result.findings:
                url = f.get("url") or f.get("endpoint") or f.get("matched_at")
                if url:
                    all_endpoints.append(url)

    if all_endpoints:
        unique = sorted(set(all_endpoints))
        logger.info(
            "Discovered %d unique endpoints from %s producers — "
            "available for downstream injection.",
            len(unique),
            ", ".join(ENDPOINT_PRODUCERS),
        )

    return triggered
