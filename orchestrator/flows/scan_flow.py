"""Main scan flow — Prefect 3.x DAG replacing runner.sh.

Usage:
    python -m orchestrator.flows.scan_flow --target https://example.com --domain example.com
    python -m orchestrator.flows.scan_flow --target https://example.com --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from prefect import flow
from prefect.futures import wait

from orchestrator.config import PARALLEL_GROUPS, TOOL_META
from orchestrator.tasks.conditional import route_findings
from orchestrator.tasks.docker_task import ScanResult, run_docker_tool

logger = logging.getLogger("orchestrator.scan_flow")

# ---------------------------------------------------------------------------
# Report directory setup (mirrors runner.sh mkdir block)
# ---------------------------------------------------------------------------
REPORT_DIRS = sorted(TOOL_META.keys())


def _ensure_report_dirs() -> None:
    for tool in REPORT_DIRS:
        Path("reports", tool).mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Flow
# ---------------------------------------------------------------------------
@flow(
    name="security-scan",
    description="Full security scan — DAG with parallel groups, retries, and conditionals.",
    log_prints=True,
    timeout_seconds=7200,  # 2h global timeout
)
def security_scan(scan_ctx: dict) -> dict:
    """Execute the full scan DAG.

    Args:
        scan_ctx: Dict with keys: target, domain, code, repo, binary,
                  bin_dir, image, rate_limit, only, skip, full, dry_run,
                  workdir, timeout.

    Returns:
        Summary dict with ok/failed/skipped counts and findings.
    """
    start = datetime.now()
    _ensure_report_dirs()

    # Export env vars for docker compose services
    _export_env(scan_ctx)

    logger.info(
        "Starting security scan — target=%s domain=%s dry_run=%s",
        scan_ctx.get("target", ""),
        scan_ctx.get("domain", ""),
        scan_ctx.get("dry_run", False),
    )

    # Build dependency graph: group name → list of dependency group names
    group_deps: dict[str, list[str]] = {
        g["name"]: g["depends_on"] for g in PARALLEL_GROUPS
    }
    group_tools: dict[str, list[str]] = {
        g["name"]: g["tools"] for g in PARALLEL_GROUPS
    }

    # Track completed groups and all results
    completed_groups: set[str] = set()
    all_results: list[ScanResult] = []

    # Iterative DAG execution: run groups whose deps are satisfied
    max_iterations = len(PARALLEL_GROUPS) + 1
    for _ in range(max_iterations):
        # Find groups ready to run
        ready = [
            name for name, deps in group_deps.items()
            if name not in completed_groups
            and all(d in completed_groups for d in deps)
        ]
        if not ready:
            break

        # Submit all tools in ready groups as parallel futures
        futures_map: dict[str, list] = {}
        for group_name in ready:
            tools = group_tools[group_name]
            futures = []
            for tool in tools:
                future = run_docker_tool.submit(tool, scan_ctx)
                futures.append(future)
            futures_map[group_name] = futures

        # Wait for all groups in this wave
        for group_name, futures in futures_map.items():
            wait(futures)
            for f in futures:
                result = f.result()
                all_results.append(result)
            completed_groups.add(group_name)
            logger.info("Group '%s' completed (%d tools)", group_name, len(futures))

    # ── Conditional routing ───────────────────────────────────────
    triggered = route_findings(all_results, scan_ctx)
    all_results.extend(triggered)

    # ── Report generation ─────────────────────────────────────────
    if not scan_ctx.get("dry_run"):
        _run_report_generation(scan_ctx)

    # ── Summary ───────────────────────────────────────────────────
    elapsed = (datetime.now() - start).total_seconds()
    ok_count = sum(1 for r in all_results if r.ok and r.findings is not None)
    failed = [r.tool for r in all_results if not r.ok]
    total_findings = sum(len(r.findings) for r in all_results)

    summary = {
        "elapsed_seconds": round(elapsed, 1),
        "tools_run": len(all_results),
        "tools_ok": ok_count,
        "tools_failed": failed,
        "total_findings": total_findings,
        "triggered_conditionals": [r.tool for r in triggered],
    }

    logger.info(
        "Scan complete in %.0fs — %d tools run, %d findings, %d failed: %s",
        elapsed, len(all_results), total_findings, len(failed),
        ", ".join(failed) if failed else "none",
    )

    return summary


def _export_env(scan_ctx: dict) -> None:
    """Export scan context as environment variables for docker compose."""
    mapping = {
        "TARGET": scan_ctx.get("target", ""),
        "DOMAIN": scan_ctx.get("domain", ""),
        "CODE": scan_ctx.get("code", "."),
        "REPO": scan_ctx.get("repo", "."),
        "BIN": scan_ctx.get("binary", "/dev/null"),
        "BIN_DIR": scan_ctx.get("bin_dir", "."),
        "IMAGE": scan_ctx.get("image", "alpine:latest"),
        "RATE_LIMIT": str(scan_ctx.get("rate_limit", 50)),
        "SCAN_DATE": scan_ctx.get("scan_date", datetime.now().strftime("%Y%m%d-%H%M%S")),
    }
    for key, val in mapping.items():
        if val:
            os.environ[key] = val


def _run_report_generation(scan_ctx: dict) -> None:
    """Run merge-reports.py and cwe-summary.py (Phase 36 equivalent)."""
    import subprocess

    workdir = scan_ctx.get("workdir", ".")
    scan_date = scan_ctx.get("scan_date", datetime.now().strftime("%Y%m%d-%H%M%S"))

    try:
        subprocess.run(
            [
                sys.executable, "scripts/merge-reports.py",
                "--output", f"reports/unified-report-{scan_date}.json",
            ],
            cwd=workdir, timeout=120, check=False,
        )
        logger.info("Report merge completed.")
    except Exception as e:
        logger.warning("Report merge failed: %s", e)

    try:
        subprocess.run(
            [sys.executable, "scripts/cwe-summary.py"],
            cwd=workdir, timeout=60, check=False,
        )
        logger.info("CWE summary completed.")
    except Exception as e:
        logger.warning("CWE summary failed: %s", e)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Security All-in-One CWE — Prefect Orchestrator",
    )
    parser.add_argument("--target", "-t", help="Target URL")
    parser.add_argument("--domain", "-d", help="Target domain")
    parser.add_argument("--code", default=".", help="Code directory for SAST")
    parser.add_argument("--repo", default=".", help="Git repo for secrets scanning")
    parser.add_argument("--binary", default="", help="Binary file for analysis")
    parser.add_argument("--bin-dir", default=".", help="Binary directory")
    parser.add_argument("--image", default="alpine:latest", help="Docker image to scan")
    parser.add_argument("--rate-limit", type=int, default=50, help="Rate limit (req/s)")
    parser.add_argument("--only", default="", help="Only run these tools (comma-separated)")
    parser.add_argument("--skip", default="", help="Skip these tools (comma-separated)")
    parser.add_argument("--full", action="store_true", help="Enable full/thorough scans")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without running tools")
    parser.add_argument("--timeout", type=int, default=1800, help="Per-tool timeout (seconds)")

    args = parser.parse_args()

    # Auto-derive domain from target
    domain = args.domain
    if not domain and args.target:
        from urllib.parse import urlparse
        parsed = urlparse(args.target)
        domain = parsed.hostname or ""

    scan_ctx = {
        "target": args.target or "",
        "domain": domain or "",
        "code": args.code,
        "repo": args.repo,
        "binary": args.binary,
        "bin_dir": args.bin_dir,
        "image": args.image,
        "rate_limit": args.rate_limit,
        "only": args.only,
        "skip": args.skip,
        "full": args.full,
        "dry_run": args.dry_run,
        "timeout": args.timeout,
        "workdir": str(Path.cwd()),
        "scan_date": datetime.now().strftime("%Y%m%d-%H%M%S"),
    }

    if not any([args.target, args.domain, args.code != ".", args.repo != ".",
                args.binary, args.bin_dir != ".", args.image != "alpine:latest"]):
        parser.error("At least one target must be specified (--target, --domain, --code, etc.)")

    result = security_scan(scan_ctx)
    print(f"\n{'='*60}")
    print(f"Scan Summary:")
    print(f"  Duration:      {result['elapsed_seconds']}s")
    print(f"  Tools run:     {result['tools_run']}")
    print(f"  Tools OK:      {result['tools_ok']}")
    print(f"  Tools failed:  {len(result['tools_failed'])}")
    print(f"  Findings:      {result['total_findings']}")
    print(f"  Conditionals:  {', '.join(result['triggered_conditionals']) or 'none'}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
