#!/usr/bin/env python3
"""Smart scan runner — orchestrates Scope → Memory → Graph → Scan → Analyze → Ingest.

Ties together all 4 modules (LLM, Memory, Scope, Graph) into a single
intelligent scan pipeline that:
  1. Loads scope (targets, restrictions)
  2. Recalls memory (past findings on similar targets)
  3. Builds tool graph (smart tool selection)
  4. Runs orchestrated scan (Prefect DAG)
  5. Filters results by scope
  6. Analyzes with LLM (memory-augmented)
  7. Ingests findings into memory for future sessions

Usage:
    python scripts/smart_scan.py --target https://example.com --domain example.com
    python scripts/smart_scan.py --scope configs/scope-example.yaml
    python scripts/smart_scan.py --config configs/smart-config.yaml
    python scripts/smart_scan.py --target https://example.com --smart-select

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from graph import DependencyGraph  # noqa: E402
from memory.scan_memory import ScanMemory  # noqa: E402
from scope import ScopeEnforcer, ScopeParser  # noqa: E402

logger = logging.getLogger("smart_scan")

# Tool profiles matching Makefile targets
PROFILES = {
    "light": [
        "nuclei", "zap-baseline", "testssl", "sqlmap", "semgrep", "gitleaks",
        "trivy", "idor-scanner", "auth-bypass", "secret-leak", "api-discovery",
        "xss-scanner", "httpx", "whatweb", "wafw00f",
    ],
    "medium": [
        "nuclei", "zap-baseline", "testssl", "sqlmap", "semgrep", "gitleaks",
        "trivy", "idor-scanner", "auth-bypass", "secret-leak", "api-discovery",
        "xss-scanner", "httpx", "whatweb", "wafw00f", "subfinder", "katana",
        "amass", "dnsx", "gowitness", "sstimap", "crlfuzz", "ffuf",
        "feroxbuster", "arjun", "nikto", "corscanner", "log4j-scan",
        "trufflehog", "user-enum", "redirect-cors", "oidc-audit",
        "bypass-403-advanced", "ssrf-scanner", "websocket-scanner",
        "cache-deception",
    ],
    "full": None,  # None = all tools
}


def load_config(path: str | None) -> dict:
    """Load smart-config.yaml or return defaults."""
    if path and Path(path).exists():
        import yaml
        return yaml.safe_load(Path(path).read_text()) or {}
    return {}


def smart_select_tools(
    scope_enforcer: ScopeEnforcer | None,
    graph: DependencyGraph,
    memory: ScanMemory | None,
    profile: str,
) -> list[str]:
    """Intelligently select tools based on scope, graph, and memory."""
    # Start with profile tools
    profile_tools = PROFILES.get(profile)
    if profile_tools is None:
        all_tools = graph.all_tools()
    else:
        all_tools = list(profile_tools)

    # Scope-based filtering: suggest tools by target types
    if scope_enforcer:
        suggested = scope_enforcer.suggest_tools(all_tools)
        if suggested:
            # Merge: keep profile tools + add scope suggestions
            for tool in suggested:
                if tool not in all_tools:
                    all_tools.append(tool)
            logger.info("Scope suggested %d tools: %s", len(suggested), suggested)

    # Memory-based prioritization: check what worked on similar targets
    if memory and memory.available and scope_enforcer:
        for target in scope_enforcer.scope.targets:
            past = memory.recall_similar({"url": target.url}, limit=5)
            for item in past:
                tool = item.get("data", {}).get("tool", "")
                if tool and tool not in all_tools:
                    all_tools.append(tool)
                    logger.info("Memory suggested tool: %s (from past finding)", tool)

    return all_tools


def run_smart_scan(args: argparse.Namespace) -> dict:
    """Execute the full smart scan pipeline."""
    config = load_config(args.config)
    scope_cfg = config.get("scope", {})
    memory_cfg = config.get("memory", {})
    graph_cfg = config.get("graph", {})
    llm_cfg = config.get("llm", {})
    scan_cfg = config.get("scan", {})
    report_cfg = config.get("reporting", {})

    result = {
        "pipeline_steps": [],
        "scope": None,
        "tools_selected": [],
        "scan_result": None,
        "findings_in_scope": 0,
        "memory_ingested": 0,
    }

    # ── Step 1: Load Scope ──────────────────────────────
    scope_enforcer = None
    scope_file = args.scope or scope_cfg.get("file", "")
    if scope_file:
        try:
            scope = ScopeParser.from_file(scope_file)
            scope_enforcer = ScopeEnforcer(scope)
            result["scope"] = scope_enforcer.summary()
            result["pipeline_steps"].append("scope_loaded")
            print(f"[scope] Loaded: {scope.name or scope_file} — "
                  f"{len(scope.targets)} targets, "
                  f"{len(scope.out_of_scope)} exclusions")
        except Exception as e:
            print(f"[scope] Failed to load scope: {e}")
    elif args.target:
        # Create minimal scope from target
        scope = ScopeParser.from_urls([args.target])
        scope_enforcer = ScopeEnforcer(scope)

    # ── Step 2: Initialize Memory ───────────────────────
    scan_memory = None
    if memory_cfg.get("enabled", True) and not args.no_memory:
        try:
            scan_memory = ScanMemory()
            if scan_memory.available:
                result["pipeline_steps"].append("memory_connected")
                print(f"[memory] Connected ({scan_memory.stats().get('mode', 'unknown')} mode)")
            else:
                scan_memory = None
        except Exception as e:
            print(f"[memory] Not available: {e}")

    # ── Step 3: Build Graph + Smart Select ─────────────
    graph = DependencyGraph()
    graph.build_from_config()
    result["pipeline_steps"].append("graph_built")
    print(f"[graph] Built: {graph.tool_count} tools, {graph.edge_count} edges")

    profile = args.profile or scan_cfg.get("profile", "medium")
    use_smart = args.smart_select or scan_cfg.get("smart_select", False)

    if use_smart:
        tools = smart_select_tools(scope_enforcer, graph, scan_memory, profile)
        result["pipeline_steps"].append("smart_select")
    else:
        tools = PROFILES.get(profile) or graph.all_tools()

    result["tools_selected"] = tools
    print(f"[tools] Selected {len(tools)} tools (profile={profile}, smart={use_smart})")

    # Show execution order
    waves = graph.execution_order(tools)
    for i, wave in enumerate(waves):
        logger.info("Wave %d: %s", i, ", ".join(wave))

    # ── Step 4: Run Scan ───────────────────────────────
    if args.dry_run:
        print(f"\n[dry-run] Would run {len(tools)} tools in {len(waves)} waves")
        for i, wave in enumerate(waves):
            print(f"  Wave {i}: {', '.join(wave)}")
        result["pipeline_steps"].append("dry_run")
        return result

    # Build scan command
    scan_cmd = [
        sys.executable, "-m", "orchestrator.flows.scan_flow",
        "--target", args.target or "",
        "--domain", args.domain or "",
        "--rate-limit", str(args.rate_limit),
    ]
    if tools:
        scan_cmd.extend(["--only", ",".join(tools)])
    if args.full:
        scan_cmd.append("--full")

    print(f"\n[scan] Starting Prefect DAG — {len(tools)} tools...")
    start = time.time()

    try:
        proc = subprocess.run(
            scan_cmd,
            cwd=str(Path(__file__).parent.parent),
            timeout=args.timeout,
            capture_output=True,
            text=True,
        )
        elapsed = time.time() - start
        result["pipeline_steps"].append("scan_completed")
        print(f"[scan] Completed in {elapsed:.0f}s (exit code: {proc.returncode})")
        if proc.returncode != 0 and proc.stderr:
            logger.warning("Scan stderr: %s", proc.stderr[:500])
    except subprocess.TimeoutExpired:
        print(f"[scan] Timeout after {args.timeout}s")
        result["pipeline_steps"].append("scan_timeout")
    except Exception as e:
        print(f"[scan] Failed: {e}")
        result["pipeline_steps"].append("scan_failed")

    # ── Step 5: Post-processing ────────────────────────
    # Load findings from report
    report_path = _find_latest_report()
    findings = []
    if report_path:
        try:
            data = json.loads(report_path.read_text())
            findings = data.get("findings", data) if isinstance(data, dict) else data
            result["pipeline_steps"].append("report_loaded")
            print(f"[report] Loaded {len(findings)} findings from {report_path.name}")
        except Exception as e:
            logger.warning("Failed to load report: %s", e)

    # Scope filtering
    if scope_enforcer and scope_cfg.get("enforce", True) and findings:
        filtered = scope_enforcer.filter_findings(findings)
        result["findings_in_scope"] = len(filtered)
        result["pipeline_steps"].append("scope_filtered")
        print(f"[scope] {len(filtered)}/{len(findings)} findings in scope")
        if scope_cfg.get("annotate", True):
            findings = scope_enforcer.annotate_findings(filtered)
        else:
            findings = filtered

    # Graph export
    export_path = graph_cfg.get("export_json", "reports/tool-graph.json")
    if export_path:
        graph.export_json(export_path)
        result["pipeline_steps"].append("graph_exported")

    # ── Step 6: AI Analysis ────────────────────────────
    if findings and not args.offline:
        provider = args.provider or llm_cfg.get("provider", "auto")
        max_llm = llm_cfg.get("max_findings", 10)
        threshold = llm_cfg.get("severity_threshold", "high")

        analyze_cmd = [
            sys.executable, "scripts/ai_analyzer.py",
            "--provider", provider,
            "--max-llm", str(max_llm),
        ]
        if report_path:
            analyze_cmd.extend(["--input", str(report_path)])
        if not memory_cfg.get("enabled", True):
            analyze_cmd.append("--no-memory")

        print(f"[analyze] Running LLM analysis (provider={provider}, max={max_llm})...")
        try:
            subprocess.run(
                analyze_cmd,
                cwd=str(Path(__file__).parent.parent),
                timeout=300,
                check=False,
            )
            result["pipeline_steps"].append("llm_analysis")
        except Exception as e:
            logger.warning("LLM analysis failed: %s", e)

    # ── Step 7: Memory Ingest ──────────────────────────
    if scan_memory and scan_memory.available and findings and memory_cfg.get("auto_ingest", True):
        ingested = scan_memory.ingest_findings(findings)
        result["memory_ingested"] = ingested
        result["pipeline_steps"].append("memory_ingested")
        print(f"[memory] Ingested {ingested} findings")

    # ── Step 8: Graph suggestions ──────────────────────
    if graph_cfg.get("auto_suggest", True) and findings:
        suggestions = graph.suggest_from_findings(findings)
        if suggestions:
            result["pipeline_steps"].append("graph_suggestions")
            print(f"[graph] Suggested follow-up tools: {', '.join(suggestions)}")

    # ── Summary ────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"Smart Scan Pipeline Complete")
    print(f"  Steps:     {' → '.join(result['pipeline_steps'])}")
    print(f"  Tools:     {len(result['tools_selected'])}")
    print(f"  Findings:  {result.get('findings_in_scope', len(findings))}")
    print(f"  Memory:    {result['memory_ingested']} ingested")
    print(f"{'='*60}")

    return result


def _find_latest_report() -> Path | None:
    """Find the most recent unified report."""
    reports_dir = Path(__file__).parent.parent / "reports"
    scored = reports_dir / "scored-report.json"
    if scored.exists():
        return scored
    deduped = reports_dir / "deduped-report.json"
    if deduped.exists():
        return deduped
    candidates = sorted(reports_dir.glob("unified-report-*.json"), reverse=True)
    return candidates[0] if candidates else None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Smart Scan — Scope + Memory + Graph + LLM integrated pipeline",
    )
    parser.add_argument("--target", "-t", help="Target URL")
    parser.add_argument("--domain", "-d", help="Target domain")
    parser.add_argument("--scope", "-s", help="Scope file (YAML/JSON/Markdown)")
    parser.add_argument("--config", "-c", default="configs/smart-config.yaml",
                        help="Smart config file (default: configs/smart-config.yaml)")
    parser.add_argument("--profile", choices=["light", "medium", "full"],
                        help="Scan profile (overrides config)")
    parser.add_argument("--smart-select", action="store_true",
                        help="Enable smart tool selection (scope+graph+memory)")
    parser.add_argument("--provider", help="LLM provider override")
    parser.add_argument("--no-memory", action="store_true", help="Disable memory")
    parser.add_argument("--offline", action="store_true", help="Skip LLM analysis")
    parser.add_argument("--full", action="store_true", help="Full/thorough scans")
    parser.add_argument("--dry-run", action="store_true", help="Simulate without scanning")
    parser.add_argument("--rate-limit", type=int, default=50, help="Rate limit (req/s)")
    parser.add_argument("--timeout", type=int, default=7200, help="Global timeout (seconds)")
    args = parser.parse_args()

    if not args.target and not args.scope:
        parser.error("Specify --target or --scope")

    # Auto-derive domain from target
    if not args.domain and args.target:
        from urllib.parse import urlparse
        parsed = urlparse(args.target)
        args.domain = parsed.hostname or ""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    run_smart_scan(args)


if __name__ == "__main__":
    main()
