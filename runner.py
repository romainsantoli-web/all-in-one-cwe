#!/usr/bin/env python3
# ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""
Scan runner — orchestrates multiple Python scanner tools sequentially.

Called by /api/scans/trigger with:
  python3 runner.py --target <url> --profile <light|medium|full>
                    --rate-limit <n> --job-id <uuid> [--tools t1,t2] [--dry-run]
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
SCANNERS_DIR = PROJECT_ROOT / "tools" / "python-scanners"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Map tool slug to Python script filename
def tool_to_script(tool_name: str) -> Path:
    return SCANNERS_DIR / (tool_name.replace("-", "_") + ".py")


def run_tool(python_bin: str, tool: str, target: str, rate_limit: int, dry_run: bool) -> dict:
    """Run a single scanner tool and return result dict."""
    script = tool_to_script(tool)
    if not script.exists():
        return {"tool": tool, "status": "skipped", "reason": f"Script not found: {script.name}"}

    output_dir = REPORTS_DIR / tool
    output_dir.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        "TARGET": target,
        "OUTPUT_DIR": str(output_dir),
        "SCAN_DATE": time.strftime("%Y-%m-%d"),
        "SCANNER_RATE_LIMIT": str(rate_limit),
    }

    if dry_run:
        return {"tool": tool, "status": "dry-run", "script": str(script)}

    args = [python_bin, str(script), "--target", target]
    t0 = time.time()
    try:
        result = subprocess.run(
            args,
            cwd=str(PROJECT_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=300,  # 5 min per tool max
        )
        elapsed = round(time.time() - t0, 1)

        # Try to count findings from the report file
        report_file = output_dir / "scan-latest.json"
        findings_count = 0
        if report_file.exists():
            try:
                data = json.loads(report_file.read_text())
                if isinstance(data, list):
                    findings_count = len(data)
                elif isinstance(data, dict) and "findings" in data:
                    findings_count = len(data["findings"])
            except (json.JSONDecodeError, KeyError):
                pass

        if result.returncode == 0:
            return {
                "tool": tool,
                "status": "completed",
                "elapsed_s": elapsed,
                "findings": findings_count,
            }
        else:
            return {
                "tool": tool,
                "status": "failed",
                "exit_code": result.returncode,
                "elapsed_s": elapsed,
                "stderr": result.stderr[:500] if result.stderr else "",
            }
    except subprocess.TimeoutExpired:
        return {"tool": tool, "status": "timeout", "elapsed_s": 300}
    except Exception as e:
        return {"tool": tool, "status": "error", "error": str(e)[:500]}


def main():
    parser = argparse.ArgumentParser(description="Security scan runner")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--profile", default="light", choices=["light", "medium", "full"])
    parser.add_argument("--rate-limit", type=int, default=10)
    parser.add_argument("--job-id", required=True, help="Job UUID")
    parser.add_argument("--tools", default="", help="Comma-separated tool names")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # Determine Python binary (prefer venv)
    python_bin = os.environ.get("PYTHON_BIN", sys.executable)

    # Parse tool list
    if args.tools:
        tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    else:
        # Default tools by profile
        profile_tools = {
            "light": ["header-classifier", "source-map-scanner", "header-poc-generator"],
            "medium": ["header-classifier", "source-map-scanner", "header-poc-generator",
                       "timing-oracle", "redirect-cors", "xss-scanner"],
            "full": [p.stem.replace("_", "-") for p in SCANNERS_DIR.glob("*.py")
                     if not p.name.startswith("_")],
        }
        tools = profile_tools.get(args.profile, profile_tools["light"])

    print(f"[runner] Job {args.job_id} — {len(tools)} tools, target: {args.target}")
    print(f"[runner] Profile: {args.profile}, rate-limit: {args.rate_limit}")

    results = []
    for i, tool in enumerate(tools, 1):
        print(f"[runner] [{i}/{len(tools)}] Running {tool}...")
        result = run_tool(python_bin, tool, args.target, args.rate_limit, args.dry_run)
        results.append(result)
        print(f"[runner]   → {result['status']}")

        # Rate limiting between tools
        if i < len(tools) and not args.dry_run:
            delay = 1.0 / args.rate_limit if args.rate_limit > 0 else 0.1
            time.sleep(delay)

    # Summary
    completed = sum(1 for r in results if r["status"] == "completed")
    failed = sum(1 for r in results if r["status"] in ("failed", "error", "timeout"))
    total_findings = sum(r.get("findings", 0) for r in results)

    summary = {
        "job_id": args.job_id,
        "target": args.target,
        "profile": args.profile,
        "tools_run": len(results),
        "completed": completed,
        "failed": failed,
        "total_findings": total_findings,
        "results": results,
    }

    # Write summary to reports
    summary_dir = REPORTS_DIR / ".jobs"
    summary_dir.mkdir(parents=True, exist_ok=True)
    summary_file = summary_dir / f"{args.job_id}-summary.json"
    summary_file.write_text(json.dumps(summary, indent=2))

    print(f"[runner] Done: {completed}/{len(results)} completed, {total_findings} findings")
    print(f"[runner] Summary: {summary_file}")

    # Generate unified report so it appears in the Scans page
    merge_script = PROJECT_ROOT / "scripts" / "merge-reports.py"
    if merge_script.exists() and completed > 0 and not args.dry_run:
        scan_date = time.strftime("%Y%m%d-%H%M%S")
        try:
            result = subprocess.run(
                [python_bin, str(merge_script), "--scan-date", scan_date, "--target", args.target],
                cwd=str(PROJECT_ROOT),
                timeout=60,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print(f"[runner] Unified report: unified-report-{scan_date}.json")
            else:
                print(f"[runner] Warning: merge-reports failed (exit {result.returncode}): {result.stderr[-500:] if result.stderr else 'no output'}")
        except Exception as e:
            print(f"[runner] Warning: merge-reports failed: {e}")

    # Exit with 0 if at least one tool completed, 1 if all failed
    sys.exit(0 if completed > 0 or args.dry_run else 1)


if __name__ == "__main__":
    main()
