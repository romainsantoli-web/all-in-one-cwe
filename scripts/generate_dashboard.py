#!/usr/bin/env python3
"""Generate interactive HTML security dashboard from analyzed findings.

Reads the analyzed report (ai_analyzer output or scored report) and renders
a Chart.js-powered dashboard with severity charts, CWE distribution, tool
coverage, CVSS histogram, sortable/filterable table, and expandable details.

Usage:
    python scripts/generate_dashboard.py [--input reports/analyzed-report.json]
    python scripts/generate_dashboard.py --output reports/dashboard.html

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    print("jinja2 required: pip install jinja2>=3.1")
    sys.exit(1)

REPORTS_DIR = Path(__file__).parent.parent / "reports"
TEMPLATES_DIR = Path(__file__).parent / "templates"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _find_latest_report() -> Path | None:
    """Try analyzed → scored → deduped → unified (most to least enriched)."""
    for name in ["analyzed-report.json", "scored-report.json", "deduped-report.json"]:
        p = REPORTS_DIR / name
        if p.exists():
            return p
    candidates = sorted(REPORTS_DIR.glob("unified-report-*.json"), reverse=True)
    return candidates[0] if candidates else None


def _truncate(text: str, maxlen: int = 60) -> str:
    if not text:
        return ""
    return text[:maxlen] + "…" if len(text) > maxlen else text


def _build_chart_data(findings: list[dict]) -> dict:
    # Severity counts (ordered)
    sev_counter = Counter(
        (f.get("severity") or "unknown").lower() for f in findings
    )
    severity_json = {s: sev_counter.get(s, 0) for s in SEVERITY_ORDER if sev_counter.get(s, 0) > 0}

    # Top CWEs
    cwe_counter = Counter(
        f.get("cwe_normalized") or f.get("cwe") or "Unknown"
        for f in findings
    )
    top_cwes = dict(cwe_counter.most_common(15))

    # Tool coverage
    tool_counter: Counter = Counter()
    for f in findings:
        tools = f.get("tools_reporting") or [f.get("tool", "unknown")]
        for t in tools:
            tool_counter[t] += 1
    top_tools = dict(tool_counter.most_common(15))

    # CVSS histogram (buckets: 0-2, 2-4, 4-6, 6-8, 8-10)
    cvss_buckets = {"0-2": 0, "2-4": 0, "4-6": 0, "6-8": 0, "8-10": 0}
    for f in findings:
        score = f.get("cvss_score", 0) or 0
        if score < 2:
            cvss_buckets["0-2"] += 1
        elif score < 4:
            cvss_buckets["2-4"] += 1
        elif score < 6:
            cvss_buckets["4-6"] += 1
        elif score < 8:
            cvss_buckets["6-8"] += 1
        else:
            cvss_buckets["8-10"] += 1

    return {
        "severity_json": json.dumps(severity_json),
        "cwe_json": json.dumps(top_cwes),
        "tool_json": json.dumps(top_tools),
        "cvss_json": json.dumps(cvss_buckets),
    }


def _prepare_findings(findings: list[dict]) -> list[dict]:
    """Flatten findings for Jinja2 template."""
    prepared = []
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        cwe = f.get("cwe_normalized") or f.get("cwe") or "N/A"
        name = f.get("name") or f.get("id") or "Unnamed"
        url = f.get("url") or ""
        tools = f.get("tools_reporting") or [f.get("tool", "unknown")]
        cvss = f.get("cvss_score", 0) or 0
        epss = f.get("epss_score", 0) or 0

        # AI analysis (if present)
        ai = f.get("ai_analysis", {})
        explanation = ai.get("explanation", "No analysis available.")
        impact = ai.get("impact", "")
        remediation = ai.get("remediation", "")
        poc = ai.get("poc_suggestion", "")

        prepared.append({
            "severity": sev,
            "cvss_score": f"{cvss:.1f}" if cvss else "—",
            "cwe": cwe,
            "name": name,
            "name_short": _truncate(name, 50),
            "url": url,
            "url_short": _truncate(url, 55),
            "tools": ", ".join(tools) if isinstance(tools, list) else str(tools),
            "epss": f"{epss:.1%}" if epss else "—",
            "explanation": explanation,
            "impact": impact,
            "remediation": remediation,
            "poc": poc,
        })

    # Sort: critical first, then by CVSS desc
    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    prepared.sort(key=lambda f: (sev_rank.get(f["severity"], 99), -(float(f["cvss_score"]) if f["cvss_score"] != "—" else 0)))
    return prepared


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate HTML security dashboard")
    parser.add_argument("--input", "-i", help="Input report JSON")
    parser.add_argument("--output", "-o", default="reports/dashboard.html")
    parser.add_argument("--title", default="Security Scan Dashboard")
    parser.add_argument("--target", help="Target URL/domain (auto-detected from report)")
    args = parser.parse_args()

    if args.input:
        input_path = Path(args.input)
    else:
        input_path = _find_latest_report()
        if not input_path:
            print("No report found. Run ai_analyzer.py or scoring_engine.py first.")
            sys.exit(1)

    data = json.loads(input_path.read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data
    metadata = data.get("metadata", {}) if isinstance(data, dict) else {}

    target = args.target or metadata.get("target", "N/A")

    prepared = _prepare_findings(findings)
    charts = _build_chart_data(findings)

    # Severity counts for stat cards
    sev_counter = Counter(f["severity"] for f in prepared)
    severity_counts = {s: sev_counter.get(s, 0) for s in SEVERITY_ORDER}

    # Avg CVSS
    cvss_vals = [float(f["cvss_score"]) for f in prepared if f["cvss_score"] != "—"]
    cvss_avg = f"{sum(cvss_vals) / len(cvss_vals):.1f}" if cvss_vals else "—"

    # Unique CWEs and tools for filter dropdowns
    cwe_list = sorted({f["cwe"] for f in prepared if f["cwe"] != "N/A"})
    tool_set: set[str] = set()
    for f in prepared:
        for t in f["tools"].split(", "):
            tool_set.add(t.strip())
    tool_list = sorted(tool_set)

    # Render
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)
    template = env.get_template("dashboard.html")

    html = template.render(
        title=args.title,
        target=target,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        tools_count=len(tool_list),
        total_findings=len(prepared),
        severity_counts=severity_counts,
        cvss_avg=cvss_avg,
        findings=prepared,
        cwe_list=cwe_list,
        tool_list=tool_list,
        **charts,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)

    print(f"Dashboard generated: {args.output}")
    print(f"  {len(prepared)} findings | {len(cwe_list)} CWEs | {len(tool_list)} tools")
    for s in SEVERITY_ORDER:
        c = severity_counts.get(s, 0)
        if c:
            print(f"  {s.upper()}: {c}")


if __name__ == "__main__":
    main()
