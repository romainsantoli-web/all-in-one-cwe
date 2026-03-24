#!/usr/bin/env python3
"""Intelligent deduplication engine — fuzzy URL matching + CWE-aware grouping.

Replaces the basic (tool, id, url) dedup in merge-reports.py with:
- URL normalization (trailing slash, query param order, fragment strip)
- CWE + endpoint + severity matching for cross-tool dedup
- Evidence enrichment: group same finding from N tools

Usage:
    python scripts/dedup_engine.py [--input reports/unified-report-*.json] [--output reports/deduped-report.json]

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

REPORTS_DIR = Path(__file__).parent.parent / "reports"


def normalize_url(url: str) -> str:
    """Normalize a URL for comparison (sort params, strip fragment, lowercase)."""
    if not url:
        return ""
    try:
        parsed = urlparse(url.lower().strip())
        # Sort query parameters
        params = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(params.items()), doseq=True)
        # Rebuild without fragment, with sorted params, strip trailing slash
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path.rstrip("/") or "/",
            parsed.params,
            sorted_query,
            "",  # no fragment
        ))
        return normalized
    except Exception:
        return url.lower().strip()


def _fingerprint(finding: dict) -> str:
    """Create a dedup fingerprint from a finding."""
    url = normalize_url(finding.get("url", ""))
    cwe = str(finding.get("cwe", "") or finding.get("cwe_id", "")).strip()
    severity = (finding.get("severity") or "unknown").lower()
    name = (finding.get("name") or finding.get("id") or "").lower().strip()

    # Primary key: CWE + normalized URL
    # Fallback: name + URL if no CWE
    if cwe:
        return f"{cwe}|{url}"
    return f"{name}|{url}|{severity}"


def deduplicate(findings: list[dict]) -> list[dict]:
    """Deduplicate findings using fuzzy URL matching + CWE grouping.

    When the same vulnerability is found by multiple tools:
    - Keep the highest severity
    - Merge evidence (tool names, descriptions)
    - Preserve the first occurrence's details
    """
    groups: dict[str, list[dict]] = {}

    for f in findings:
        fp = _fingerprint(f)
        groups.setdefault(fp, []).append(f)

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}

    deduped = []
    for fp, group in groups.items():
        # Sort by severity (highest first)
        group.sort(
            key=lambda x: SEVERITY_ORDER.get((x.get("severity") or "unknown").lower(), 0),
            reverse=True,
        )
        primary = dict(group[0])  # copy

        # Enrich with evidence from all tools
        tools_reporting = list({f.get("tool", "unknown") for f in group})
        primary["tools_reporting"] = tools_reporting
        primary["duplicate_count"] = len(group)

        # Keep highest severity
        best_sev = max(
            group,
            key=lambda x: SEVERITY_ORDER.get((x.get("severity") or "unknown").lower(), 0),
        )
        primary["severity"] = best_sev.get("severity", primary.get("severity", "unknown"))

        # Merge descriptions if different
        descriptions = list({
            f.get("description", "") for f in group if f.get("description")
        })
        if len(descriptions) > 1:
            primary["descriptions_all"] = descriptions

        deduped.append(primary)

    # Sort by severity descending
    deduped.sort(
        key=lambda x: SEVERITY_ORDER.get((x.get("severity") or "unknown").lower(), 0),
        reverse=True,
    )

    return deduped


def _find_latest_report() -> Path | None:
    """Find the most recent unified-report-*.json."""
    candidates = sorted(REPORTS_DIR.glob("unified-report-*.json"), reverse=True)
    return candidates[0] if candidates else None


def main() -> None:
    parser = argparse.ArgumentParser(description="Intelligent deduplication engine")
    parser.add_argument("--input", "-i", help="Input unified report JSON")
    parser.add_argument("--output", "-o", default="reports/deduped-report.json",
                        help="Output deduped report JSON")
    args = parser.parse_args()

    # Find input
    if args.input:
        input_path = Path(args.input)
    else:
        input_path = _find_latest_report()
        if not input_path:
            print("No unified report found in reports/. Run merge-reports.py first.")
            sys.exit(1)

    data = json.loads(input_path.read_text())
    findings = data if isinstance(data, list) else data.get("findings", [])

    before = len(findings)
    deduped = deduplicate(findings)
    after = len(deduped)

    output = {
        "metadata": {
            "source": str(input_path),
            "before_dedup": before,
            "after_dedup": after,
            "reduction_pct": round((1 - after / before) * 100, 1) if before else 0,
        },
        "findings": deduped,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(output, indent=2, default=str))
    print(f"Dedup: {before} → {after} findings ({output['metadata']['reduction_pct']}% reduction)")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
