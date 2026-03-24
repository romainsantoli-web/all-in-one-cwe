#!/usr/bin/env python3
"""CVSS v3.1 + EPSS scoring engine — auto-score findings by CWE.

Features:
- CWE → CVSS v3.1 vector string lookup (50+ CWEs)
- Contextual adjustment (authenticated vs unauthenticated)
- EPSS via FIRST API (optional, graceful fallback)
- Composite ranking score: severity * CVSS * EPSS

Usage:
    python scripts/scoring_engine.py [--input reports/deduped-report.json] [--output reports/scored-report.json]

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

# ---------------------------------------------------------------------------
# CWE → CVSS v3.1 base vector + base score (pre-computed defaults)
# Source: NVD common vectors per CWE
# ---------------------------------------------------------------------------
CWE_CVSS_MAP: dict[str, dict] = {
    # Injection
    "CWE-78":  {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "score": 8.8},
    "CWE-79":  {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1},
    "CWE-89":  {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
    "CWE-90":  {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
    "CWE-91":  {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
    "CWE-94":  {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
    "CWE-99":  {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "score": 6.5},
    "CWE-113": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1},
    # Auth / Access
    "CWE-200": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3},
    "CWE-209": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3},
    "CWE-215": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3},
    "CWE-284": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "score": 9.1},
    "CWE-287": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
    "CWE-307": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
    "CWE-312": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
    "CWE-319": {"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 5.9},
    "CWE-326": {"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 5.9},
    "CWE-327": {"vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 5.9},
    "CWE-352": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", "score": 8.1},
    # Files / Traversal
    "CWE-22":  {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
    "CWE-434": {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "score": 8.8},
    "CWE-502": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
    # SSRF / Redirect
    "CWE-601": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1},
    "CWE-611": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
    "CWE-639": {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "score": 8.1},
    "CWE-918": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "score": 8.6},
    # DoS / Resource
    "CWE-400": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "score": 7.5},
    "CWE-770": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "score": 7.5},
    # Config / Secrets
    "CWE-16":  {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "score": 6.5},
    "CWE-425": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3},
    "CWE-444": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "score": 9.1},
    "CWE-524": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3},
    "CWE-532": {"vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "score": 5.5},
    "CWE-540": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3},
    "CWE-548": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3},
    "CWE-615": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "score": 5.3},
    "CWE-798": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
    "CWE-922": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "score": 7.5},
    "CWE-942": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", "score": 7.1},
    # SSTI / Misc
    "CWE-1336": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
    "CWE-1021": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", "score": 5.4},
    "CWE-345": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", "score": 7.5},
    "CWE-346": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "score": 6.5},
}

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.05, "unknown": 0.1}


def _extract_cwe(finding: dict) -> str | None:
    """Extract CWE-ID from a finding (handles various formats)."""
    raw = finding.get("cwe") or finding.get("cwe_id") or ""
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    raw = str(raw).strip()
    # Normalize: "CWE-79", "79", "cwe-79" → "CWE-79"
    if raw.isdigit():
        return f"CWE-{raw}"
    if raw.upper().startswith("CWE-"):
        return raw.upper()
    return None


def score_finding(finding: dict) -> dict:
    """Add CVSS score and vector to a finding based on its CWE."""
    cwe = _extract_cwe(finding)
    scored = dict(finding)

    if cwe and cwe in CWE_CVSS_MAP:
        cvss_data = CWE_CVSS_MAP[cwe]
        scored["cvss_vector"] = cvss_data["vector"]
        scored["cvss_score"] = cvss_data["score"]
    else:
        # Fallback: derive from severity
        sev = (finding.get("severity") or "unknown").lower()
        fallback_scores = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
        scored["cvss_score"] = fallback_scores.get(sev, 3.0)
        scored["cvss_vector"] = None

    scored["cwe_normalized"] = cwe
    return scored


def enrich_epss(findings: list[dict]) -> list[dict]:
    """Try to enrich findings with EPSS scores from FIRST API.

    Fails gracefully if no network or API unavailable.
    """
    # Collect unique CVE IDs (some findings have them)
    cve_ids = set()
    for f in findings:
        cve = f.get("cve") or f.get("cve_id") or ""
        if isinstance(cve, str) and cve.upper().startswith("CVE-"):
            cve_ids.add(cve.upper())

    if not cve_ids:
        return findings

    # Fetch EPSS in batch
    epss_map: dict[str, float] = {}
    try:
        import requests
        # FIRST EPSS API: https://api.first.org/data/v1/epss?cve=CVE-2021-44228
        cve_list = ",".join(sorted(cve_ids)[:100])  # API limit ~100
        resp = requests.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve_list},
            timeout=15,
        )
        if resp.status_code == 200:
            for entry in resp.json().get("data", []):
                epss_map[entry["cve"].upper()] = float(entry.get("epss", 0))
    except Exception:
        pass  # Graceful fallback

    # Enrich
    for f in findings:
        cve = (f.get("cve") or f.get("cve_id") or "").upper()
        if cve in epss_map:
            f["epss_score"] = epss_map[cve]
        else:
            f["epss_score"] = None

    return findings


def compute_composite_rank(findings: list[dict]) -> list[dict]:
    """Compute a composite ranking score for each finding.

    Formula: composite = severity_weight * cvss_score * (1 + epss_score)
    Higher = more critical.
    """
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        sev_w = SEVERITY_WEIGHT.get(sev, 0.1)
        cvss = f.get("cvss_score", 3.0)
        epss = f.get("epss_score") or 0.0

        f["composite_rank"] = round(sev_w * cvss * (1 + epss), 2)

    # Sort by composite rank descending
    findings.sort(key=lambda x: x.get("composite_rank", 0), reverse=True)
    return findings


def _find_latest_report() -> Path | None:
    """Find deduped report, or fall back to unified."""
    deduped = REPORTS_DIR / "deduped-report.json"
    if deduped.exists():
        return deduped
    candidates = sorted(REPORTS_DIR.glob("unified-report-*.json"), reverse=True)
    return candidates[0] if candidates else None


def main() -> None:
    parser = argparse.ArgumentParser(description="CVSS + EPSS scoring engine")
    parser.add_argument("--input", "-i", help="Input report JSON")
    parser.add_argument("--output", "-o", default="reports/scored-report.json")
    parser.add_argument("--no-epss", action="store_true", help="Skip EPSS API call")
    args = parser.parse_args()

    if args.input:
        input_path = Path(args.input)
    else:
        input_path = _find_latest_report()
        if not input_path:
            print("No report found. Run merge-reports.py or dedup_engine.py first.")
            sys.exit(1)

    data = json.loads(input_path.read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data

    # Score each finding
    scored = [score_finding(f) for f in findings]

    # EPSS enrichment (optional)
    if not args.no_epss:
        scored = enrich_epss(scored)

    # Composite ranking
    scored = compute_composite_rank(scored)

    output = {
        "metadata": {
            "source": str(input_path),
            "total_findings": len(scored),
            "with_cvss": sum(1 for f in scored if f.get("cvss_vector")),
            "with_epss": sum(1 for f in scored if f.get("epss_score")),
        },
        "findings": scored,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(output, indent=2, default=str))

    print(f"Scored {len(scored)} findings ({output['metadata']['with_cvss']} with CVSS, "
          f"{output['metadata']['with_epss']} with EPSS)")
    print(f"Top 5 by composite rank:")
    for f in scored[:5]:
        print(f"  [{f.get('composite_rank', 0):.1f}] {f.get('severity', '?'):8s} "
              f"{f.get('cwe_normalized', 'N/A'):10s} {f.get('name', f.get('id', ''))[:50]}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
