#!/usr/bin/env python3
"""Platform-specific report generators for bug bounty submissions.

Generates formatted reports for:
- YesWeHack (YAML-like markdown)
- HackerOne (H1 markdown template)
- Bugcrowd (P1-P4 + VRT)
- Intigriti (domain/endpoint/impact)
- Immunefi (smart contract / financial impact)
- Markdown (generic)

Usage:
    python scripts/report_generators.py --format yeswehack --input reports/analyzed-report.json
    python scripts/report_generators.py --format hackerone --input reports/scored-report.json

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Any

REPORTS_DIR = Path(__file__).parent.parent / "reports"


class ReportFormat(Enum):
    YESWEHACK = "yeswehack"
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    IMMUNEFI = "immunefi"
    MARKDOWN = "markdown"


# ---------------------------------------------------------------------------
# Severity mappings per platform
# ---------------------------------------------------------------------------

_BUGCROWD_PRIORITY = {
    "critical": "P1", "high": "P2", "medium": "P3",
    "low": "P4", "info": "P5", "unknown": "P4",
}

_BUGCROWD_VRT = {
    "CWE-89":   "Server-Side Injection > SQL Injection",
    "CWE-78":   "Server-Side Injection > OS Command Injection",
    "CWE-79":   "Cross-Site Scripting (XSS) > Reflected",
    "CWE-918":  "Server-Side Request Forgery (SSRF) > Internal",
    "CWE-22":   "Server Security Misconfiguration > Path Traversal",
    "CWE-352":  "Cross-Site Request Forgery (CSRF)",
    "CWE-639":  "Broken Access Control (BAC) > IDOR",
    "CWE-287":  "Broken Authentication > Auth Bypass",
    "CWE-502":  "Server-Side Injection > Deserialization",
    "CWE-611":  "Server-Side Injection > XXE",
    "CWE-434":  "Broken Access Control (BAC) > Unrestricted File Upload",
    "CWE-798":  "Sensitive Data Exposure > Hardcoded Credentials",
    "CWE-601":  "Unvalidated Redirects and Forwards > Open Redirect",
    "CWE-1336": "Server-Side Injection > SSTI",
    "CWE-94":   "Server-Side Injection > Code Injection",
    "CWE-444":  "Server Security Misconfiguration > HTTP Request Smuggling",
}

_INTIGRITI_SEVERITY = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Informational",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _extract_poc(finding: dict) -> str:
    """Extract or generate a PoC curl command from finding data."""
    # Direct curl command
    curl = finding.get("curl_command") or finding.get("poc_url") or ""
    if curl:
        return str(curl)

    # Build from evidence
    evidence = finding.get("evidence", {})
    if isinstance(evidence, dict):
        req = evidence.get("request") or evidence.get("http_request") or ""
        if req:
            return f"# Evidence:\n{req}"

    url = finding.get("url") or finding.get("endpoint") or ""
    if url:
        return f"curl -v '{url}'"

    return "# No PoC available — reproduce manually"


def _get_cwe(finding: dict) -> str:
    """Extract normalized CWE."""
    cwe = finding.get("cwe_normalized") or finding.get("cwe") or finding.get("cwe_id") or ""
    return str(cwe).upper()


def _get_title(finding: dict) -> str:
    """Build platform-quality title."""
    title = finding.get("title") or finding.get("name") or "Untitled"
    url = finding.get("url") or finding.get("endpoint") or ""
    if url and url not in title:
        # Shorten URL for title
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
            return f"{title} in {path}"
        except Exception:
            pass
    return title


def _validation_status(finding: dict) -> str:
    """Get validation gate status summary."""
    val = finding.get("validation", {})
    if not val:
        return ""
    verdict = val.get("overall_verdict", "")
    passed = val.get("gates_passed", 0)
    total = val.get("total_gates", 0)
    return f"Validation: {verdict} ({passed}/{total} gates)"


# ---------------------------------------------------------------------------
# Platform report formatters
# ---------------------------------------------------------------------------

class YesWeHackReport:
    """Format findings for YesWeHack submission."""

    @staticmethod
    def format_finding(finding: dict, idx: int = 1) -> str:
        sev = (finding.get("severity") or "medium").capitalize()
        cwe = _get_cwe(finding)
        title = _get_title(finding)
        desc = finding.get("description") or ""
        remediation = finding.get("remediation") or "Apply standard security best practices."
        cvss = finding.get("cvss_score")
        cvss_vector = finding.get("cvss_vector") or ""
        poc = _extract_poc(finding)
        ai = finding.get("ai_analysis") or ""

        lines = [
            f"## Finding {idx}: {title}",
            "",
            f"**Severity:** {sev}",
            f"**CWE:** {cwe}" if cwe else "",
            f"**CVSS 3.1:** {cvss} ({cvss_vector})" if cvss else "",
            "",
            "### Summary",
            desc[:500] if desc else "See steps to reproduce below.",
            "",
            "### Steps To Reproduce",
            "```bash",
            poc,
            "```",
            "",
            "### Impact",
            ai[:300] if ai else f"This vulnerability allows an attacker to exploit {cwe or 'this issue'}.",
            "",
            "### Remediation",
            remediation[:300],
        ]
        return "\n".join(line for line in lines if line is not None)

    @staticmethod
    def generate(findings: list[dict], **kwargs: Any) -> str:
        target = kwargs.get("target", "Unknown Target")
        parts = [
            f"# Security Report — {target}",
            f"**Platform:** YesWeHack",
            f"**Findings:** {len(findings)}",
            "",
        ]
        for i, f in enumerate(findings, 1):
            parts.append(YesWeHackReport.format_finding(f, i))
            parts.append("\n---\n")
        return "\n".join(parts)


class HackerOneReport:
    """Format findings for HackerOne submission."""

    @staticmethod
    def format_finding(finding: dict, idx: int = 1) -> str:
        sev = (finding.get("severity") or "medium").lower()
        cwe = _get_cwe(finding)
        title = _get_title(finding)
        desc = finding.get("description") or ""
        remediation = finding.get("remediation") or ""
        cvss = finding.get("cvss_score")
        cvss_vector = finding.get("cvss_vector") or ""
        poc = _extract_poc(finding)
        url = finding.get("url") or finding.get("endpoint") or ""
        ai = finding.get("ai_analysis") or ""

        lines = [
            f"## {title}",
            "",
            f"**Severity:** {sev}  ",
            f"**Weakness:** {cwe}  " if cwe else "",
            f"**Asset:** `{url}`  " if url else "",
            "",
            "## Summary",
            desc[:500] if desc else "Vulnerability discovered during automated security testing.",
            "",
            "## Steps To Reproduce",
            f"1. Navigate to `{url}`" if url else "",
            "2. Execute the following request:",
            "",
            "```",
            poc,
            "```",
            "",
            "## Impact",
            ai[:300] if ai else "An attacker could exploit this vulnerability to compromise the application.",
            "",
        ]
        if cvss:
            lines.extend([
                "## CVSS",
                f"**Score:** {cvss}  ",
                f"**Vector:** {cvss_vector}  " if cvss_vector else "",
                "",
            ])
        if remediation:
            lines.extend(["## Suggested Fix", remediation[:300], ""])
        return "\n".join(line for line in lines if line is not None)

    @staticmethod
    def generate(findings: list[dict], **kwargs: Any) -> str:
        target = kwargs.get("target", "Unknown Target")
        parts = [f"# HackerOne Report — {target}\n"]
        for i, f in enumerate(findings, 1):
            parts.append(HackerOneReport.format_finding(f, i))
            parts.append("---\n")
        return "\n".join(parts)


class BugcrowdReport:
    """Format findings for Bugcrowd submission (P1–P5 + VRT)."""

    @staticmethod
    def format_finding(finding: dict, idx: int = 1) -> str:
        sev = (finding.get("severity") or "medium").lower()
        priority = _BUGCROWD_PRIORITY.get(sev, "P4")
        cwe = _get_cwe(finding)
        vrt = _BUGCROWD_VRT.get(cwe, "Other")
        title = _get_title(finding)
        desc = finding.get("description") or ""
        poc = _extract_poc(finding)
        url = finding.get("url") or finding.get("endpoint") or ""

        lines = [
            f"## [{priority}] {title}",
            "",
            f"**Priority:** {priority}  ",
            f"**VRT:** {vrt}  ",
            f"**CWE:** {cwe}  " if cwe else "",
            f"**URL:** `{url}`  " if url else "",
            "",
            "### Description",
            desc[:500] if desc else "Security vulnerability discovered.",
            "",
            "### Proof of Concept",
            "```",
            poc,
            "```",
            "",
            "### Impact",
            finding.get("ai_analysis", "")[:300] or f"Exploitation of {vrt}.",
            "",
        ]
        return "\n".join(line for line in lines if line is not None)

    @staticmethod
    def generate(findings: list[dict], **kwargs: Any) -> str:
        target = kwargs.get("target", "Unknown Target")
        parts = [f"# Bugcrowd Report — {target}\n"]
        for i, f in enumerate(findings, 1):
            parts.append(BugcrowdReport.format_finding(f, i))
            parts.append("---\n")
        return "\n".join(parts)


class IntigritiReport:
    """Format findings for Intigriti submission."""

    @staticmethod
    def format_finding(finding: dict, idx: int = 1) -> str:
        sev = _INTIGRITI_SEVERITY.get(
            (finding.get("severity") or "medium").lower(), "Medium"
        )
        title = _get_title(finding)
        desc = finding.get("description") or ""
        poc = _extract_poc(finding)
        url = finding.get("url") or finding.get("endpoint") or ""
        cwe = _get_cwe(finding)
        from urllib.parse import urlparse
        try:
            domain = urlparse(url).netloc if url else "unknown"
        except Exception:
            domain = "unknown"

        lines = [
            f"## {title}",
            "",
            f"**Severity:** {sev}  ",
            f"**Domain:** `{domain}`  ",
            f"**Endpoint:** `{url}`  " if url else "",
            f"**CWE:** {cwe}  " if cwe else "",
            "",
            "### Description",
            desc[:500] if desc else "Vulnerability details below.",
            "",
            "### Steps to Reproduce",
            "```",
            poc,
            "```",
            "",
            "### Impact",
            finding.get("ai_analysis", "")[:300] or "Security impact on the domain.",
            "",
        ]
        return "\n".join(line for line in lines if line is not None)

    @staticmethod
    def generate(findings: list[dict], **kwargs: Any) -> str:
        target = kwargs.get("target", "Unknown Target")
        parts = [f"# Intigriti Report — {target}\n"]
        for i, f in enumerate(findings, 1):
            parts.append(IntigritiReport.format_finding(f, i))
            parts.append("---\n")
        return "\n".join(parts)


class ImmunefiReport:
    """Format findings for Immunefi (blockchain / DeFi focus)."""

    @staticmethod
    def format_finding(finding: dict, idx: int = 1) -> str:
        sev = (finding.get("severity") or "medium").capitalize()
        title = _get_title(finding)
        desc = finding.get("description") or ""
        poc = _extract_poc(finding)
        url = finding.get("url") or finding.get("endpoint") or ""
        cwe = _get_cwe(finding)
        chains = finding.get("chains", [])
        chain_text = ""
        if chains:
            chain_impacts = [c.get("final_impact", "") for c in chains[:3]]
            chain_text = "**Exploit Chain:** " + " → ".join(filter(None, chain_impacts))

        lines = [
            f"## {title}",
            "",
            f"**Severity:** {sev}  ",
            f"**CWE:** {cwe}  " if cwe else "",
            f"**Target:** `{url}`  " if url else "",
            chain_text if chain_text else "",
            "",
            "### Bug Description",
            desc[:500] if desc else "Vulnerability affecting the protocol/application.",
            "",
            "### Impact",
            "#### Financial Impact",
            finding.get("ai_analysis", "")[:300] or "Potential financial loss or unauthorized access.",
            "",
            "#### Affected Assets",
            f"- `{url}`" if url else "- See description",
            "",
            "### Proof of Concept",
            "```",
            poc,
            "```",
            "",
            "### Recommendation",
            finding.get("remediation", "") or "Implement proper security controls.",
            "",
        ]
        return "\n".join(line for line in lines if line is not None)

    @staticmethod
    def generate(findings: list[dict], **kwargs: Any) -> str:
        target = kwargs.get("target", "Unknown Target")
        parts = [f"# Immunefi Report — {target}\n"]
        for i, f in enumerate(findings, 1):
            parts.append(ImmunefiReport.format_finding(f, i))
            parts.append("---\n")
        return "\n".join(parts)


class MarkdownReport:
    """Generic markdown report."""

    @staticmethod
    def format_finding(finding: dict, idx: int = 1) -> str:
        sev = (finding.get("severity") or "medium").capitalize()
        title = _get_title(finding)
        desc = finding.get("description") or ""
        poc = _extract_poc(finding)
        url = finding.get("url") or ""
        cwe = _get_cwe(finding)
        cvss = finding.get("cvss_score")
        validation = _validation_status(finding)

        lines = [
            f"### {idx}. {title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Severity | {sev} |",
            f"| CWE | {cwe} |" if cwe else "",
            f"| CVSS | {cvss} |" if cvss else "",
            f"| URL | `{url}` |" if url else "",
            f"| {validation} |" if validation else "",
            "",
            desc[:500] if desc else "",
            "",
            "**PoC:**",
            "```",
            poc,
            "```",
            "",
        ]
        return "\n".join(line for line in lines if line is not None)

    @staticmethod
    def generate(findings: list[dict], **kwargs: Any) -> str:
        target = kwargs.get("target", "Unknown Target")
        parts = [
            f"# Security Assessment Report",
            f"**Target:** {target}  ",
            f"**Findings:** {len(findings)}  ",
            "",
            "---",
            "",
        ]
        for i, f in enumerate(findings, 1):
            parts.append(MarkdownReport.format_finding(f, i))
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Report dispatcher
# ---------------------------------------------------------------------------

_GENERATORS: dict[ReportFormat, type] = {
    ReportFormat.YESWEHACK: YesWeHackReport,
    ReportFormat.HACKERONE: HackerOneReport,
    ReportFormat.BUGCROWD: BugcrowdReport,
    ReportFormat.INTIGRITI: IntigritiReport,
    ReportFormat.IMMUNEFI: ImmunefiReport,
    ReportFormat.MARKDOWN: MarkdownReport,
}


class PlatformReportGenerator:
    """Dispatch to the correct platform template."""

    @staticmethod
    def generate(
        findings: list[dict],
        fmt: ReportFormat | str = ReportFormat.MARKDOWN,
        **kwargs: Any,
    ) -> str:
        if isinstance(fmt, str):
            fmt = ReportFormat(fmt.lower())
        gen_cls = _GENERATORS.get(fmt, MarkdownReport)
        return gen_cls.generate(findings, **kwargs)

    @staticmethod
    def available_formats() -> list[str]:
        return [f.value for f in ReportFormat]

    @staticmethod
    def format_single_finding(
        finding: dict,
        fmt: ReportFormat | str = ReportFormat.MARKDOWN,
        idx: int = 1,
    ) -> str:
        if isinstance(fmt, str):
            fmt = ReportFormat(fmt.lower())
        gen_cls = _GENERATORS.get(fmt, MarkdownReport)
        return gen_cls.format_finding(finding, idx)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate platform-specific bug bounty reports",
    )
    parser.add_argument("--format", "-f", default="markdown",
                        choices=PlatformReportGenerator.available_formats(),
                        help="Output format / platform")
    parser.add_argument("--input", "-i", help="Input report JSON")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--target", "-t", help="Target name for report header")
    parser.add_argument("--validated-only", action="store_true",
                        help="Only include findings that passed validation gates")
    args = parser.parse_args()

    # Load input
    if args.input:
        input_path = Path(args.input)
    else:
        # Auto-find best report
        for name in ["analyzed-report.json", "scored-report.json", "deduped-report.json"]:
            candidate = REPORTS_DIR / name
            if candidate.exists():
                input_path = candidate
                break
        else:
            print("No report found in reports/", file=sys.stderr)
            sys.exit(1)

    data = json.loads(input_path.read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data
    target = args.target or (data.get("target") if isinstance(data, dict) else None) or "Unknown"

    # Filter validated only
    if args.validated_only:
        findings = [
            f for f in findings
            if f.get("validation", {}).get("overall_verdict") not in ("REJECTED", "FAIL")
        ]

    # Generate
    report = PlatformReportGenerator.generate(
        findings, fmt=args.format, target=target,
    )

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(report)
        print(f"Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
