#!/usr/bin/env python3
"""Merge reports from all security tools into a unified JSON format.
⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

# Map tool names to their report directory and parser
TOOL_PARSERS = {
    "nuclei": "parse_nuclei",
    "zap": "parse_zap",
    "sqlmap": "parse_sqlmap",
    "semgrep": "parse_semgrep",
    "gitleaks": "parse_gitleaks",
    "trufflehog": "parse_trufflehog",
    "trivy": "parse_trivy",
    "cwe-checker": "parse_cwe_checker",
    "garak": "parse_garak",
    "idor-scanner": "parse_python_scanner",
    "auth-bypass": "parse_python_scanner",
    "user-enum": "parse_python_scanner",
    "notif-inject": "parse_python_scanner",
    "redirect-cors": "parse_python_scanner",
    "oidc-audit": "parse_python_scanner",
    "bypass-403-advanced": "parse_python_scanner",
    "ssrf-scanner": "parse_python_scanner",
    "xss-scanner": "parse_python_scanner",
    "api-discovery": "parse_python_scanner",
    "secret-leak": "parse_python_scanner",
    "websocket-scanner": "parse_python_scanner",
    "cache-deception": "parse_python_scanner",
    "slowloris-check": "parse_python_scanner",
    "smuggler": "parse_smuggler",
    "checkov": "parse_checkov",
    "restler": "parse_restler",
}


def parse_nuclei(data):
    """Parse Nuclei JSON output (JSONL — one object per line)."""
    findings = []
    if isinstance(data, list):
        items = data
    else:
        items = [data]
    for item in items:
        findings.append({
            "tool": "nuclei",
            "id": item.get("template-id", ""),
            "name": item.get("info", {}).get("name", ""),
            "severity": item.get("info", {}).get("severity", "unknown"),
            "cwe": item.get("info", {}).get("classification", {}).get("cwe-id", ""),
            "url": item.get("matched-at", item.get("host", "")),
            "description": item.get("info", {}).get("description", ""),
            "matched": item.get("matcher-name", ""),
            "curl_command": item.get("curl-command", ""),
        })
    return findings


def parse_zap(data):
    """Parse ZAP JSON output."""
    findings = []
    alerts = []
    if isinstance(data, dict):
        # ZAP automation framework report format
        for site in data.get("site", []):
            alerts.extend(site.get("alerts", []))
        # ZAP traditional JSON
        alerts.extend(data.get("alerts", []))
    for alert in alerts:
        findings.append({
            "tool": "zap",
            "id": alert.get("pluginid", ""),
            "name": alert.get("name", alert.get("alert", "")),
            "severity": _zap_risk_to_severity(alert.get("riskcode", 0)),
            "cwe": f"CWE-{alert.get('cweid', '')}" if alert.get("cweid") else "",
            "url": alert.get("url", ""),
            "description": alert.get("desc", ""),
            "solution": alert.get("solution", ""),
        })
    return findings


def _zap_risk_to_severity(risk_code):
    return {0: "info", 1: "low", 2: "medium", 3: "high"}.get(risk_code, "unknown")


def parse_sqlmap(data):
    """Parse SQLMap output directory."""
    findings = []
    if isinstance(data, dict):
        for url, details in data.items():
            findings.append({
                "tool": "sqlmap",
                "id": "sqli",
                "name": "SQL Injection",
                "severity": "critical",
                "cwe": "CWE-89",
                "url": url,
                "description": json.dumps(details) if isinstance(details, dict) else str(details),
            })
    return findings


def parse_semgrep(data):
    """Parse Semgrep JSON output."""
    findings = []
    if isinstance(data, dict):
        for result in data.get("results", []):
            meta = result.get("extra", {}).get("metadata", {})
            cwe_list = meta.get("cwe", [])
            cwe_str = cwe_list[0] if cwe_list else ""
            findings.append({
                "tool": "semgrep",
                "id": result.get("check_id", ""),
                "name": result.get("check_id", "").split(".")[-1],
                "severity": result.get("extra", {}).get("severity", "unknown").lower(),
                "cwe": cwe_str,
                "url": f"{result.get('path', '')}:{result.get('start', {}).get('line', '')}",
                "description": result.get("extra", {}).get("message", ""),
            })
    return findings


def parse_gitleaks(data):
    """Parse Gitleaks JSON output."""
    findings = []
    if isinstance(data, list):
        for leak in data:
            findings.append({
                "tool": "gitleaks",
                "id": leak.get("RuleID", ""),
                "name": leak.get("Description", "Secret detected"),
                "severity": "high",
                "cwe": "CWE-798",
                "url": f"{leak.get('File', '')}:{leak.get('StartLine', '')}",
                "description": f"Rule: {leak.get('RuleID', '')} — Match: {leak.get('Match', '')[:50]}...",
            })
    return findings


def parse_trufflehog(data):
    """Parse TruffleHog JSON output (JSONL)."""
    findings = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        findings.append({
            "tool": "trufflehog",
            "id": item.get("DetectorName", ""),
            "name": f"Secret: {item.get('DetectorName', '')}",
            "severity": "high",
            "cwe": "CWE-798",
            "url": item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
            "description": f"Verified: {item.get('Verified', False)}",
        })
    return findings


def parse_trivy(data):
    """Parse Trivy JSON output."""
    findings = []
    if isinstance(data, dict):
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                findings.append({
                    "tool": "trivy",
                    "id": vuln.get("VulnerabilityID", ""),
                    "name": vuln.get("Title", vuln.get("VulnerabilityID", "")),
                    "severity": vuln.get("Severity", "unknown").lower(),
                    "cwe": "",
                    "url": vuln.get("PrimaryURL", ""),
                    "description": vuln.get("Description", ""),
                    "package": f"{vuln.get('PkgName', '')}@{vuln.get('InstalledVersion', '')}",
                    "fixed_version": vuln.get("FixedVersion", ""),
                })
            for secret in result.get("Secrets", []):
                findings.append({
                    "tool": "trivy",
                    "id": secret.get("RuleID", ""),
                    "name": secret.get("Title", "Secret"),
                    "severity": secret.get("Severity", "high").lower(),
                    "cwe": "CWE-798",
                    "url": f"{result.get('Target', '')}:{secret.get('StartLine', '')}",
                    "description": secret.get("Match", ""),
                })
    return findings


def parse_cwe_checker(data):
    """Parse cwe_checker JSON output."""
    findings = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("warnings", data.get("results", []))
    else:
        items = []
    for item in items:
        findings.append({
            "tool": "cwe-checker",
            "id": item.get("name", ""),
            "name": item.get("description", item.get("name", "")),
            "severity": "high",
            "cwe": item.get("name", ""),  # cwe_checker uses CWE-XXX as name
            "url": item.get("addresses", [""])[0] if item.get("addresses") else "",
            "description": item.get("description", ""),
        })
    return findings


def parse_garak(data):
    """Parse garak output."""
    findings = []
    if isinstance(data, dict):
        for probe, results in data.items():
            if isinstance(results, dict):
                for det, score in results.items():
                    if isinstance(score, (int, float)) and score > 0:
                        findings.append({
                            "tool": "garak",
                            "id": f"{probe}/{det}",
                            "name": f"LLM Vulnerability: {probe}",
                            "severity": "high" if score > 0.5 else "medium",
                            "cwe": "CWE-1427",
                            "url": "",
                            "description": f"Probe: {probe}, Detector: {det}, Score: {score}",
                        })
    return findings


def load_report(tool_dir):
    """Load the most recent JSON report from a tool directory."""
    tool_path = REPORTS_DIR / tool_dir
    if not tool_path.exists():
        return None

    json_files = sorted(
        list(tool_path.glob("*.json")) + list(tool_path.glob("*.jsonl")),
        key=os.path.getmtime, reverse=True,
    )
    if not json_files:
        return None

    # Handle JSONL format (one JSON object per line)
    content = json_files[0].read_text(encoding="utf-8").strip()
    if not content:
        return None

    # Try standard JSON first
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Try JSONL
    items = []
    for line in content.splitlines():
        line = line.strip()
        if line:
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items if items else None


def parse_python_scanner(data):
    """Parse output from custom Python scanners (lib.py save_findings format).

    Format: {"tool": "...", "findings": [{"id": ..., "name": ..., "severity": ..., ...}]}
    """
    findings = []
    if isinstance(data, dict):
        raw = data.get("findings", [])
        tool = data.get("tool", "python-scanner")
    elif isinstance(data, list):
        raw = data
        tool = "python-scanner"
    else:
        return findings

    for item in raw:
        findings.append({
            "tool": tool,
            "id": item.get("id", ""),
            "name": item.get("name", item.get("title", "")),
            "severity": item.get("severity", "info"),
            "cwe": item.get("cwe", ""),
            "url": item.get("url", item.get("endpoint", "")),
            "description": item.get("description", ""),
            "evidence": item.get("evidence", {}),
            "remediation": item.get("remediation", ""),
        })
    return findings


def parse_smuggler(data):
    """Parse defparam/smuggler stdout JSON."""
    findings = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        findings.append({
            "tool": "smuggler",
            "id": item.get("id", "http-smuggling"),
            "name": item.get("title", "HTTP Request Smuggling"),
            "severity": item.get("severity", "high"),
            "cwe": "CWE-444",
            "url": item.get("url", ""),
            "description": item.get("detail", item.get("description", "")),
            "evidence": item.get("evidence", {}),
        })
    return findings


def parse_checkov(data):
    """Parse Checkov JSON output."""
    findings = []
    results = data if isinstance(data, list) else data.get("results", {}).get("failed_checks", [])
    for item in results:
        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
        sev = sev_map.get(str(item.get("severity", "")).upper(), "medium")
        findings.append({
            "tool": "checkov",
            "id": item.get("check_id", ""),
            "name": item.get("check_name", item.get("name", "")),
            "severity": sev,
            "cwe": item.get("cwe", "CWE-16"),
            "url": item.get("file_path", item.get("resource", "")),
            "description": item.get("guideline", ""),
            "evidence": {"resource": item.get("resource", ""), "file": item.get("file_path", "")},
        })
    return findings


def parse_restler(data):
    """Parse RESTler fuzzing results."""
    findings = []
    bugs = data if isinstance(data, list) else data.get("bugs", [])
    for item in bugs:
        findings.append({
            "tool": "restler",
            "id": item.get("id", f"restler-{item.get('type', 'bug')}"),
            "name": item.get("name", item.get("type", "API Fuzzing Finding")),
            "severity": item.get("severity", "medium"),
            "cwe": item.get("cwe", "CWE-20"),
            "url": item.get("endpoint", item.get("url", "")),
            "description": item.get("detail", item.get("description", "")),
            "evidence": item.get("evidence", {}),
        })
    return findings


def main():
    parser = argparse.ArgumentParser(description="Merge security scan reports")
    parser.add_argument("--scan-date", default=datetime.now().strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    if args.output is None:
        args.output = str(REPORTS_DIR / f"unified-report-{args.scan_date}.json")

    all_findings = []
    stats = {}

    for tool_name, parser_name in TOOL_PARSERS.items():
        data = load_report(tool_name)
        if data is None:
            print(f"  [-] {tool_name}: no report found")
            stats[tool_name] = 0
            continue

        parser_func = globals()[parser_name]
        findings = parser_func(data)
        stats[tool_name] = len(findings)
        all_findings.extend(findings)
        print(f"  [+] {tool_name}: {len(findings)} findings")

    # Deduplicate by (tool, id, url)
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.get("tool"), f.get("id"), f.get("url"))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    report = {
        "scan_date": args.scan_date,
        "generated_at": datetime.now().isoformat(),
        "total_findings": len(unique),
        "by_severity": {},
        "by_tool": stats,
        "findings": unique,
    }

    # Count by severity
    for f in unique:
        sev = f.get("severity", "unknown")
        report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)

    print(f"\n  Unified report: {args.output}")
    print(f"  Total findings: {len(unique)}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = report["by_severity"].get(sev, 0)
        if count:
            print(f"    {sev}: {count}")


if __name__ == "__main__":
    main()
