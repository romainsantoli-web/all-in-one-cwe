#!/usr/bin/env python3
"""Generate a CWE summary from the unified report.
⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""
import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"

# Full CWE mapping from the bug bounty scope
CWE_DESCRIPTIONS = {
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection - Generic",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-91": "XML Injection",
    "CWE-93": "CRLF Injection",
    "CWE-94": "Code Injection",
    "CWE-98": "Remote File Inclusion",
    "CWE-99": "Resource Injection",
    "CWE-113": "HTTP Response Splitting",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-121": "Stack Overflow",
    "CWE-122": "Heap Overflow",
    "CWE-123": "Write-what-where Condition",
    "CWE-124": "Buffer Underflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-126": "Buffer Over-read",
    "CWE-127": "Buffer Under-read",
    "CWE-128": "Wrap-around Error",
    "CWE-129": "Array Index Underflow",
    "CWE-131": "Incorrect Buffer Size Calculation",
    "CWE-134": "Uncontrolled Format String",
    "CWE-170": "Improper Null Termination",
    "CWE-190": "Integer Overflow",
    "CWE-191": "Integer Underflow",
    "CWE-193": "Off-by-one Error",
    "CWE-200": "Information Disclosure",
    "CWE-209": "Info Exposure Through Error Message",
    "CWE-215": "Info Exposure Through Debug Info",
    "CWE-235": "Improper Handling of Extra Parameters",
    "CWE-256": "Plaintext Storage of Password",
    "CWE-257": "Storing Passwords in Recoverable Format",
    "CWE-259": "Hard-coded Password",
    "CWE-260": "Password in Configuration File",
    "CWE-261": "Weak Cryptography for Passwords",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-296": "Improper Chain of Trust",
    "CWE-300": "Man-in-the-Middle",
    "CWE-307": "Brute Force",
    "CWE-310": "Cryptographic Issues",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Info",
    "CWE-319": "Cleartext Transmission",
    "CWE-321": "Hard-coded Cryptographic Key",
    "CWE-322": "Key Exchange without Entity Auth",
    "CWE-323": "Reusing Nonce/Key Pair",
    "CWE-324": "Use of Key Past Expiration",
    "CWE-325": "Missing Required Crypto Step",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken/Risky Crypto Algorithm",
    "CWE-328": "Reversible One-Way Hash",
    "CWE-330": "Insufficiently Random Values",
    "CWE-338": "Weak PRNG",
    "CWE-349": "Cache Poisoning",
    "CWE-352": "CSRF",
    "CWE-359": "Privacy Violation",
    "CWE-400": "Denial of Service",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-425": "Direct Request / Forced Browsing",
    "CWE-434": "Unrestricted File Upload",
    "CWE-444": "HTTP Request Smuggling",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-523": "Unprotected Transport of Credentials",
    "CWE-524": "Cache Deception",
    "CWE-532": "Sensitive Info in Log Files",
    "CWE-548": "Info Exposure Through Directory Listing",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entities (XXE)",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-620": "Unverified Password Change",
    "CWE-639": "IDOR",
    "CWE-640": "Weak Forgotten Password Mechanism",
    "CWE-644": "HTTP Headers for Scripting Syntax",
    "CWE-657": "Violation of Secure Design Principles",
    "CWE-776": "XML Entity Expansion",
    "CWE-798": "Hard-coded Credentials",
    "CWE-840": "Business Logic Errors",
    "CWE-843": "Type Confusion",
    "CWE-918": "SSRF",
    "CWE-922": "Insecure Storage of Sensitive Info",
    "CWE-942": "CORS Misconfiguration",
    "CWE-1021": "Clickjacking",
    "CWE-1022": "window.opener Access",
    "CWE-1236": "CSV Formula Injection",
    "CWE-1336": "SSTI/CSTI",
    "CWE-1391": "Use of Weak Credentials",
    "CWE-1392": "Use of Default Credentials",
    "CWE-1395": "Vulnerable Third-Party Components",
    "CWE-1427": "LLM Prompt Injection",
    "CWE-16": "Server Misconfiguration / Takeover",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-date", default=None)
    args = parser.parse_args()

    # Find most recent unified report
    reports = sorted(REPORTS_DIR.glob("unified-report-*.json"), reverse=True)
    if not reports:
        print("No unified report found. Run merge-reports.py first.")
        return

    report_path = reports[0]
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    findings = report.get("findings", [])

    # Count by CWE
    cwe_counter = Counter()
    cwe_severity = {}
    for f in findings:
        cwe = f.get("cwe", "")
        if not cwe:
            continue
        # Normalize CWE-XXX
        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        cwe_counter[cwe] += 1
        sev = f.get("severity", "unknown")
        if cwe not in cwe_severity or _sev_rank(sev) > _sev_rank(cwe_severity[cwe]):
            cwe_severity[cwe] = sev

    scan_date = args.scan_date or report.get("scan_date", "unknown")
    output = REPORTS_DIR / f"cwe-summary-{scan_date}.txt"

    lines = [
        f"CWE Summary — Scan {scan_date}",
        f"Generated: {datetime.now().isoformat()}",
        f"Total findings: {len(findings)}",
        f"Unique CWEs: {len(cwe_counter)}",
        "",
        f"{'CWE':<12} {'Count':>6}  {'Severity':<10} Description",
        "─" * 80,
    ]

    for cwe, count in cwe_counter.most_common():
        desc = CWE_DESCRIPTIONS.get(cwe, "Unknown")
        sev = cwe_severity.get(cwe, "unknown")
        lines.append(f"{cwe:<12} {count:>6}  {sev:<10} {desc}")

    # Coverage report
    lines.extend(["", "", "Coverage Report: CWEs in scope vs detected", "─" * 80])
    detected = set(cwe_counter.keys())
    in_scope = set(CWE_DESCRIPTIONS.keys())
    covered = detected & in_scope
    missing = in_scope - detected

    lines.append(f"In scope:  {len(in_scope)}")
    lines.append(f"Detected:  {len(covered)}")
    lines.append(f"Not found: {len(missing)}")
    lines.append("")
    if missing:
        lines.append("CWEs not detected (may require manual testing):")
        for cwe in sorted(missing):
            lines.append(f"  {cwe}: {CWE_DESCRIPTIONS[cwe]}")

    text = "\n".join(lines)
    output.write_text(text, encoding="utf-8")
    print(text)
    print(f"\nSaved to: {output}")


def _sev_rank(sev):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, -1)


if __name__ == "__main__":
    main()
