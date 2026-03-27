#!/usr/bin/env python3
"""Header Classifier — Security header analysis + tech fingerprinting (CWE-200).

Analyzes HTTP response headers to:
- Grade security header implementation (CSP, HSTS, X-Frame-Options, etc.)
- Fingerprint server technology stack
- Detect misconfigurations
- Check cookie security attributes
- Identify deprecated/dangerous headers

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import re
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Security headers checklist
# ---------------------------------------------------------------------------

SECURITY_HEADERS: list[dict] = [
    {
        "header": "Strict-Transport-Security",
        "required": True,
        "severity_missing": "high",
        "cwe": "CWE-319",
        "description": "HSTS prevents protocol downgrade attacks",
        "best_practice": "max-age=31536000; includeSubDomains; preload",
        "check": lambda v: "max-age=" in v.lower() and int(re.search(r'max-age=(\d+)', v.lower()).group(1)) >= 31536000 if re.search(r'max-age=(\d+)', v.lower()) else False,
    },
    {
        "header": "Content-Security-Policy",
        "required": True,
        "severity_missing": "high",
        "cwe": "CWE-79",
        "description": "CSP prevents XSS and data injection attacks",
        "best_practice": "default-src 'self'; script-src 'self'",
        "check": lambda v: "unsafe-inline" not in v and "unsafe-eval" not in v,
    },
    {
        "header": "X-Content-Type-Options",
        "required": True,
        "severity_missing": "medium",
        "cwe": "CWE-16",
        "description": "Prevents MIME type sniffing",
        "best_practice": "nosniff",
        "check": lambda v: v.lower().strip() == "nosniff",
    },
    {
        "header": "X-Frame-Options",
        "required": True,
        "severity_missing": "medium",
        "cwe": "CWE-1021",
        "description": "Prevents clickjacking attacks",
        "best_practice": "DENY or SAMEORIGIN",
        "check": lambda v: v.upper().strip() in ("DENY", "SAMEORIGIN"),
    },
    {
        "header": "X-XSS-Protection",
        "required": False,
        "severity_missing": "low",
        "cwe": "CWE-79",
        "description": "Legacy XSS filter (deprecated in modern browsers)",
        "best_practice": "0 (disabled, rely on CSP instead)",
        "check": lambda v: v.strip() == "0",
    },
    {
        "header": "Referrer-Policy",
        "required": True,
        "severity_missing": "medium",
        "cwe": "CWE-200",
        "description": "Controls referer header information leakage",
        "best_practice": "strict-origin-when-cross-origin or no-referrer",
        "check": lambda v: v.lower().strip() in ("strict-origin-when-cross-origin", "no-referrer", "same-origin", "strict-origin"),
    },
    {
        "header": "Permissions-Policy",
        "required": True,
        "severity_missing": "medium",
        "cwe": "CWE-16",
        "description": "Controls browser feature access (camera, mic, geolocation)",
        "best_practice": "geolocation=(), camera=(), microphone=()",
        "check": lambda v: len(v) > 0,
    },
    {
        "header": "Cross-Origin-Opener-Policy",
        "required": False,
        "severity_missing": "low",
        "cwe": "CWE-16",
        "description": "Prevents cross-origin window access",
        "best_practice": "same-origin",
        "check": lambda v: v.lower().strip() == "same-origin",
    },
    {
        "header": "Cross-Origin-Resource-Policy",
        "required": False,
        "severity_missing": "low",
        "cwe": "CWE-16",
        "description": "Prevents cross-origin resource loading",
        "best_practice": "same-origin",
        "check": lambda v: v.lower().strip() in ("same-origin", "same-site"),
    },
    {
        "header": "Cross-Origin-Embedder-Policy",
        "required": False,
        "severity_missing": "low",
        "cwe": "CWE-16",
        "description": "Required for SharedArrayBuffer, prevents Spectre attacks",
        "best_practice": "require-corp",
        "check": lambda v: v.lower().strip() == "require-corp",
    },
]

# Headers that reveal server info
FINGERPRINT_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "X-Cache",
    "X-Runtime", "X-Version", "X-Framework", "X-Turbo-Request-Id",
    "X-Request-Id", "X-Amzn-Requestid", "CF-Ray", "X-Cloud-Trace-Context",
]

# Dangerous headers that should not be exposed
DANGEROUS_HEADERS = [
    "X-Debug", "X-Debug-Token", "X-Debug-Token-Link",
    "X-PHP-Originating-Script", "X-SourceMap", "SourceMap",
]


def analyze_security_headers(headers: dict[str, str]) -> tuple[list[dict], int]:
    """Analyze security headers and return issues + score."""
    issues: list[dict] = []
    score = 100
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for spec in SECURITY_HEADERS:
        header_lower = spec["header"].lower()
        value = headers_lower.get(header_lower)

        if value is None:
            if spec["required"]:
                issues.append({
                    "header": spec["header"],
                    "issue": "missing",
                    "severity": spec["severity_missing"],
                    "cwe": spec["cwe"],
                    "description": f"Missing: {spec['description']}",
                    "best_practice": spec["best_practice"],
                })
                penalty = {"high": 15, "medium": 10, "low": 5}.get(spec["severity_missing"], 5)
                score -= penalty
        else:
            try:
                if not spec["check"](value):
                    issues.append({
                        "header": spec["header"],
                        "issue": "misconfigured",
                        "severity": "medium",
                        "cwe": spec["cwe"],
                        "current_value": value,
                        "description": f"Weak configuration: {spec['description']}",
                        "best_practice": spec["best_practice"],
                    })
                    score -= 5
            except Exception:
                pass

    return issues, max(0, score)


def analyze_cookies(headers: dict[str, str]) -> list[dict]:
    """Analyze Set-Cookie headers for security attributes."""
    issues: list[dict] = []
    set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
    if not set_cookie:
        return issues

    # Handle multiple Set-Cookie headers (may be comma-separated)
    cookies = set_cookie.split("\n") if "\n" in set_cookie else [set_cookie]

    for cookie in cookies:
        parts = cookie.split(";")
        if not parts:
            continue

        name_val = parts[0].strip()
        name = name_val.split("=", 1)[0].strip() if "=" in name_val else name_val
        attrs_str = cookie.lower()

        if "secure" not in attrs_str:
            issues.append({
                "cookie": name,
                "issue": "missing_secure",
                "severity": "medium",
                "description": f"Cookie '{name}' missing Secure flag (sent over HTTP)",
            })

        if "httponly" not in attrs_str:
            issues.append({
                "cookie": name,
                "issue": "missing_httponly",
                "severity": "medium",
                "description": f"Cookie '{name}' missing HttpOnly flag (accessible via JS)",
            })

        if "samesite" not in attrs_str:
            issues.append({
                "cookie": name,
                "issue": "missing_samesite",
                "severity": "medium",
                "description": f"Cookie '{name}' missing SameSite attribute",
            })
        elif "samesite=none" in attrs_str:
            issues.append({
                "cookie": name,
                "issue": "samesite_none",
                "severity": "medium",
                "description": f"Cookie '{name}' has SameSite=None (sent in cross-site requests)",
            })

    return issues


def fingerprint_technology(headers: dict[str, str]) -> list[dict]:
    """Extract technology fingerprints from response headers."""
    fingerprints: list[dict] = []

    for header in FINGERPRINT_HEADERS:
        value = headers.get(header) or headers.get(header.lower())
        if value:
            fingerprints.append({
                "header": header,
                "value": value,
                "category": "server" if header.lower() in ("server", "x-powered-by") else "infrastructure",
            })

    # Check for dangerous debug headers
    for header in DANGEROUS_HEADERS:
        value = headers.get(header) or headers.get(header.lower())
        if value:
            fingerprints.append({
                "header": header,
                "value": value,
                "category": "debug",
                "dangerous": True,
            })

    return fingerprints


def scan(
    session: RateLimitedSession,
    target: str,
    paths: list[str] | None = None,
    dry_run: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    check_paths = paths or ["/", "/api", "/login", "/health"]

    for path in check_paths:
        url = f"{target.rstrip('/')}{path}"
        if dry_run:
            log.info("[DRY-RUN] GET %s", url)
            continue

        try:
            resp = session.get(url, allow_redirects=False, timeout=10)
        except Exception as e:
            log.debug("Error fetching %s: %s", url, e)
            continue

        headers = dict(resp.headers)

        # Phase 1: Security headers
        issues, score = analyze_security_headers(headers)
        if issues:
            for issue in issues:
                findings.append(Finding(
                    title=f"Security Header: {issue['header']} ({issue['issue']})",
                    severity=issue["severity"],
                    cwe=issue["cwe"],
                    endpoint=url,
                    method="GET",
                    description=issue["description"],
                    steps=[
                        f"GET {url}",
                        f"Check {issue['header']}: {'missing' if issue['issue'] == 'missing' else issue.get('current_value', '')}",
                        f"Best practice: {issue['best_practice']}",
                    ],
                    impact=f"Weakened security posture (score: {score}/100)",
                    evidence=issue,
                    remediation=f"Set {issue['header']}: {issue['best_practice']}",
                ))

        # Phase 2: Cookie security
        cookie_issues = analyze_cookies(headers)
        for ci in cookie_issues:
            findings.append(Finding(
                title=f"Cookie Security: {ci['cookie']} ({ci['issue']})",
                severity=ci["severity"],
                cwe="CWE-614",
                endpoint=url,
                method="GET",
                description=ci["description"],
                steps=[f"GET {url}", f"Inspect Set-Cookie header for {ci['cookie']}"],
                impact="Session hijacking or CSRF risk due to insecure cookie configuration",
                evidence=ci,
                remediation="Set Secure, HttpOnly, SameSite=Strict on all session cookies.",
            ))

        # Phase 3: Technology fingerprinting
        fingerprints = fingerprint_technology(headers)
        dangerous_fps = [fp for fp in fingerprints if fp.get("dangerous")]
        info_fps = [fp for fp in fingerprints if not fp.get("dangerous")]

        if dangerous_fps:
            findings.append(Finding(
                title=f"Debug Headers Exposed on {path}",
                severity="high",
                cwe="CWE-200",
                endpoint=url,
                method="GET",
                description=f"Dangerous debug headers found: {', '.join(fp['header'] for fp in dangerous_fps)}",
                steps=[f"GET {url}", f"Headers: {', '.join(f'{fp[\"header\"]}: {fp[\"value\"]}' for fp in dangerous_fps)}"],
                impact="Internal debug information leakage",
                evidence=dangerous_fps,
                remediation="Remove all debug headers from production responses.",
            ))

        if info_fps:
            findings.append(Finding(
                title=f"Technology Fingerprint: {path}",
                severity="low",
                cwe="CWE-200",
                endpoint=url,
                method="GET",
                description=f"Server technology revealed via headers: {', '.join(fp['header'] for fp in info_fps[:5])}",
                steps=[f"GET {url}"] + [f"  {fp['header']}: {fp['value']}" for fp in info_fps[:5]],
                impact="Technology stack identification aids targeted attacks",
                evidence=info_fps,
                remediation="Remove Server, X-Powered-By and version headers.",
            ))

    return findings


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--paths", nargs="*", default=None,
                        help="Paths to check (default: /, /api, /login, /health)")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    log.info("=== Header Classifier starting on %s ===", args.target)
    all_findings = scan(session, args.target, args.paths, args.dry_run)
    log.info("=== Header Classifier complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "header-classifier")


if __name__ == "__main__":
    main()
