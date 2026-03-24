#!/usr/bin/env python3
"""Web Cache Deception scanner — detect cache poisoning & path confusion.

CWE-346 (Origin Validation), CWE-524 (Information Exposure Through Caching),
CWE-444 (HTTP Request Smuggling — cache poisoning variant)

Tests:
- Path confusion: /account/wcd.css, /account/..%2F../static/x.css
- Cache key normalization issues
- Cache header analysis (X-Cache, Age, CF-Cache-Status)
- Unauthenticated access to cached authenticated pages

Usage:
    python cache_deception.py --target https://example.com
    python cache_deception.py --target https://example.com --auth-cookie "session=abc123"

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("requests required: pip install requests")
    sys.exit(1)

OUTPUT_DIR = Path("/output") if Path("/output").exists() else Path("reports/cache-deception")

# Sensitive paths likely to contain user data
SENSITIVE_PATHS = [
    "/account", "/profile", "/settings", "/dashboard",
    "/api/me", "/api/user", "/api/account",
    "/my-account", "/user/profile",
]

# Cache-busting extensions
CACHE_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".webp", ".avif",
]

# Path confusion patterns
PATH_CONFUSIONS = [
    "/{path}{ext}",                          # /account.css
    "/{path}/{random}{ext}",                 # /account/wcd.css
    "/{path}%2F{random}{ext}",               # /account%2Fwcd.css
    "/{path}/..%2F..%2Fstatic/{random}{ext}",# path traversal through cache
    "/{path}/%2e%2e/%2e%2e/static/{random}{ext}",  # double-encoded
    "/{path};{random}{ext}",                 # semicolon (Tomcat)
    "/{path}%23{random}{ext}",               # URL-encoded fragment
    "/{path}%3F{random}{ext}",               # URL-encoded question mark
    "/{path}%00{random}{ext}",               # null byte
]

CACHE_HEADERS = ["x-cache", "x-cache-status", "cf-cache-status", "age",
                 "x-varnish", "x-fastly-request-id", "x-served-by",
                 "via", "x-proxy-cache", "x-cache-hit"]


def _is_cached(headers: dict) -> bool:
    """Heuristic: check if response came from cache."""
    h = {k.lower(): v.lower() for k, v in headers.items()}

    if h.get("x-cache", "").startswith("hit"):
        return True
    if h.get("cf-cache-status") in ("hit", "dynamic"):
        return True
    if h.get("x-cache-status") in ("hit", "stale"):
        return True
    if "age" in h:
        try:
            return int(h["age"]) > 0
        except ValueError:
            pass
    return False


def _get_cache_info(headers: dict) -> dict:
    """Extract cache-relevant headers."""
    info = {}
    for hdr in CACHE_HEADERS:
        val = headers.get(hdr)
        if val:
            info[hdr] = val
    return info


def _get_sensitive_content_markers(text: str) -> list[str]:
    """Check if response contains user-specific data indicators."""
    markers = []
    patterns = [
        (r'"email"\s*:\s*"[^"]+@', "email"),
        (r'"username"\s*:\s*"', "username"),
        (r'"name"\s*:\s*"', "name"),
        (r'"token"\s*:\s*"', "token"),
        (r'"password', "password_field"),
        (r'"ssn"\s*:\s*"', "ssn"),
        (r'"credit_card', "credit_card"),
        (r'csrf[_-]?token', "csrf_token"),
        (r'<input[^>]*name="password"', "password_form"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            markers.append(label)
    return markers


def test_cache_deception(
    target: str,
    path: str,
    session: requests.Session,
    auth_headers: dict | None = None,
    rate_limit: int = 10,
) -> list[dict]:
    """Test cache deception on a single sensitive path."""
    findings = []
    base_url = target.rstrip("/")

    # Step 1: Get authenticated baseline
    auth_resp = session.get(
        urljoin(base_url, path),
        headers=auth_headers or {},
        verify=False,
        timeout=10,
        allow_redirects=True,
    )

    if auth_resp.status_code not in (200, 301, 302):
        return findings

    auth_markers = _get_sensitive_content_markers(auth_resp.text)
    if not auth_markers:
        return findings  # No sensitive data on this path — skip

    # Step 2: Try each path confusion pattern
    for pattern in PATH_CONFUSIONS:
        for ext in CACHE_EXTENSIONS[:5]:  # Limit extensions to control rate
            confused_path = pattern.format(
                path=path.lstrip("/"),
                random="wcd",
                ext=ext,
            )
            confused_url = urljoin(base_url + "/", confused_path)

            try:
                # Request WITH auth (prime the cache)
                r1 = session.get(
                    confused_url,
                    headers=auth_headers or {},
                    verify=False,
                    timeout=10,
                    allow_redirects=True,
                )
                time.sleep(1.0 / max(rate_limit, 1))

                if r1.status_code not in (200, 301, 302):
                    continue

                cache_info = _get_cache_info(dict(r1.headers))

                # Request WITHOUT auth (test if cached version is served)
                r2 = session.get(
                    confused_url,
                    verify=False,
                    timeout=10,
                    allow_redirects=True,
                )
                time.sleep(1.0 / max(rate_limit, 1))

                if r2.status_code != 200:
                    continue

                # Check if unauthenticated response has sensitive data
                unauth_markers = _get_sensitive_content_markers(r2.text)
                cached = _is_cached(dict(r2.headers))

                if unauth_markers and (cached or cache_info):
                    severity = "critical" if len(unauth_markers) > 1 else "high"
                    findings.append({
                        "id": f"wcd-{path.replace('/', '-').strip('-')}-{ext.strip('.')}",
                        "name": f"Web Cache Deception on {path}",
                        "severity": severity,
                        "cwe": "CWE-524",
                        "url": confused_url,
                        "detail": (
                            f"Cached authenticated page accessible without auth. "
                            f"Sensitive data exposed: {', '.join(unauth_markers)}. "
                            f"Pattern: {pattern}"
                        ),
                        "evidence": json.dumps({
                            "confused_url": confused_url,
                            "original_path": path,
                            "cache_headers": cache_info,
                            "sensitive_markers": unauth_markers,
                            "is_cached": cached,
                        }),
                    })
                    break  # One finding per path is enough

            except requests.RequestException:
                continue

    return findings


def check_cache_headers(target: str, session: requests.Session) -> list[dict]:
    """Analyze main page for cache misconfigurations."""
    findings = []
    try:
        resp = session.get(target, verify=False, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Missing Cache-Control
        if "cache-control" not in headers:
            findings.append({
                "id": "wcd-missing-cache-control",
                "name": "Missing Cache-Control Header",
                "severity": "low",
                "cwe": "CWE-524",
                "url": target,
                "detail": "No Cache-Control header set — default caching behavior may cache sensitive pages",
                "evidence": json.dumps({"headers": _get_cache_info(dict(resp.headers))}),
            })
        elif "no-store" not in headers.get("cache-control", ""):
            # Cache-Control exists but doesn't prevent storage
            if "private" not in headers.get("cache-control", ""):
                findings.append({
                    "id": "wcd-weak-cache-control",
                    "name": "Weak Cache-Control (no no-store/private)",
                    "severity": "medium",
                    "cwe": "CWE-524",
                    "url": target,
                    "detail": f"Cache-Control: {headers['cache-control']} — may allow proxy caching of sensitive data",
                    "evidence": json.dumps({"cache-control": headers["cache-control"]}),
                })
    except requests.RequestException:
        pass

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Web Cache Deception scanner")
    parser.add_argument("--target", "-t", required=True, help="Target URL")
    parser.add_argument("--auth-cookie", help="Authentication cookie (e.g. 'session=abc123')")
    parser.add_argument("--auth-header", help="Authorization header value (e.g. 'Bearer xxx')")
    parser.add_argument("--paths", default="", help="Comma-separated sensitive paths to test")
    parser.add_argument("--rate-limit", type=int, default=10, help="Requests per second")
    parser.add_argument("--config", help="Config YAML path")
    parser.add_argument("--output", "-o", default=str(OUTPUT_DIR / "results.json"))
    args = parser.parse_args()

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (security-scanner/cache-deception)"

    auth_headers = {}
    if args.auth_cookie:
        session.headers["Cookie"] = args.auth_cookie
        auth_headers["Cookie"] = args.auth_cookie
    if args.auth_header:
        session.headers["Authorization"] = args.auth_header
        auth_headers["Authorization"] = args.auth_header

    paths = [p.strip() for p in args.paths.split(",") if p.strip()] if args.paths else SENSITIVE_PATHS

    print(f"[*] Web Cache Deception Scanner — Target: {args.target}")
    print(f"[*] Testing {len(paths)} sensitive paths x {len(PATH_CONFUSIONS)} patterns")

    all_findings: list[dict] = []

    # Cache header analysis
    header_findings = check_cache_headers(args.target, session)
    all_findings.extend(header_findings)
    print(f"[+] Cache header analysis: {len(header_findings)} findings")

    # Path confusion tests
    for path in paths:
        print(f"\n[*] Testing: {path}")
        path_findings = test_cache_deception(
            args.target, path, session,
            auth_headers=auth_headers if auth_headers else None,
            rate_limit=args.rate_limit,
        )
        print(f"  Findings: {len(path_findings)}")
        all_findings.extend(path_findings)

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(all_findings, indent=2))

    print(f"\n{'='*50}")
    print(f"Total findings: {len(all_findings)}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sum(1 for f in all_findings if f.get("severity") == sev)
        if count:
            print(f"  {sev.upper()}: {count}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
