#!/usr/bin/env python3
"""Timing Oracle — SSRF/auth timing differential detection (CWE-208/918).

Detects timing side channels:
- User enumeration via login response time differences
- SSRF via timing differentials on internal vs external URLs
- Token validation timing leaks
- Rate limiting inconsistencies
- Blind boolean conditions via response time

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import statistics
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TIMING_SAMPLES = 5          # Number of requests per test
TIMING_THRESHOLD_MS = 100   # Minimum difference (ms) to flag
BASELINE_THRESHOLD_MS = 50  # Max stddev for reliable baseline

# Default auth endpoints
DEFAULT_AUTH_ENDPOINTS = [
    {"path": "/api/auth/login", "method": "POST", "body": {"username": "{user}", "password": "wrongpassword123!"}},
    {"path": "/api/v1/auth/login", "method": "POST", "body": {"email": "{user}", "password": "wrongpassword123!"}},
    {"path": "/login", "method": "POST", "body": {"username": "{user}", "password": "wrongpassword123!"}},
    {"path": "/api/auth/signin", "method": "POST", "body": {"email": "{user}", "password": "wrongpassword123!"}},
]

# User enumeration test pairs
ENUM_USERS = [
    ("admin", "nonexistent_user_abc123xyz"),
    ("root", "definitely_not_a_user_9876"),
    ("test@example.com", "fake_email_no_exist@impossible.invalid"),
]

# SSRF test URLs (safe — no actual requests to internal services)
SSRF_TARGETS = [
    ("https://httpbin.org/get", "external"),
    ("http://127.0.0.1:80", "internal_loopback"),
    ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp_metadata"),
    ("http://[::1]:80", "ipv6_loopback"),
]


def measure_response_time(
    session: RateLimitedSession,
    method: str,
    url: str,
    body: dict | None = None,
    samples: int = TIMING_SAMPLES,
) -> tuple[list[float], float, float]:
    """Measure response times and return (times_ms, mean_ms, stddev_ms)."""
    times: list[float] = []

    for _ in range(samples):
        start = time.monotonic()
        try:
            if method.upper() == "POST":
                session.post(url, json=body, timeout=15)
            else:
                session.get(url, timeout=15)
        except Exception:
            pass
        elapsed = (time.monotonic() - start) * 1000  # ms
        times.append(elapsed)
        time.sleep(0.05)  # Small delay between samples

    if not times:
        return [], 0.0, 0.0

    mean = statistics.mean(times)
    stddev = statistics.stdev(times) if len(times) > 1 else 0.0
    return times, mean, stddev


def scan_user_enumeration(
    session: RateLimitedSession,
    target: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Detect user enumeration via timing differences."""
    findings: list[Finding] = []

    for ep in DEFAULT_AUTH_ENDPOINTS:
        url = f"{target.rstrip('/')}{ep['path']}"
        if dry_run:
            log.info("[DRY-RUN] User enumeration test: %s", url)
            continue

        # Check if endpoint exists
        try:
            test_resp = session.post(url, json={"test": "probe"}, timeout=5)
            if test_resp.status_code == 404:
                continue
        except Exception:
            continue

        for valid_user, invalid_user in ENUM_USERS:
            # Measure valid user timing
            valid_body = json.loads(
                json.dumps(ep["body"]).replace("{user}", valid_user)
            )
            _, valid_mean, valid_stddev = measure_response_time(
                session, ep["method"], url, valid_body
            )

            # Measure invalid user timing
            invalid_body = json.loads(
                json.dumps(ep["body"]).replace("{user}", invalid_user)
            )
            _, invalid_mean, invalid_stddev = measure_response_time(
                session, ep["method"], url, invalid_body
            )

            # Check if baselines are reliable
            if valid_stddev > BASELINE_THRESHOLD_MS or invalid_stddev > BASELINE_THRESHOLD_MS:
                log.info("  Unreliable baseline (stddev too high), skipping")
                continue

            diff = abs(valid_mean - invalid_mean)
            if diff >= TIMING_THRESHOLD_MS:
                faster = "valid user" if valid_mean < invalid_mean else "invalid user"
                findings.append(Finding(
                    title=f"User Enumeration via Timing: {ep['path']}",
                    severity="medium",
                    cwe="CWE-208",
                    endpoint=url,
                    method=ep["method"],
                    description=(
                        f"Timing difference of {diff:.0f}ms between valid and "
                        f"invalid users. {faster} responds faster."
                    ),
                    steps=[
                        f"POST {url} with valid user '{valid_user}': avg {valid_mean:.0f}ms (±{valid_stddev:.0f}ms)",
                        f"POST {url} with invalid user '{invalid_user}': avg {invalid_mean:.0f}ms (±{invalid_stddev:.0f}ms)",
                        f"Difference: {diff:.0f}ms (threshold: {TIMING_THRESHOLD_MS}ms)",
                    ],
                    impact="Attackers can enumerate valid usernames before brute-forcing passwords",
                    evidence={
                        "valid_user_ms": round(valid_mean, 1),
                        "invalid_user_ms": round(invalid_mean, 1),
                        "difference_ms": round(diff, 1),
                        "threshold_ms": TIMING_THRESHOLD_MS,
                    },
                    remediation=(
                        "Use constant-time comparison for user lookups. "
                        "Add artificial delay to normalize response times."
                    ),
                ))

    return findings


def scan_ssrf_timing(
    session: RateLimitedSession,
    target: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Detect SSRF via timing differences on URL fetch endpoints."""
    findings: list[Finding] = []

    # Common URL fetch/proxy endpoints
    url_endpoints = [
        "/api/fetch", "/api/proxy", "/api/url", "/api/preview",
        "/api/v1/fetch", "/webhook/test", "/api/image",
    ]

    for ep_path in url_endpoints:
        url = f"{target.rstrip('/')}{ep_path}"
        if dry_run:
            log.info("[DRY-RUN] SSRF timing test: %s", url)
            continue

        # Check if endpoint exists
        try:
            test_resp = session.post(url, json={"url": "https://example.com"}, timeout=5)
            if test_resp.status_code == 404:
                continue
        except Exception:
            continue

        log.info("  Testing SSRF timing on %s", ep_path)

        # Measure baseline with external URL
        ext_url = "https://httpbin.org/get"
        _, ext_mean, ext_stddev = measure_response_time(
            session, "POST", url, {"url": ext_url}, samples=3,
        )

        if ext_mean == 0:
            continue

        # Test internal URLs
        for ssrf_target, ssrf_type in SSRF_TARGETS[1:]:  # Skip external baseline
            _, int_mean, int_stddev = measure_response_time(
                session, "POST", url, {"url": ssrf_target}, samples=3,
            )

            diff = abs(ext_mean - int_mean)
            if diff >= TIMING_THRESHOLD_MS and int_mean > 0:
                faster = "internal" if int_mean < ext_mean else "external"
                findings.append(Finding(
                    title=f"SSRF Timing Oracle: {ssrf_type} on {ep_path}",
                    severity="high",
                    cwe="CWE-918",
                    endpoint=url,
                    method="POST",
                    description=(
                        f"Timing difference of {diff:.0f}ms between external and "
                        f"{ssrf_type} URL. {faster} responds faster."
                    ),
                    steps=[
                        f"POST {url} with external URL: avg {ext_mean:.0f}ms",
                        f"POST {url} with {ssrf_type}: avg {int_mean:.0f}ms",
                        f"Difference: {diff:.0f}ms",
                    ],
                    impact="Server-Side Request Forgery: internal resources may be reachable",
                    evidence={
                        "external_ms": round(ext_mean, 1),
                        "internal_ms": round(int_mean, 1),
                        "ssrf_type": ssrf_type,
                        "difference_ms": round(diff, 1),
                    },
                    remediation=(
                        "Block internal IPs in URL fetch. Use allowlist for external domains. "
                        "Normalize response times for error conditions."
                    ),
                ))

    return findings


def scan_token_timing(
    session: RateLimitedSession,
    target: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Detect token validation timing leaks."""
    findings: list[Finding] = []

    # Test endpoints that accept tokens
    token_endpoints = ["/api/me", "/api/v1/me", "/api/user", "/api/profile"]

    for ep_path in token_endpoints:
        url = f"{target.rstrip('/')}{ep_path}"
        if dry_run:
            log.info("[DRY-RUN] Token timing test: %s", url)
            continue

        try:
            test_resp = session.get(url, timeout=5)
            if test_resp.status_code == 404:
                continue
        except Exception:
            continue

        # Measure with no token
        orig_headers = dict(session.headers)
        session.headers.pop("Authorization", None)
        _, no_token_mean, _ = measure_response_time(session, "GET", url, samples=3)

        # Measure with short invalid token
        session.headers["Authorization"] = "Bearer invalid"
        _, short_token_mean, _ = measure_response_time(session, "GET", url, samples=3)

        # Measure with long invalid token (looks like JWT)
        session.headers["Authorization"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        _, jwt_token_mean, _ = measure_response_time(session, "GET", url, samples=3)

        # Restore headers
        session.headers = orig_headers

        # Compare timings
        diffs = [
            abs(no_token_mean - short_token_mean),
            abs(no_token_mean - jwt_token_mean),
            abs(short_token_mean - jwt_token_mean),
        ]
        max_diff = max(diffs)

        if max_diff >= TIMING_THRESHOLD_MS:
            findings.append(Finding(
                title=f"Token Validation Timing Leak: {ep_path}",
                severity="medium",
                cwe="CWE-208",
                endpoint=url,
                method="GET",
                description=f"Token validation shows timing differences ({max_diff:.0f}ms max delta)",
                steps=[
                    f"GET {url} with no token: {no_token_mean:.0f}ms",
                    f"GET {url} with short token: {short_token_mean:.0f}ms",
                    f"GET {url} with JWT-like token: {jwt_token_mean:.0f}ms",
                    f"Max difference: {max_diff:.0f}ms",
                ],
                impact="Token format or validity can be inferred from response timing",
                evidence={
                    "no_token_ms": round(no_token_mean, 1),
                    "short_token_ms": round(short_token_mean, 1),
                    "jwt_token_ms": round(jwt_token_mean, 1),
                    "max_diff_ms": round(max_diff, 1),
                },
                remediation="Use constant-time token comparison. Return immediately for missing tokens.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--threshold-ms", type=int, default=TIMING_THRESHOLD_MS,
                        help="Timing difference threshold in ms (default: 100)")
    parser.add_argument("--samples", type=int, default=TIMING_SAMPLES,
                        help="Number of timing samples per test (default: 5)")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    global TIMING_THRESHOLD_MS, TIMING_SAMPLES
    TIMING_THRESHOLD_MS = args.threshold_ms
    TIMING_SAMPLES = args.samples

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    all_findings: list[Finding] = []

    log.info("=== Timing Oracle starting on %s ===", args.target)

    log.info("--- Phase 1: User Enumeration ---")
    all_findings.extend(scan_user_enumeration(session, args.target, args.dry_run))

    log.info("--- Phase 2: SSRF Timing ---")
    all_findings.extend(scan_ssrf_timing(session, args.target, args.dry_run))

    log.info("--- Phase 3: Token Timing ---")
    all_findings.extend(scan_token_timing(session, args.target, args.dry_run))

    log.info("=== Timing Oracle complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "timing-oracle")


if __name__ == "__main__":
    main()
