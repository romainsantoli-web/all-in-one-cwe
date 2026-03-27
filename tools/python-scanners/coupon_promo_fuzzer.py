#!/usr/bin/env python3
"""Coupon & Promo Fuzzer — Business logic coupon/promo code abuse (CWE-639/915).

Tests business logic vulnerabilities in coupon/promotion systems:
- Code reuse after redemption
- Stacking multiple codes
- Race condition on redemption
- Negative quantity / price manipulation
- Expired code bypass
- Case sensitivity bypass

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import sys
import os
import time
import threading
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Default coupon endpoints & payloads
# ---------------------------------------------------------------------------

DEFAULT_COUPON_ENDPOINTS = [
    {"path": "/api/coupons/apply", "method": "POST", "body_key": "code"},
    {"path": "/api/v1/coupons/apply", "method": "POST", "body_key": "code"},
    {"path": "/api/promo/apply", "method": "POST", "body_key": "promoCode"},
    {"path": "/api/cart/coupon", "method": "POST", "body_key": "coupon"},
    {"path": "/api/discount/apply", "method": "POST", "body_key": "discountCode"},
    {"path": "/api/voucher/redeem", "method": "POST", "body_key": "voucher"},
    {"path": "/checkout/apply-coupon", "method": "POST", "body_key": "code"},
]

# Common test coupon codes
TEST_CODES = [
    "TEST", "WELCOME", "FIRST10", "SAVE20", "FREESHIP",
    "ADMIN", "DEBUG", "INTERNAL", "EMPLOYEE",
    "EXPIRED2024", "BLACKFRIDAY", "SUMMER2025",
]

# Mass-assignment / parameter pollution payloads
MASS_ASSIGNMENT_PAYLOADS = [
    {"discount_percent": 100},
    {"discount_amount": 99999},
    {"price": 0},
    {"total": 0},
    {"is_valid": True},
    {"expires_at": "2099-12-31T23:59:59Z"},
    {"max_uses": 999999},
    {"used_count": 0},
]


def discover_coupon_endpoints(
    session: RateLimitedSession,
    target: str,
    dry_run: bool = False,
) -> list[dict]:
    """Discover active coupon endpoints."""
    active: list[dict] = []

    for ep in DEFAULT_COUPON_ENDPOINTS:
        url = urljoin(target, ep["path"])
        if dry_run:
            log.info("[DRY-RUN] OPTIONS %s", url)
            continue

        try:
            # Try OPTIONS first
            resp = session.request("OPTIONS", url, timeout=5)
            if resp.status_code != 404:
                active.append({**ep, "url": url})
                continue

            # Try POST with empty body
            resp = session.post(url, json={}, timeout=5)
            if resp.status_code in (400, 401, 422):  # Exists but invalid input
                active.append({**ep, "url": url})
        except Exception:
            pass

    return active


def test_code_reuse(
    session: RateLimitedSession,
    endpoint: dict,
    code: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Test if a coupon code can be applied multiple times."""
    findings: list[Finding] = []
    url = endpoint["url"]
    body_key = endpoint["body_key"]

    if dry_run:
        log.info("[DRY-RUN] Testing code reuse: %s on %s", code, url)
        return findings

    results = []
    for i in range(3):
        try:
            resp = session.post(url, json={body_key: code}, timeout=10)
            results.append(resp.status_code)
        except Exception:
            break

    # If all 3 attempts succeed, code can be reused
    success_count = sum(1 for s in results if s == 200)
    if success_count >= 2:
        findings.append(Finding(
            title=f"Coupon Reuse: '{code}' applied {success_count}x",
            severity="high",
            cwe="CWE-639",
            endpoint=url,
            method="POST",
            description=f"Coupon code '{code}' can be applied {success_count} times without limit.",
            steps=[
                f"POST {url} with {body_key}={code}",
                f"Repeat 3 times",
                f"Success count: {success_count}/3",
            ],
            impact="Financial loss through unlimited coupon reuse",
            evidence={"code": code, "attempts": 3, "successes": success_count, "statuses": results},
            remediation="Track coupon usage per user/session. Enforce single-use or max-use limits.",
        ))

    return findings


def test_code_stacking(
    session: RateLimitedSession,
    endpoint: dict,
    codes: list[str],
    dry_run: bool = False,
) -> list[Finding]:
    """Test if multiple codes can be stacked."""
    findings: list[Finding] = []
    url = endpoint["url"]
    body_key = endpoint["body_key"]

    if dry_run:
        log.info("[DRY-RUN] Testing code stacking: %s", codes[:3])
        return findings

    applied: list[str] = []
    for code in codes[:5]:
        try:
            resp = session.post(url, json={body_key: code}, timeout=10)
            if resp.status_code == 200:
                applied.append(code)
        except Exception:
            pass

    if len(applied) >= 2:
        findings.append(Finding(
            title=f"Coupon Stacking: {len(applied)} codes applied",
            severity="high",
            cwe="CWE-639",
            endpoint=url,
            method="POST",
            description=f"Multiple coupon codes can be stacked: {', '.join(applied)}",
            steps=[
                f"Apply codes sequentially to {url}",
                f"Applied: {', '.join(applied)}",
            ],
            impact="Accumulated discounts beyond intended limits",
            evidence={"applied_codes": applied, "count": len(applied)},
            remediation="Allow only one active coupon per cart/order.",
        ))

    return findings


def test_race_condition(
    session: RateLimitedSession,
    endpoint: dict,
    code: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Test race condition on coupon redemption (concurrent requests)."""
    findings: list[Finding] = []
    url = endpoint["url"]
    body_key = endpoint["body_key"]

    if dry_run:
        log.info("[DRY-RUN] Testing race condition: %s on %s", code, url)
        return findings

    results: list[int] = []
    lock = threading.Lock()

    def send_request():
        try:
            # Use a fresh session to avoid rate limiting interference
            import requests
            resp = requests.post(url, json={body_key: code}, timeout=10)
            with lock:
                results.append(resp.status_code)
        except Exception:
            pass

    threads = [threading.Thread(target=send_request) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    success_count = sum(1 for s in results if s == 200)
    if success_count >= 2:
        findings.append(Finding(
            title=f"Race Condition: '{code}' redeemed {success_count}x concurrently",
            severity="high",
            cwe="CWE-362",
            endpoint=url,
            method="POST",
            description=f"Concurrent requests allowed coupon '{code}' to be redeemed {success_count} times.",
            steps=[
                f"Send 5 concurrent POST to {url} with {body_key}={code}",
                f"Success count: {success_count}/5",
            ],
            impact="TOCTOU race condition allows multiple redemptions of single-use coupons",
            evidence={"code": code, "threads": 5, "successes": success_count, "statuses": results},
            remediation="Use database-level locking or atomic operations for coupon redemption.",
        ))

    return findings


def test_mass_assignment(
    session: RateLimitedSession,
    endpoint: dict,
    code: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Test mass assignment on coupon apply endpoint."""
    findings: list[Finding] = []
    url = endpoint["url"]
    body_key = endpoint["body_key"]

    for payload in MASS_ASSIGNMENT_PAYLOADS:
        body = {body_key: code, **payload}
        if dry_run:
            log.info("[DRY-RUN] Mass assignment test: %s", body)
            continue

        try:
            resp = session.post(url, json=body, timeout=10)
            if resp.status_code == 200:
                # Check if extra fields were accepted
                resp_body = resp.text[:1000]
                extra_key = list(payload.keys())[0]
                extra_val = str(list(payload.values())[0])
                if extra_val in resp_body or extra_key in resp_body:
                    findings.append(Finding(
                        title=f"Mass Assignment: {extra_key} accepted on coupon endpoint",
                        severity="critical",
                        cwe="CWE-915",
                        endpoint=url,
                        method="POST",
                        description=f"Extra field '{extra_key}' was accepted in coupon request.",
                        steps=[
                            f"POST {url} with extra field {extra_key}={extra_val}",
                            f"Server returned 200 and reflected the value",
                        ],
                        impact="Price/discount manipulation via mass assignment",
                        evidence={"payload": payload, "status": resp.status_code},
                        remediation="Whitelist accepted fields. Reject unknown parameters.",
                    ))
        except Exception:
            pass

    return findings


def test_case_sensitivity(
    session: RateLimitedSession,
    endpoint: dict,
    code: str,
    dry_run: bool = False,
) -> list[Finding]:
    """Test case sensitivity bypass."""
    findings: list[Finding] = []
    url = endpoint["url"]
    body_key = endpoint["body_key"]

    variants = [
        code.upper(), code.lower(),
        code.capitalize(), code.swapcase(),
        f" {code}", f"{code} ", f" {code} ",
    ]

    if dry_run:
        log.info("[DRY-RUN] Case sensitivity test: %s variants", len(variants))
        return findings

    successes: list[str] = []
    for variant in variants:
        if variant == code:
            continue
        try:
            resp = session.post(url, json={body_key: variant}, timeout=10)
            if resp.status_code == 200:
                successes.append(variant)
        except Exception:
            pass

    if successes:
        findings.append(Finding(
            title=f"Case/Whitespace Bypass: {len(successes)} variants accepted",
            severity="medium",
            cwe="CWE-178",
            endpoint=url,
            method="POST",
            description=f"Coupon code accepts case/whitespace variants: {successes[:3]}",
            steps=[
                f"Original code: '{code}'",
                f"Variants accepted: {successes}",
            ],
            impact="Coupon code can be reused with case/whitespace variations",
            evidence={"original": code, "variants_accepted": successes},
            remediation="Normalize (trim + lowercase) coupon codes before validation.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--codes", nargs="*", default=None,
                        help="Specific coupon codes to test (default: common codes)")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    config = load_config(args.config)
    codes = args.codes or config.get("coupon_codes", TEST_CODES)

    log.info("=== Coupon & Promo Fuzzer starting on %s ===", args.target)

    # Phase 1: Discover endpoints
    log.info("--- Phase 1: Discovering coupon endpoints ---")
    endpoints = discover_coupon_endpoints(session, args.target, args.dry_run)
    log.info("Found %d active coupon endpoints", len(endpoints))

    all_findings: list[Finding] = []

    for ep in endpoints:
        log.info("--- Testing endpoint: %s ---", ep["url"])

        for code in codes[:5]:  # Test top 5 codes per endpoint
            log.info("  Testing code: %s", code)

            # Phase 2: Code reuse
            all_findings.extend(test_code_reuse(session, ep, code, args.dry_run))

            # Phase 3: Mass assignment
            all_findings.extend(test_mass_assignment(session, ep, code, args.dry_run))

            # Phase 4: Case sensitivity
            all_findings.extend(test_case_sensitivity(session, ep, code, args.dry_run))

        # Phase 5: Code stacking
        all_findings.extend(test_code_stacking(session, ep, codes, args.dry_run))

        # Phase 6: Race condition (only on first code)
        if codes:
            all_findings.extend(test_race_condition(session, ep, codes[0], args.dry_run))

    log.info("=== Coupon & Promo Fuzzer complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "coupon-promo")


if __name__ == "__main__":
    main()
