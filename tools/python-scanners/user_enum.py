#!/usr/bin/env python3
"""User Enumeration Scanner — Timing & response-based account discovery (CWE-203/204).

Tests timing differences on login, response differences on password reset,
registration flow "email taken" leakage, and account ID leaks via search.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

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
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_NONEXISTENT_EMAILS = [
    f"bb_test_nonexist_{i}@fakemailywh.test" for i in range(5)
]

DEFAULT_LOGIN_ENDPOINTS = ["/login", "/login.json", "/api/login", "/api/auth/login",
                           "/api/sessions", "/auth/sign_in"]

DEFAULT_RESET_ENDPOINTS = ["/account/reset_password", "/api/password/reset",
                           "/auth/forgot-password", "/api/users/forgot-password"]

DEFAULT_REGISTER_ENDPOINTS = ["/api/users", "/api/register", "/auth/sign_up",
                              "/api/patients", "/api/accounts"]

DEFAULT_SEARCH_ENDPOINTS = ["/api/users/search", "/api/search", "/search.json",
                            "/api/searchbar"]


def test_login_timing(
    sess: RateLimitedSession, base: str, login_endpoints: list[str],
    test_email: str, fake_emails: list[str], dry_run: bool,
) -> list[Finding]:
    """Measure timing differences on login endpoint."""
    findings: list[Finding] = []

    for path in login_endpoints:
        url = f"{base}{path}"
        if dry_run:
            log.info("[dry-run] Would POST %s with timing test", url)
            continue

        existing_times: list[float] = []
        nonexist_times: list[float] = []

        # Existing-pattern email
        t0 = time.monotonic()
        try:
            r = sess.post(url, json={"username": test_email, "password": "wrongpass123"})
            elapsed = time.monotonic() - t0
            if r.status_code not in (404,):
                existing_times.append(elapsed)
                log.info("  %s existing: %d in %.3fs", path, r.status_code, elapsed)
        except Exception:
            continue

        # Non-existing emails
        for email in fake_emails[:3]:
            t0 = time.monotonic()
            try:
                r = sess.post(url, json={"username": email, "password": "wrongpass123"})
                elapsed = time.monotonic() - t0
                nonexist_times.append(elapsed)
            except Exception:
                pass

        if existing_times and nonexist_times:
            avg_exist = statistics.mean(existing_times)
            avg_nonexist = statistics.mean(nonexist_times)
            diff = abs(avg_exist - avg_nonexist)
            log.info("  Timing diff: %.3fs (exist=%.3f, nonexist=%.3f)", diff, avg_exist, avg_nonexist)
            if diff > 0.1:
                findings.append(Finding(
                    title=f"User Enumeration via Login Timing — {path}",
                    severity="medium",
                    cwe="CWE-204",
                    endpoint=url,
                    method="POST",
                    description=f"{diff:.3f}s timing difference between existing/non-existing accounts.",
                    steps=[
                        f"POST {url} with existing → avg {avg_exist:.3f}s",
                        f"POST {url} with non-existing → avg {avg_nonexist:.3f}s",
                    ],
                    impact="Attacker can enumerate valid accounts at scale.",
                    evidence={"avg_existing_s": avg_exist, "avg_nonexist_s": avg_nonexist, "diff_s": diff},
                ))

    return findings


def test_password_reset_enum(
    sess: RateLimitedSession, base: str, reset_endpoints: list[str],
    test_email: str, fake_emails: list[str], dry_run: bool,
) -> list[Finding]:
    """Check password reset for response differences."""
    findings: list[Finding] = []

    for path in reset_endpoints:
        url = f"{base}{path}"
        if dry_run:
            log.info("[dry-run] Would POST %s", url)
            continue

        responses: dict[str, dict] = {}
        for email in [test_email] + fake_emails[:2]:
            try:
                r = sess.post(url, json={"email": email})
                responses[email] = {"status": r.status_code, "length": len(r.content)}
                log.info("  %s: %d (%d bytes)", email, r.status_code, len(r.content))
            except Exception:
                pass

        if len(responses) >= 2:
            statuses = {v["status"] for v in responses.values()}
            lengths = {v["length"] for v in responses.values()}
            if len(statuses) > 1 or len(lengths) > 1:
                findings.append(Finding(
                    title=f"User Enumeration via Password Reset — {path}",
                    severity="medium",
                    cwe="CWE-204",
                    endpoint=url,
                    method="POST",
                    description="Password reset returns different responses for existing vs non-existing accounts.",
                    impact="Attacker can enumerate valid accounts.",
                    evidence=responses,
                ))

    return findings


def test_registration_enum(
    sess: RateLimitedSession, base: str, register_endpoints: list[str],
    fake_emails: list[str], dry_run: bool,
) -> list[Finding]:
    """Check registration for 'email already taken' leakage."""
    findings: list[Finding] = []

    for path in register_endpoints:
        url = f"{base}{path}"
        if dry_run:
            log.info("[dry-run] Would POST %s", url)
            continue

        for email in fake_emails[:2]:
            try:
                r = sess.post(url, json={"email": email, "first_name": "Test", "last_name": "User"})
                log.info("  %s: %d", email, r.status_code)
                snippet = r.text[:300].lower()
                if any(kw in snippet for kw in ["already", "existe", "existiert", "taken", "in use"]):
                    findings.append(Finding(
                        title=f"User Enumeration via Registration — {path}",
                        severity="medium",
                        cwe="CWE-204",
                        endpoint=url,
                        method="POST",
                        description="Registration reveals if an email is already registered.",
                        impact="Attacker can enumerate valid accounts.",
                        evidence={"response_snippet": snippet[:200]},
                    ))
                    break
            except Exception:
                pass

    return findings


def test_account_id_leak(
    sess: RateLimitedSession, base: str, search_endpoints: list[str],
    test_email: str, dry_run: bool,
) -> list[Finding]:
    """Check if account_id is leaked via search."""
    findings: list[Finding] = []

    for path in search_endpoints:
        url = f"{base}{path}"
        if dry_run:
            log.info("[dry-run] Would GET %s?q=<email>", url)
            continue
        try:
            r = sess.get(url, params={"q": test_email})
            log.info("  %s: %d (%d bytes)", path, r.status_code, len(r.content))
            if r.status_code == 200:
                text = r.text
                if "account_id" in text or '"id"' in text:
                    findings.append(Finding(
                        title=f"Account ID Leak via Search — {path}",
                        severity="medium",
                        cwe="CWE-200",
                        endpoint=url,
                        method="GET",
                        description="Search endpoint leaks account IDs.",
                        impact="Attacker can discover account IDs for any email.",
                        evidence={"response_snippet": text[:500]},
                    ))
        except Exception:
            pass

    return findings


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--test-email", default=os.environ.get("TEST_EMAIL", "test@example.com"),
                        help="Known-existing email pattern for timing comparison")
    args = parser.parse_args()
    if args.verbose:
        log.setLevel("DEBUG")

    sess = get_session_from_env()
    if args.rate_limit != 10.0:
        sess = RateLimitedSession(rate_limit=args.rate_limit)

    base = args.target.rstrip("/")
    config = load_config(args.config)
    findings: list[Finding] = []

    fake_emails = config.get("fake_emails", DEFAULT_NONEXISTENT_EMAILS)
    login_eps = config.get("login_endpoints", DEFAULT_LOGIN_ENDPOINTS)
    reset_eps = config.get("reset_endpoints", DEFAULT_RESET_ENDPOINTS)
    register_eps = config.get("register_endpoints", DEFAULT_REGISTER_ENDPOINTS)
    search_eps = config.get("search_endpoints", DEFAULT_SEARCH_ENDPOINTS)

    log.info("=" * 60)
    log.info("User Enumeration Scanner (CWE-203/204)")
    log.info("Target: %s | Dry-run: %s", base, args.dry_run)
    log.info("=" * 60)

    log.info("[1/4] Login timing...")
    findings.extend(test_login_timing(sess, base, login_eps, args.test_email, fake_emails, args.dry_run))
    log.info("[2/4] Password reset enum...")
    findings.extend(test_password_reset_enum(sess, base, reset_eps, args.test_email, fake_emails, args.dry_run))
    log.info("[3/4] Registration enum...")
    findings.extend(test_registration_enum(sess, base, register_eps, fake_emails, args.dry_run))
    log.info("[4/4] Account ID leak...")
    findings.extend(test_account_id_leak(sess, base, search_eps, args.test_email, args.dry_run))

    log.info("=" * 60)
    log.info("Results: %d findings", len(findings))
    save_findings(findings, "user-enum")


if __name__ == "__main__":
    main()
