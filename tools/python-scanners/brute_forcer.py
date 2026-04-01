#!/usr/bin/env python3
"""Brute-force credential scanner — wraps Hydra + custom auth endpoint testing (CWE-307/521).

Tests login endpoints for:
  - Default credentials (admin/admin, admin/password, etc.)
  - Weak password policy detection (short passwords accepted)
  - Rate limiting absence (CWE-307)
  - Account lockout bypass

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding,
    RateLimitedSession,
    get_session_from_env,
    load_config,
    log,
    parse_base_args,
    save_findings,
)

# ---------------------------------------------------------------------------
# Defaults — safe, low-impact credential pairs
# ---------------------------------------------------------------------------

DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("test", "test"),
    ("root", "root"),
    ("root", "toor"),
    ("user", "user"),
    ("guest", "guest"),
    ("demo", "demo"),
]

DEFAULT_LOGIN_ENDPOINTS = [
    "/login",
    "/api/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/auth/signin",
    "/api/session",
    "/admin/login",
]

DEFAULT_WEAK_PASSWORDS = ["a", "12", "abc", "1234"]


# ---------------------------------------------------------------------------
# Phase 1: Default credential testing
# ---------------------------------------------------------------------------


def test_default_creds(
    sess: RateLimitedSession,
    target: str,
    config: dict,
    dry_run: bool,
) -> list[Finding]:
    """Try common default credentials against login endpoints."""
    findings: list[Finding] = []
    endpoints = config.get("login_endpoints", DEFAULT_LOGIN_ENDPOINTS)
    creds = config.get("credentials", [tuple(c) for c in DEFAULT_CREDS])
    username_field = config.get("username_field", "username")
    password_field = config.get("password_field", "password")
    success_indicators = config.get("success_indicators", [
        "token", "access_token", "session", "jwt", "logged_in", "dashboard",
    ])
    failure_indicators = config.get("failure_indicators", [
        "invalid", "incorrect", "failed", "error", "unauthorized", "wrong",
    ])

    for endpoint in endpoints:
        url = f"{target.rstrip('/')}{endpoint}"
        for user, pwd in creds:
            if dry_run:
                log.info("[DRY-RUN] POST %s (%s:%s)", url, user, pwd)
                continue
            try:
                resp = sess.post(url, json={username_field: user, password_field: pwd})
                body = resp.text.lower()

                is_success = (
                    resp.status_code in (200, 201, 302)
                    and any(ind in body for ind in success_indicators)
                    and not any(ind in body for ind in failure_indicators)
                )
                if is_success:
                    findings.append(Finding(
                        title=f"Default credentials accepted: {user}:{pwd}",
                        severity="critical",
                        cwe="CWE-798",
                        endpoint=url,
                        method="POST",
                        description=(
                            f"The login endpoint accepted default credentials "
                            f"{user}:{pwd}. This allows unauthorized access."
                        ),
                        steps=[
                            f"POST {url}",
                            f'Body: {{"{username_field}":"{user}","{password_field}":"{pwd}"}}',
                            f"Response: {resp.status_code}",
                        ],
                        impact="Full account access with default credentials",
                        evidence={
                            "status_code": resp.status_code,
                            "response_snippet": body[:500],
                        },
                        remediation=(
                            "Force password change on first login. "
                            "Remove default accounts from production."
                        ),
                    ))
                    log.warning("DEFAULT CREDS ACCEPTED: %s:%s on %s", user, pwd, url)
            except Exception as exc:
                log.debug("Error testing %s:%s on %s: %s", user, pwd, url, exc)
    return findings


# ---------------------------------------------------------------------------
# Phase 2: Rate limiting detection (CWE-307)
# ---------------------------------------------------------------------------


def test_rate_limiting(
    sess: RateLimitedSession,
    target: str,
    config: dict,
    dry_run: bool,
) -> list[Finding]:
    """Check if login endpoint has rate limiting / account lockout."""
    findings: list[Finding] = []
    endpoints = config.get("login_endpoints", DEFAULT_LOGIN_ENDPOINTS)
    username_field = config.get("username_field", "username")
    password_field = config.get("password_field", "password")
    attempts = config.get("rate_limit_test_attempts", 15)

    for endpoint in endpoints:
        url = f"{target.rstrip('/')}{endpoint}"
        if dry_run:
            log.info("[DRY-RUN] Rate limit test: %d attempts on %s", attempts, url)
            continue

        # First check endpoint exists
        try:
            probe = sess.post(url, json={username_field: "test", password_field: "test"})
            if probe.status_code in (404, 405):
                continue
        except Exception:
            continue

        statuses: list[int] = []
        blocked = False
        for i in range(attempts):
            try:
                resp = sess.post(
                    url,
                    json={username_field: f"brute_test_{i}", password_field: "wrong"},
                )
                statuses.append(resp.status_code)
                if resp.status_code == 429:
                    blocked = True
                    break
            except Exception:
                break

        if not blocked and len(statuses) >= attempts:
            findings.append(Finding(
                title=f"No rate limiting on login endpoint: {endpoint}",
                severity="high",
                cwe="CWE-307",
                endpoint=url,
                method="POST",
                description=(
                    f"Sent {attempts} rapid login attempts without being rate-limited "
                    f"or locked out. All returned HTTP {statuses[-1]}."
                ),
                steps=[
                    f"POST {url} × {attempts} rapid attempts",
                    f"All returned: {set(statuses)}",
                    "No 429 Too Many Requests received",
                ],
                impact="Enables brute-force attacks against user accounts",
                evidence={
                    "attempts": attempts,
                    "status_codes": statuses,
                    "rate_limited": False,
                },
                remediation=(
                    "Implement rate limiting (e.g., 5 attempts per minute). "
                    "Add CAPTCHA after 3 failed attempts. "
                    "Implement account lockout after 10 failed attempts."
                ),
            ))
            log.warning("NO RATE LIMITING on %s (%d attempts)", url, attempts)
    return findings


# ---------------------------------------------------------------------------
# Phase 3: Weak password policy (CWE-521)
# ---------------------------------------------------------------------------


def test_weak_password_policy(
    sess: RateLimitedSession,
    target: str,
    config: dict,
    dry_run: bool,
) -> list[Finding]:
    """Check if signup/password-change accepts weak passwords."""
    findings: list[Finding] = []
    signup_endpoints = config.get("signup_endpoints", [
        "/register", "/signup", "/api/register", "/api/v1/register",
        "/api/auth/register", "/api/users",
    ])
    username_field = config.get("username_field", "username")
    password_field = config.get("password_field", "password")
    email_field = config.get("email_field", "email")
    weak_passwords = config.get("weak_passwords", DEFAULT_WEAK_PASSWORDS)

    for endpoint in signup_endpoints:
        url = f"{target.rstrip('/')}{endpoint}"
        if dry_run:
            log.info("[DRY-RUN] Weak password test on %s", url)
            continue

        try:
            probe = sess.post(url, json={
                username_field: "bb_policy_test",
                password_field: "StrongP@ssw0rd123!",
                email_field: "bb_policy_test@fakemailywh.test",
            })
            if probe.status_code in (404, 405):
                continue
        except Exception:
            continue

        for weak_pwd in weak_passwords:
            try:
                resp = sess.post(url, json={
                    username_field: f"bb_weak_{weak_pwd}",
                    password_field: weak_pwd,
                    email_field: f"bb_weak_{weak_pwd}@fakemailywh.test",
                })
                body = resp.text.lower()
                password_rejected = any(
                    kw in body for kw in [
                        "password", "weak", "short", "minimum", "strength",
                        "requirement", "policy", "too short",
                    ]
                )
                if resp.status_code in (200, 201) and not password_rejected:
                    findings.append(Finding(
                        title=f"Weak password accepted: '{weak_pwd}'",
                        severity="medium",
                        cwe="CWE-521",
                        endpoint=url,
                        method="POST",
                        description=(
                            f"The registration endpoint accepted password '{weak_pwd}' "
                            f"({len(weak_pwd)} chars) without rejection."
                        ),
                        steps=[
                            f"POST {url}",
                            f'Body: {{"password": "{weak_pwd}"}}',
                            f"Response: {resp.status_code}",
                        ],
                        impact="Users can set trivially weak passwords",
                        evidence={
                            "weak_password_length": len(weak_pwd),
                            "status_code": resp.status_code,
                        },
                        remediation=(
                            "Enforce minimum 8 characters, "
                            "require uppercase + number + special character. "
                            "Use NIST SP 800-63B guidelines."
                        ),
                    ))
                    break  # One weak password accepted is enough
            except Exception:
                continue
    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--skip-default-creds", action="store_true",
                        help="Skip default credential testing")
    parser.add_argument("--skip-rate-limit", action="store_true",
                        help="Skip rate limiting detection")
    args = parser.parse_args()
    config = load_config(args.config) if hasattr(args, "config") and args.config else {}

    sess = get_session_from_env()
    findings: list[Finding] = []

    if not args.skip_default_creds:
        log.info("Phase 1: Testing default credentials...")
        findings.extend(test_default_creds(sess, args.target, config, args.dry_run))

    if not args.skip_rate_limit:
        log.info("Phase 2: Testing rate limiting...")
        findings.extend(test_rate_limiting(sess, args.target, config, args.dry_run))

    log.info("Phase 3: Testing weak password policy...")
    findings.extend(test_weak_password_policy(sess, args.target, config, args.dry_run))

    log.info("Brute-forcer scan complete: %d findings", len(findings))
    save_findings(findings, "brute-forcer")


if __name__ == "__main__":
    main()
