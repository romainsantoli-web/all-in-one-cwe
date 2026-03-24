#!/usr/bin/env python3
"""IDOR Scanner — Insecure Direct Object Reference detection (CWE-639).

Tests sequential ID enumeration, cross-user resource access, and horizontal
privilege escalation (±offset on own resource IDs).

Configurable via YAML:
  idor_targets:
    - name: "Patient Profile"
      paths: ["/api/patients/{id}", "/api/patients/{id}.json"]
      severity: critical
      pii_keywords: [email, phone, name, birth]

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
# Default IDOR targets (generic REST patterns)
# ---------------------------------------------------------------------------

DEFAULT_IDOR_TARGETS = [
    {
        "name": "User Profile",
        "paths": ["/api/users/{id}", "/api/users/{id}.json", "/api/profiles/{id}"],
        "severity": "high",
        "cwe": "CWE-639",
        "pii_keywords": ["email", "phone", "first_name", "last_name", "name",
                         "birth", "address", "ssn"],
    },
    {
        "name": "Appointments / Bookings",
        "paths": ["/api/appointments/{id}", "/api/bookings/{id}",
                  "/api/appointments/{id}.json"],
        "severity": "critical",
        "cwe": "CWE-639",
        "pii_keywords": ["patient", "appointment", "diagnosis", "doctor",
                         "date", "reason"],
    },
    {
        "name": "Documents / Files",
        "paths": ["/api/documents/{id}", "/api/documents/{id}/download",
                  "/api/files/{id}", "/api/attachments/{id}"],
        "severity": "critical",
        "cwe": "CWE-639",
        "pii_keywords": ["content", "file", "document", "prescription",
                         "report", "diagnosis"],
    },
    {
        "name": "Messages / Conversations",
        "paths": ["/api/messages/{id}", "/api/conversations/{id}",
                  "/api/threads/{id}"],
        "severity": "critical",
        "cwe": "CWE-639",
        "pii_keywords": ["content", "body", "message", "sender", "recipient"],
    },
    {
        "name": "Organization Patient List",
        "paths": ["/api/organizations/{id}/users",
                  "/api/organizations/{id}/patients",
                  "/api/organizations/{id}/members",
                  "/api/practices/{id}/patients"],
        "severity": "critical",
        "cwe": "CWE-639",
        "pii_keywords": ["patient", "user", "member", "email", "name"],
    },
    {
        "name": "Orders / Transactions",
        "paths": ["/api/orders/{id}", "/api/invoices/{id}",
                  "/api/transactions/{id}", "/api/payments/{id}"],
        "severity": "high",
        "cwe": "CWE-639",
        "pii_keywords": ["amount", "card", "email", "address", "total"],
    },
    {
        "name": "Invitations / Sharing Links",
        "paths": ["/api/invitations/{id}", "/api/sharing_links/{id}",
                  "/api/shares/{id}"],
        "severity": "medium",
        "cwe": "CWE-639",
        "pii_keywords": ["email", "link", "token"],
    },
]

DEFAULT_TEST_IDS = ["1", "2", "100", "1000", "99999"]

# Resource discovery endpoints (to find own IDs for ±offset testing)
DEFAULT_RESOURCE_ENDPOINTS = [
    ("users", "/api/users"),
    ("users", "/api/users/me"),
    ("appointments", "/api/appointments"),
    ("documents", "/api/documents"),
    ("orders", "/api/orders"),
    ("messages", "/api/messages"),
]


def discover_own_resources(
    sess: RateLimitedSession, base: str
) -> dict[str, list[str]]:
    """Fetch authenticated user's resource IDs for horizontal IDOR testing."""
    own_ids: dict[str, list[str]] = {}

    for name, path in DEFAULT_RESOURCE_ENDPOINTS:
        url = f"{base}{path}"
        try:
            r = sess.get(url)
            if r.status_code == 200:
                data = r.json()
                ids = []
                if isinstance(data, dict) and "id" in data:
                    ids.append(str(data["id"]))
                items = data if isinstance(data, list) else []
                if isinstance(data, dict):
                    for key in ("data", "items", name, "results"):
                        candidate = data.get(key, [])
                        if isinstance(candidate, list):
                            items = candidate
                            break
                for item in items[:5]:
                    if isinstance(item, dict) and "id" in item:
                        ids.append(str(item["id"]))
                if ids:
                    own_ids[name] = ids
                    log.info("  Own %s IDs: %s", name, ids[:3])
        except Exception as e:
            log.debug("  %s: %s", name, e)

    return own_ids


def test_idor_endpoint(
    sess: RateLimitedSession,
    base: str,
    target: dict,
    test_ids: list[str],
    dry_run: bool,
) -> list[Finding]:
    """Test a single IDOR target with multiple probe IDs."""
    findings: list[Finding] = []
    pii_keywords = target.get("pii_keywords", ["email", "name", "phone"])

    for path_template in target["paths"]:
        for test_id in test_ids:
            path = path_template.replace("{id}", test_id)
            url = f"{base}{path}"

            if dry_run:
                log.info("[dry-run] Would GET %s", url)
                continue

            try:
                r = sess.get(url)
                log.info("  GET %s → %d (%d bytes)", path, r.status_code, len(r.content))

                if r.status_code == 200 and len(r.content) > 50:
                    try:
                        data = r.json()
                        data_str = str(data).lower()
                        has_pii = any(k in data_str for k in pii_keywords)
                        if has_pii:
                            matched_fields = [k for k in pii_keywords if k in data_str]
                            findings.append(Finding(
                                title=f"IDOR — {target['name']} (ID={test_id})",
                                severity=target["severity"],
                                cwe=target["cwe"],
                                endpoint=url,
                                method="GET",
                                description=(
                                    f"Accessed {target['name']} with ID {test_id}. "
                                    f"Response contains PII fields: {matched_fields}"
                                ),
                                steps=[
                                    "Authenticate as user A (test account)",
                                    f"GET {url}",
                                    f"Response: {r.status_code} with {len(r.content)} bytes",
                                    f"PII fields found: {matched_fields}",
                                ],
                                impact=f"Cross-user data access on {target['name']}.",
                                evidence={
                                    "status": r.status_code,
                                    "response_length": len(r.content),
                                    "pii_fields": matched_fields,
                                    "response_snippet": str(data)[:500],
                                },
                            ))
                            log.warning("⚠ IDOR FOUND: %s ID=%s → %s",
                                        target["name"], test_id, target["severity"])
                    except Exception:
                        pass
            except Exception as e:
                log.debug("  %s: %s", url, e)

    return findings


def test_horizontal_idor(
    sess: RateLimitedSession,
    base: str,
    own_ids: dict[str, list[str]],
    dry_run: bool,
) -> list[Finding]:
    """Test ±offset on own resource IDs (horizontal privilege escalation)."""
    findings: list[Finding] = []

    id_to_endpoint = {
        "users": "/api/users/{id}",
        "appointments": "/api/appointments/{id}",
        "documents": "/api/documents/{id}",
        "orders": "/api/orders/{id}",
        "messages": "/api/messages/{id}",
    }

    for resource, ids in own_ids.items():
        endpoint_tpl = id_to_endpoint.get(resource)
        if not endpoint_tpl:
            continue

        for own_id in ids[:2]:
            try:
                numeric_id = int(own_id)
            except ValueError:
                continue

            for offset in [-1, 1, -10, 10, -100, 100]:
                target_id = numeric_id + offset
                if target_id < 1:
                    continue

                path = endpoint_tpl.replace("{id}", str(target_id))
                url = f"{base}{path}"

                if dry_run:
                    log.info("[dry-run] Would GET %s (own=%s, offset=%+d)", url, own_id, offset)
                    continue

                try:
                    r = sess.get(url)
                    if r.status_code == 200 and len(r.content) > 50:
                        log.warning("⚠ Horizontal IDOR: %s (own=%s, target=%d) → 200 OK",
                                    resource, own_id, target_id)
                        findings.append(Finding(
                            title=f"Horizontal IDOR — {resource} (own={own_id}, target={target_id})",
                            severity="critical",
                            cwe="CWE-639",
                            endpoint=url,
                            method="GET",
                            description=(
                                f"Accessed {resource} ID {target_id} belonging to another user. "
                                f"Own ID: {own_id} (offset: {offset:+d})."
                            ),
                            steps=[
                                f"Authenticate as user A with {resource} ID {own_id}",
                                f"GET {url} (ID {own_id}{offset:+d})",
                                f"Response: {r.status_code} with {len(r.content)} bytes",
                            ],
                            impact="Cross-user data access via sequential ID enumeration.",
                            evidence={
                                "own_id": own_id,
                                "target_id": target_id,
                                "offset": offset,
                                "status": r.status_code,
                                "response_length": len(r.content),
                            },
                        ))
                except Exception as e:
                    log.debug("  %s: %s", url, e)

    return findings


def main() -> None:
    parser = parse_base_args()
    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    sess = get_session_from_env()
    if args.rate_limit != 10.0:
        sess = RateLimitedSession(rate_limit=args.rate_limit)

    base = args.target.rstrip("/")
    config = load_config(args.config)
    findings: list[Finding] = []

    # Use config targets if provided, else defaults
    idor_targets = config.get("idor_targets", DEFAULT_IDOR_TARGETS)
    test_ids = config.get("test_ids", DEFAULT_TEST_IDS)

    log.info("=" * 60)
    log.info("IDOR Scanner (CWE-639)")
    log.info("Target: %s | Dry-run: %s | Endpoints: %d",
             base, args.dry_run, len(idor_targets))
    log.info("=" * 60)

    # Phase 1: Discover own resource IDs
    own_ids: dict[str, list[str]] = {}
    if not args.dry_run:
        log.info("[phase 1] Discovering own resource IDs...")
        own_ids = discover_own_resources(sess, base)
    else:
        log.info("[dry-run] Skipping resource discovery")

    # Phase 2: Test IDOR patterns
    log.info("[phase 2] Testing IDOR endpoints...")
    for target in idor_targets:
        log.info("  Testing: %s (%d paths)", target["name"], len(target["paths"]))
        results = test_idor_endpoint(sess, base, target, test_ids[:3], args.dry_run)
        findings.extend(results)

    # Phase 3: Horizontal IDOR
    if own_ids:
        log.info("[phase 3] Testing horizontal IDOR on own IDs...")
        results = test_horizontal_idor(sess, base, own_ids, args.dry_run)
        findings.extend(results)

    log.info("=" * 60)
    log.info("Results: %d findings", len(findings))
    save_findings(findings, "idor-scanner")


if __name__ == "__main__":
    main()
