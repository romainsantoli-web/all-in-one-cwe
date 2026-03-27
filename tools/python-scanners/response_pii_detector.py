#!/usr/bin/env python3
"""Response PII Detector — Deep JSON response PII pattern detection (CWE-200).

Scans API responses for exposed Personally Identifiable Information:
- Email addresses, phone numbers, SSNs
- Credit card numbers, IBANs
- Dates of birth, national IDs
- Addresses, geolocation data
- Session tokens, auth cookies in response bodies

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import re
import sys
import os
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# PII detection patterns
# ---------------------------------------------------------------------------

PII_PATTERNS: list[dict] = [
    {
        "name": "Email Address",
        "pattern": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        "severity": "medium",
        "pii_type": "email",
    },
    {
        "name": "Phone Number (International)",
        "pattern": r'(?:\+\d{1,3}[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
        "severity": "medium",
        "pii_type": "phone",
        "min_length": 10,
    },
    {
        "name": "SSN (US)",
        "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
        "severity": "critical",
        "pii_type": "ssn",
    },
    {
        "name": "Credit Card (Visa/MC/Amex/Discover)",
        "pattern": r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b',
        "severity": "critical",
        "pii_type": "credit_card",
    },
    {
        "name": "IBAN",
        "pattern": r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b',
        "severity": "high",
        "pii_type": "iban",
    },
    {
        "name": "Date of Birth",
        "pattern": r'(?:date.?of.?birth|dob|birth.?date|birthday)\s*[:=]\s*["\'"]?(\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})',
        "severity": "high",
        "pii_type": "dob",
    },
    {
        "name": "JWT Token",
        "pattern": r'\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b',
        "severity": "high",
        "pii_type": "jwt",
    },
    {
        "name": "API Key Pattern",
        "pattern": r'(?:api[_-]?key|apikey|token|secret|password)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
        "severity": "critical",
        "pii_type": "api_key",
    },
    {
        "name": "IPv4 Address",
        "pattern": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        "severity": "low",
        "pii_type": "ip_address",
    },
    {
        "name": "French SIRET/SIREN",
        "pattern": r'\b\d{9}(?:\d{5})?\b',
        "severity": "medium",
        "pii_type": "siret",
        "context_required": True,
    },
    {
        "name": "French NIR (Social Security)",
        "pattern": r'\b[12]\d{2}(?:0[1-9]|1[0-2])(?:2[AB]|[0-9]{2})\d{3}\d{3}(?:\d{2})?\b',
        "severity": "critical",
        "pii_type": "nir",
    },
]

# Field names that indicate PII (for JSON key analysis)
SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_token", "refresh_token", "session_id", "sessionid", "csrf",
    "ssn", "social_security", "credit_card", "card_number", "cc_number",
    "cvv", "cvc", "pin", "date_of_birth", "dob", "birthday",
    "phone", "mobile", "telephone", "fax",
    "address", "street", "zip", "postal", "city",
    "first_name", "last_name", "full_name", "surname",
    "email", "mail",
    "salary", "income", "bank_account", "iban", "routing_number",
    "passport", "driver_license", "national_id",
    "geolocation", "latitude", "longitude", "lat", "lng", "geo",
}

# API paths to scan for PII
DEFAULT_API_PATHS = [
    "/api/users", "/api/v1/users", "/api/user",
    "/api/me", "/api/v1/me", "/api/profile",
    "/api/account", "/api/v1/account",
    "/api/customers", "/api/v1/customers",
    "/api/orders", "/api/v1/orders",
    "/api/members", "/api/contacts",
]


def detect_pii_in_text(text: str) -> list[dict]:
    """Detect PII patterns in a text string."""
    detections: list[dict] = []

    for pat in PII_PATTERNS:
        matches = list(re.finditer(pat["pattern"], text, re.IGNORECASE))
        for match in matches:
            value = match.group(0)
            # Skip very short matches for patterns like phone
            if pat.get("min_length") and len(value) < pat["min_length"]:
                continue
            # Mask the value
            masked = value[:3] + "***" + value[-2:] if len(value) > 5 else "***"
            detections.append({
                "type": pat["name"],
                "pii_type": pat["pii_type"],
                "severity": pat["severity"],
                "masked_value": masked,
                "position": match.start(),
            })

    return detections


def detect_sensitive_fields(data: dict | list, path: str = "") -> list[dict]:
    """Recursively check JSON structure for sensitive field names."""
    findings: list[dict] = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            key_lower = key.lower().replace("-", "_")

            if key_lower in SENSITIVE_FIELD_NAMES:
                if value is not None and value != "" and value != "***":
                    findings.append({
                        "field": current_path,
                        "key": key,
                        "value_type": type(value).__name__,
                        "value_preview": str(value)[:20] + "..." if len(str(value)) > 20 else str(value),
                    })

            if isinstance(value, (dict, list)):
                findings.extend(detect_sensitive_fields(value, current_path))

    elif isinstance(data, list):
        for i, item in enumerate(data[:10]):  # Check first 10 items
            if isinstance(item, (dict, list)):
                findings.extend(detect_sensitive_fields(item, f"{path}[{i}]"))

    return findings


def scan(
    session: RateLimitedSession,
    target: str,
    api_paths: list[str] | None = None,
    dry_run: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    paths = api_paths or DEFAULT_API_PATHS

    for path in paths:
        url = f"{target.rstrip('/')}{path}"
        if dry_run:
            log.info("[DRY-RUN] GET %s", url)
            continue

        try:
            resp = session.get(url, timeout=15)
            if resp.status_code != 200:
                continue

            ct = resp.headers.get("content-type", "")
            body = resp.text

            # Phase 1: Regex pattern detection on raw response
            pii_detections = detect_pii_in_text(body)
            if pii_detections:
                grouped: dict[str, list] = {}
                for d in pii_detections:
                    grouped.setdefault(d["pii_type"], []).append(d)

                findings.append(Finding(
                    title=f"PII Exposed: {len(pii_detections)} items in {path}",
                    severity=max((d["severity"] for d in pii_detections),
                                 key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)),
                    cwe="CWE-200",
                    endpoint=url,
                    method="GET",
                    description=f"Detected {len(pii_detections)} PII patterns in response: {', '.join(grouped.keys())}",
                    steps=[
                        f"GET {url}",
                        f"Scan response body ({len(body)} bytes)",
                        f"Detections: {json.dumps({k: len(v) for k, v in grouped.items()})}",
                    ],
                    impact="Personal data exposure in API responses",
                    evidence={
                        "types": {k: len(v) for k, v in grouped.items()},
                        "samples": [d["masked_value"] for d in pii_detections[:5]],
                        "total": len(pii_detections),
                    },
                    remediation="Filter sensitive fields from API responses. Use field-level access control.",
                ))

            # Phase 2: JSON structure analysis for sensitive fields
            if "json" in ct:
                try:
                    data = resp.json()
                    sensitive_fields = detect_sensitive_fields(data)
                    if sensitive_fields:
                        findings.append(Finding(
                            title=f"Sensitive Fields: {len(sensitive_fields)} exposed in {path}",
                            severity="high",
                            cwe="CWE-200",
                            endpoint=url,
                            method="GET",
                            description=f"Response contains {len(sensitive_fields)} sensitive field names",
                            steps=[
                                f"GET {url}",
                                f"Parse JSON response",
                                f"Fields: {', '.join(f['field'] for f in sensitive_fields[:10])}",
                            ],
                            impact="Sensitive user data exposed via API response fields",
                            evidence={
                                "fields": [f["field"] for f in sensitive_fields],
                                "count": len(sensitive_fields),
                            },
                            remediation=(
                                "Implement field-level serialization. "
                                "Use DTOs to prevent internal model leakage."
                            ),
                        ))
                except json.JSONDecodeError:
                    pass

            # Phase 3: Check response headers for sensitive info
            sensitive_headers = {}
            for header, value in resp.headers.items():
                h_lower = header.lower()
                if any(s in h_lower for s in ("server", "x-powered-by", "x-aspnet", "x-debug", "x-request-id")):
                    sensitive_headers[header] = value

            if sensitive_headers:
                findings.append(Finding(
                    title=f"Information Disclosure Headers: {path}",
                    severity="low",
                    cwe="CWE-200",
                    endpoint=url,
                    method="GET",
                    description=f"Response headers reveal server information: {', '.join(sensitive_headers.keys())}",
                    steps=[f"GET {url}", f"Headers: {json.dumps(sensitive_headers)}"],
                    impact="Server technology fingerprinting",
                    evidence=sensitive_headers,
                    remediation="Remove server version headers. Disable X-Powered-By.",
                ))

        except Exception as e:
            log.debug("Error scanning %s: %s", url, e)

    return findings


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--api-paths", nargs="*", default=None,
                        help="Custom API paths to scan (default: common user/account paths)")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    log.info("=== Response PII Detector starting on %s ===", args.target)
    all_findings = scan(session, args.target, args.api_paths, args.dry_run)
    log.info("=== Response PII Detector complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "response-pii")


if __name__ == "__main__":
    main()
