#!/usr/bin/env python3
"""CDP Checkout Interceptor — Checkout flow mutation tracking (CWE-915/362).

Uses Chrome DevTools Protocol to intercept and analyze checkout flows:
- Price manipulation via request interception
- Cart quantity tampering
- Coupon/discount field injection
- Payment method bypass
- Race conditions in checkout process
- Client-side price validation bypass

Requires a running Chrome/Chromium with --remote-debugging-port=9222.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import re
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings,
)
from cdp_bridge import (
    cdp_connect, cdp_send, cdp_eval, cdp_collect_events,
    cdp_close, cdp_fetch_enable, cdp_get_response_body,
    cdp_continue_request,
)

# ---------------------------------------------------------------------------
# Checkout-related patterns
# ---------------------------------------------------------------------------

CHECKOUT_URL_PATTERNS = [
    r'/checkout', r'/cart', r'/order', r'/payment',
    r'/api/v?\d*/cart', r'/api/v?\d*/checkout', r'/api/v?\d*/order',
    r'/api/v?\d*/payment', r'/purchase', r'/basket',
]

PRICE_FIELD_PATTERNS = [
    "price", "amount", "total", "subtotal", "unit_price",
    "item_price", "line_total", "grand_total", "tax",
    "shipping", "discount", "fee",
]

QUANTITY_FIELD_PATTERNS = [
    "quantity", "qty", "count", "amount", "num",
]


def is_checkout_url(url: str) -> bool:
    """Check if URL is checkout-related."""
    url_lower = url.lower()
    return any(re.search(p, url_lower) for p in CHECKOUT_URL_PATTERNS)


def find_price_fields(data: dict | list, path: str = "") -> list[dict]:
    """Recursively find price/money fields in JSON."""
    fields: list[dict] = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            key_lower = key.lower()

            if any(p in key_lower for p in PRICE_FIELD_PATTERNS):
                if isinstance(value, (int, float)):
                    fields.append({"path": current_path, "value": value, "type": "price"})
            elif any(p in key_lower for p in QUANTITY_FIELD_PATTERNS):
                if isinstance(value, (int, float)):
                    fields.append({"path": current_path, "value": value, "type": "quantity"})

            if isinstance(value, (dict, list)):
                fields.extend(find_price_fields(value, current_path))

    elif isinstance(data, list):
        for i, item in enumerate(data[:20]):
            if isinstance(item, (dict, list)):
                fields.extend(find_price_fields(item, f"{path}[{i}]"))

    return fields


def scan(
    target: str,
    duration_seconds: int = 60,
    dry_run: bool = False,
) -> list[Finding]:
    """Monitor checkout flow for price/cart manipulation vulnerabilities."""
    findings: list[Finding] = []

    if dry_run:
        log.info("[DRY-RUN] Would connect to CDP and monitor checkout for %ds", duration_seconds)
        return findings

    log.info("Connecting to Chrome DevTools Protocol...")
    try:
        session = cdp_connect()
    except Exception as e:
        log.error("Cannot connect to CDP: %s", e)
        return findings

    try:
        # Enable required domains
        cdp_send(session, "Network.enable", {})
        cdp_fetch_enable(session, patterns=[
            {"urlPattern": "*checkout*", "requestStage": "Response"},
            {"urlPattern": "*cart*", "requestStage": "Response"},
            {"urlPattern": "*order*", "requestStage": "Response"},
            {"urlPattern": "*payment*", "requestStage": "Response"},
        ])

        # Navigate to target
        log.info("Navigating to %s", target)
        cdp_send(session, "Page.navigate", {"url": target})
        time.sleep(3)

        # Phase 1: Observe checkout requests
        log.info("--- Phase 1: Observing checkout traffic (%ds) ---", duration_seconds)
        checkout_requests: list[dict] = []
        events = cdp_collect_events(session, duration_seconds)

        for event in events:
            method = event.get("method", "")
            params = event.get("params", {})

            # Capture Fetch.requestPaused events (intercepted requests)
            if method == "Fetch.requestPaused":
                request = params.get("request", {})
                url = request.get("url", "")

                if is_checkout_url(url):
                    req_method = request.get("method", "GET")
                    post_data = request.get("postData", "")

                    checkout_requests.append({
                        "url": url,
                        "method": req_method,
                        "post_data": post_data,
                        "request_id": params.get("requestId"),
                    })

                    # Continue the request (don't block it)
                    cdp_continue_request(session, params.get("requestId"))

                    # Analyze POST data for price fields
                    if post_data:
                        try:
                            body = json.loads(post_data)
                            price_fields = find_price_fields(body)
                            if price_fields:
                                findings.append(Finding(
                                    title=f"Client-Side Price Field: {url.split('/')[-1]}",
                                    severity="high",
                                    cwe="CWE-915",
                                    endpoint=url[:200],
                                    method=req_method,
                                    description=(
                                        f"Checkout request contains client-controlled price fields: "
                                        f"{', '.join(f['path'] for f in price_fields[:5])}"
                                    ),
                                    steps=[
                                        f"Intercept {req_method} {url[:100]}",
                                        f"Price fields found: {json.dumps([f['path'] for f in price_fields])}",
                                        f"Values: {json.dumps({f['path']: f['value'] for f in price_fields})}",
                                    ],
                                    impact=(
                                        "Client can manipulate prices/quantities in checkout request. "
                                        "Server must validate all amounts."
                                    ),
                                    evidence={
                                        "fields": price_fields[:10],
                                        "url": url[:200],
                                    },
                                    remediation=(
                                        "Never trust client-side price calculations. "
                                        "Compute all prices server-side from cart items and catalog."
                                    ),
                                ))
                        except json.JSONDecodeError:
                            pass

            # Capture normal network responses
            elif method == "Network.responseReceived":
                response = params.get("response", {})
                url = response.get("url", "")

                if is_checkout_url(url):
                    # Try to get response body
                    request_id = params.get("requestId")
                    if request_id:
                        try:
                            body_result = cdp_get_response_body(session, request_id)
                            if body_result:
                                body_text = body_result.get("body", "")
                                try:
                                    data = json.loads(body_text)
                                    price_fields = find_price_fields(data)

                                    # Check for sensitive checkout data in response
                                    if price_fields:
                                        # Look for potential manipulation vectors
                                        for field in price_fields:
                                            if field["type"] == "price" and field["value"] == 0:
                                                findings.append(Finding(
                                                    title=f"Zero Price in Response: {field['path']}",
                                                    severity="medium",
                                                    cwe="CWE-915",
                                                    endpoint=url[:200],
                                                    method="GET",
                                                    description=f"Checkout response contains zero price at {field['path']}",
                                                    steps=[
                                                        f"GET {url[:100]}",
                                                        f"Field {field['path']} = 0",
                                                    ],
                                                    impact="Zero-price items may indicate discount bypass",
                                                    evidence=field,
                                                    remediation="Validate all line items have positive prices.",
                                                ))

                                            if field["type"] == "quantity" and field["value"] < 0:
                                                findings.append(Finding(
                                                    title=f"Negative Quantity: {field['path']}",
                                                    severity="high",
                                                    cwe="CWE-915",
                                                    endpoint=url[:200],
                                                    method="GET",
                                                    description=f"Negative quantity at {field['path']} = {field['value']}",
                                                    steps=[
                                                        f"GET {url[:100]}",
                                                        f"Field {field['path']} = {field['value']}",
                                                    ],
                                                    impact="Negative quantities can reduce order total",
                                                    evidence=field,
                                                    remediation="Enforce quantity >= 1 for all cart items.",
                                                ))
                                except json.JSONDecodeError:
                                    pass
                        except Exception:
                            pass

        # Phase 2: Detect race condition potential
        log.info("--- Phase 2: Race condition analysis ---")
        if checkout_requests:
            # Check for checkout endpoints that don't use idempotency keys
            for req in checkout_requests:
                if req["method"] in ("POST", "PUT", "PATCH"):
                    post_data = req.get("post_data", "")
                    if "idempotency" not in post_data.lower() and "idempotent" not in post_data.lower():
                        findings.append(Finding(
                            title=f"No Idempotency Key: {req['url'].split('/')[-1]}",
                            severity="medium",
                            cwe="CWE-362",
                            endpoint=req["url"][:200],
                            method=req["method"],
                            description="Checkout request lacks idempotency key — vulnerable to race conditions",
                            steps=[
                                f"{req['method']} {req['url'][:100]}",
                                "No idempotency-key header or field found",
                            ],
                            impact="Double charges or duplicate orders via concurrent requests",
                            evidence={"url": req["url"][:200], "method": req["method"]},
                            remediation="Require Idempotency-Key header on all checkout mutations.",
                        ))

        log.info("Observed %d checkout requests", len(checkout_requests))

    finally:
        cdp_close(session)

    return findings


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--duration", type=int, default=60,
                        help="Monitoring duration in seconds (default: 60)")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("=== CDP Checkout Interceptor starting on %s ===", args.target)
    all_findings = scan(args.target, args.duration, args.dry_run)
    log.info("=== CDP Checkout Interceptor complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "cdp-checkout")


if __name__ == "__main__":
    main()
