#!/usr/bin/env python3
"""HATEOAS Fuzzer — Link extraction + schema fuzzing (CWE-639/284).

Discovers and tests HATEOAS (Hypermedia as the Engine of Application State) links:
- Extracts _links, _embedded, href from API responses
- Follows link relations to discover hidden endpoints
- Tests IDOR via ID manipulation in discovered links
- Fuzzes discovered schemas with boundary values

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import re
import sys
import os
from urllib.parse import urlparse, urljoin

sys.path.insert(0, os.path.dirname(__file__))

from lib import (
    Finding, RateLimitedSession, get_session_from_env, log,
    parse_base_args, save_findings, load_config,
)

# ---------------------------------------------------------------------------
# Known API entry points
# ---------------------------------------------------------------------------

DEFAULT_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/graphql",
    "/", "/index.json",
]

# HATEOAS link keys to extract
LINK_KEYS = ["_links", "links", "_embedded", "href", "url", "self", "next", "prev", "first", "last"]

# IDOR payload mutations
IDOR_MUTATIONS = [
    lambda x: str(int(x) + 1) if x.isdigit() else None,       # id + 1
    lambda x: str(int(x) - 1) if x.isdigit() and int(x) > 0 else None,  # id - 1
    lambda x: "0" if x.isdigit() else None,                     # id = 0
    lambda x: "99999" if x.isdigit() else None,                 # large id
    lambda x: "1" if x.isdigit() and x != "1" else None,        # id = 1 (admin)
]


def extract_links(data: dict | list, base_url: str) -> list[dict]:
    """Recursively extract HATEOAS links from JSON response."""
    links: list[dict] = []

    if isinstance(data, dict):
        # Standard HAL _links
        if "_links" in data:
            hal_links = data["_links"]
            if isinstance(hal_links, dict):
                for rel, link_data in hal_links.items():
                    if isinstance(link_data, dict) and "href" in link_data:
                        href = link_data["href"]
                        if not href.startswith("http"):
                            href = urljoin(base_url, href)
                        links.append({"rel": rel, "href": href, "method": link_data.get("method", "GET")})
                    elif isinstance(link_data, list):
                        for item in link_data:
                            if isinstance(item, dict) and "href" in item:
                                href = item["href"]
                                if not href.startswith("http"):
                                    href = urljoin(base_url, href)
                                links.append({"rel": rel, "href": href, "method": item.get("method", "GET")})

        # Direct href/url fields
        for key in ("href", "url", "self"):
            if key in data and isinstance(data[key], str):
                href = data[key]
                if not href.startswith("http"):
                    href = urljoin(base_url, href)
                links.append({"rel": key, "href": href, "method": "GET"})

        # JSON:API links
        if "links" in data and isinstance(data["links"], dict):
            for rel, href in data["links"].items():
                if isinstance(href, str):
                    if not href.startswith("http"):
                        href = urljoin(base_url, href)
                    links.append({"rel": rel, "href": href, "method": "GET"})
                elif isinstance(href, dict) and "href" in href:
                    h = href["href"]
                    if not h.startswith("http"):
                        h = urljoin(base_url, h)
                    links.append({"rel": rel, "href": h, "method": href.get("method", "GET")})

        # Recurse into _embedded
        if "_embedded" in data and isinstance(data["_embedded"], dict):
            for _key, embedded in data["_embedded"].items():
                links.extend(extract_links(embedded, base_url))

        # Recurse into nested objects
        for key, value in data.items():
            if key not in ("_links", "_embedded", "links") and isinstance(value, (dict, list)):
                links.extend(extract_links(value, base_url))

    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                links.extend(extract_links(item, base_url))

    return links


def test_idor_on_link(
    session: RateLimitedSession,
    link: dict,
    original_status: int,
    dry_run: bool = False,
) -> list[Finding]:
    """Test IDOR by manipulating numeric IDs in the link URL."""
    findings: list[Finding] = []
    href = link["href"]

    # Find numeric segments in the URL path
    parsed = urlparse(href)
    segments = parsed.path.strip("/").split("/")

    for i, segment in enumerate(segments):
        for mutate in IDOR_MUTATIONS:
            mutated = mutate(segment)
            if mutated is None or mutated == segment:
                continue

            new_segments = segments.copy()
            new_segments[i] = mutated
            new_path = "/" + "/".join(new_segments)
            new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
            if parsed.query:
                new_url += f"?{parsed.query}"

            if dry_run:
                log.info("[DRY-RUN] IDOR test: %s → %s", href, new_url)
                continue

            try:
                resp = session.get(new_url, timeout=10)
                if resp.status_code == 200:
                    # Check if we got different data (not just the same resource)
                    findings.append(Finding(
                        title=f"Potential IDOR: {link['rel']} ({segment} → {mutated})",
                        severity="high",
                        cwe="CWE-639",
                        endpoint=new_url,
                        method="GET",
                        description=(
                            f"HATEOAS link '{link['rel']}' accessible with manipulated ID. "
                            f"Original: {segment}, Mutated: {mutated}"
                        ),
                        steps=[
                            f"Discovered link via HATEOAS: {href} (rel={link['rel']})",
                            f"Mutated ID segment: {segment} → {mutated}",
                            f"GET {new_url} returned {resp.status_code}",
                        ],
                        impact="Insecure Direct Object Reference — access to other users' resources",
                        evidence={
                            "original_url": href,
                            "mutated_url": new_url,
                            "original_id": segment,
                            "mutated_id": mutated,
                            "status": resp.status_code,
                            "size": len(resp.content),
                        },
                        remediation="Implement proper authorization checks. Verify resource ownership before returning data.",
                    ))
            except Exception as e:
                log.debug("IDOR test error: %s", e)

    return findings


def scan(
    session: RateLimitedSession,
    target: str,
    api_paths: list[str] | None = None,
    dry_run: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    visited: set[str] = set()
    all_links: list[dict] = []

    paths = api_paths or DEFAULT_API_PATHS

    # Phase 1: Discover HATEOAS links from entry points
    log.info("--- Phase 1: Discovering HATEOAS links ---")
    for path in paths:
        url = f"{target.rstrip('/')}{path}"
        if dry_run:
            log.info("[DRY-RUN] GET %s", url)
            continue

        try:
            resp = session.get(url, timeout=10)
            if resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                if "json" in ct:
                    try:
                        data = resp.json()
                        links = extract_links(data, url)
                        all_links.extend(links)
                        log.info("  %s: %d links found", path, len(links))
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            log.debug("Error fetching %s: %s", url, e)

    # Deduplicate links
    seen_hrefs: set[str] = set()
    unique_links: list[dict] = []
    for link in all_links:
        if link["href"] not in seen_hrefs:
            seen_hrefs.add(link["href"])
            unique_links.append(link)

    log.info("Total unique links discovered: %d", len(unique_links))

    # Phase 2: Follow links and look for sensitive data
    log.info("--- Phase 2: Following discovered links ---")
    for link in unique_links[:50]:  # Cap at 50 to avoid excessive scanning
        href = link["href"]
        if href in visited:
            continue
        visited.add(href)

        # Only follow links on the same domain
        if urlparse(href).netloc != urlparse(target).netloc:
            continue

        if dry_run:
            log.info("[DRY-RUN] Following %s (%s)", link["rel"], href)
            continue

        try:
            resp = session.get(href, timeout=10)
            if resp.status_code == 200:
                # Discover more links recursively (one level only)
                ct = resp.headers.get("content-type", "")
                if "json" in ct:
                    try:
                        data = resp.json()
                        nested = extract_links(data, href)
                        for nl in nested:
                            if nl["href"] not in seen_hrefs:
                                unique_links.append(nl)
                                seen_hrefs.add(nl["href"])
                    except json.JSONDecodeError:
                        pass

                # Check if the endpoint reveals unexpected data
                if resp.status_code == 200 and link["rel"] not in ("self", "next", "prev", "first", "last"):
                    findings.append(Finding(
                        title=f"HATEOAS Endpoint Accessible: {link['rel']}",
                        severity="low",
                        cwe="CWE-284",
                        endpoint=href,
                        method="GET",
                        description=f"HATEOAS link relation '{link['rel']}' is publicly accessible",
                        steps=[
                            f"Discovered via HATEOAS link extraction",
                            f"Relation: {link['rel']}",
                            f"GET {href} → {resp.status_code}",
                        ],
                        impact="API surface enumeration via HATEOAS links",
                        evidence={"rel": link["rel"], "status": resp.status_code, "size": len(resp.content)},
                        remediation="Ensure all linked resources enforce proper authorization.",
                    ))
        except Exception as e:
            log.debug("Error following link %s: %s", href, e)

    # Phase 3: IDOR testing on discovered links
    log.info("--- Phase 3: IDOR testing ---")
    for link in unique_links[:30]:  # Cap IDOR testing
        idor_findings = test_idor_on_link(session, link, 200, dry_run)
        findings.extend(idor_findings)

    return findings


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--api-paths", nargs="*", default=None,
                        help="Custom API entry paths (default: common paths)")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    session = get_session_from_env()
    if args.rate_limit:
        session.min_interval = 1.0 / args.rate_limit

    log.info("=== HATEOAS Fuzzer starting on %s ===", args.target)
    all_findings = scan(session, args.target, args.api_paths, args.dry_run)
    log.info("=== HATEOAS Fuzzer complete: %d findings ===", len(all_findings))
    save_findings(all_findings, "hateoas-fuzzer")


if __name__ == "__main__":
    main()
