#!/usr/bin/env python3
"""OSINT Enricher — Shodan + SearchSploit + Recon-ng result parsing (CWE-200).

Enriches reconnaissance data by:
  1. Querying Shodan for exposed services/ports
  2. Looking up CVEs via SearchSploit for detected tech stack
  3. Parsing recon-ng workspace results
  4. Correlating exposed services with known exploits

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

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
# Phase 1: Shodan host lookup
# ---------------------------------------------------------------------------


def query_shodan(
    domain: str,
    config: dict,
    dry_run: bool,
) -> list[Finding]:
    """Query Shodan API for exposed services on the target domain."""
    findings: list[Finding] = []
    api_key = os.environ.get("SHODAN_API_KEY") or config.get("shodan_api_key")

    if not api_key:
        log.warning("SHODAN_API_KEY not set — skipping Shodan enrichment")
        return findings

    if dry_run:
        log.info("[DRY-RUN] Shodan lookup for %s", domain)
        return findings

    import requests as req

    try:
        resp = req.get(
            f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={api_key}",
            timeout=15,
        )
        resp.raise_for_status()
        ip_data = resp.json()
        ip = ip_data.get(domain)
        if not ip:
            log.info("Shodan: no IP resolved for %s", domain)
            return findings

        host_resp = req.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=15,
        )
        host_resp.raise_for_status()
        host_data = host_resp.json()

        ports = host_data.get("ports", [])
        vulns = host_data.get("vulns", [])
        services = host_data.get("data", [])

        # Report unexpected open ports
        expected_ports = config.get("expected_ports", [80, 443])
        unexpected = [p for p in ports if p not in expected_ports]

        if unexpected:
            findings.append(Finding(
                title=f"Unexpected open ports on {domain}: {unexpected}",
                severity="medium",
                cwe="CWE-200",
                endpoint=domain,
                description=(
                    f"Shodan reports {len(ports)} open ports on {domain} ({ip}). "
                    f"Unexpected: {unexpected}"
                ),
                steps=[
                    f"Shodan API query for {domain}",
                    f"Resolved IP: {ip}",
                    f"All ports: {sorted(ports)}",
                    f"Unexpected: {unexpected}",
                ],
                impact="Exposed services increase attack surface",
                evidence={
                    "ip": ip,
                    "all_ports": sorted(ports),
                    "unexpected_ports": unexpected,
                    "org": host_data.get("org", "unknown"),
                },
                remediation=(
                    "Close unnecessary ports. "
                    "Apply firewall rules to restrict access. "
                    "Move internal services behind VPN."
                ),
            ))

        # Report known CVEs
        if vulns:
            findings.append(Finding(
                title=f"Known CVEs on {domain}: {len(vulns)} vulnerabilities",
                severity="high" if len(vulns) > 5 else "medium",
                cwe="CWE-1035",
                endpoint=domain,
                description=(
                    f"Shodan reports {len(vulns)} known CVEs on {domain}: "
                    f"{', '.join(vulns[:10])}"
                ),
                steps=[
                    f"Shodan API query for {domain}",
                    f"CVEs found: {vulns}",
                ],
                impact="Known vulnerabilities may be exploitable",
                evidence={
                    "cves": vulns,
                    "ip": ip,
                },
                remediation="Patch affected software to latest versions.",
            ))

        # Report services with banner info
        for svc in services:
            product = svc.get("product", "")
            version = svc.get("version", "")
            port = svc.get("port", 0)
            if product and version:
                findings.append(Finding(
                    title=f"Service banner: {product} {version} on port {port}",
                    severity="info",
                    cwe="CWE-200",
                    endpoint=f"{domain}:{port}",
                    description=(
                        f"Shodan identifies {product} {version} on port {port}. "
                        f"Version disclosure aids targeted attacks."
                    ),
                    steps=[
                        f"Shodan banner grab on {domain}:{port}",
                        f"Product: {product}, Version: {version}",
                    ],
                    impact="Version disclosure enables targeted CVE exploitation",
                    evidence={
                        "product": product,
                        "version": version,
                        "port": port,
                        "banner": svc.get("data", "")[:200],
                    },
                    remediation="Hide version banners in server configuration.",
                ))

    except Exception as exc:
        log.warning("Shodan query failed: %s", exc)

    return findings


# ---------------------------------------------------------------------------
# Phase 2: SearchSploit CVE lookup for detected technologies
# ---------------------------------------------------------------------------


def searchsploit_lookup(
    tech_stack: list[str],
    config: dict,
    dry_run: bool,
) -> list[Finding]:
    """Run searchsploit against detected technologies."""
    findings: list[Finding] = []

    if dry_run:
        log.info("[DRY-RUN] SearchSploit lookup for: %s", tech_stack)
        return findings

    # Read tech stack from reports or config
    if not tech_stack:
        tech_stack = config.get("tech_stack", [])

    # Also try to auto-detect from existing scan results
    whatweb_report = Path(os.environ.get("REPORTS_DIR", "reports")) / "whatweb"
    if not tech_stack and whatweb_report.exists():
        for f in whatweb_report.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                if isinstance(data, list):
                    for entry in data:
                        plugins = entry.get("plugins", {})
                        for name in plugins:
                            if name.lower() not in ("ip", "country", "httpserver"):
                                tech_stack.append(name)
            except Exception:
                continue

    for tech in tech_stack[:20]:  # Limit to avoid excessive queries
        # Clean up tech name for searchsploit
        clean_tech = re.sub(r"[^a-zA-Z0-9. -]", "", tech).strip()
        if len(clean_tech) < 3:
            continue

        try:
            result = subprocess.run(
                ["searchsploit", "--json", clean_tech],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                # searchsploit not installed — try Docker fallback
                result = subprocess.run(
                    [
                        "docker", "compose", "run", "--rm",
                        "--profile", "exploit-lookup",
                        "searchsploit", "--json", clean_tech,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

            if result.stdout:
                data = json.loads(result.stdout)
                exploits = data.get("RESULTS_EXPLOIT", [])
                if exploits:
                    findings.append(Finding(
                        title=f"Known exploits for {clean_tech}: {len(exploits)} found",
                        severity="high" if any(
                            "remote" in e.get("Title", "").lower() for e in exploits
                        ) else "medium",
                        cwe="CWE-1035",
                        endpoint=clean_tech,
                        description=(
                            f"SearchSploit found {len(exploits)} exploits for "
                            f"'{clean_tech}': "
                            + "; ".join(e.get("Title", "")[:80] for e in exploits[:5])
                        ),
                        steps=[
                            f"searchsploit --json {clean_tech}",
                            f"Found {len(exploits)} exploits",
                        ],
                        impact="Known exploits available for detected technology",
                        evidence={
                            "technology": clean_tech,
                            "exploit_count": len(exploits),
                            "top_exploits": [
                                {
                                    "title": e.get("Title", ""),
                                    "path": e.get("Path", ""),
                                    "type": e.get("Type", ""),
                                }
                                for e in exploits[:5]
                            ],
                        },
                        remediation=(
                            f"Update {clean_tech} to latest version. "
                            f"Check {len(exploits)} exploits for applicability."
                        ),
                    ))
        except FileNotFoundError:
            log.info("searchsploit not available locally — use Docker service")
            break
        except Exception as exc:
            log.debug("SearchSploit error for %s: %s", clean_tech, exc)

    return findings


# ---------------------------------------------------------------------------
# Phase 3: Parse recon-ng results
# ---------------------------------------------------------------------------


def parse_recon_ng_results(config: dict) -> list[Finding]:
    """Parse recon-ng workspace results if available."""
    findings: list[Finding] = []
    recon_dir = Path(os.environ.get("REPORTS_DIR", "reports")) / "recon-ng"

    if not recon_dir.exists():
        return findings

    for f in recon_dir.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            hosts = data if isinstance(data, list) else data.get("hosts", [])
            for host in hosts:
                if isinstance(host, dict) and host.get("host"):
                    findings.append(Finding(
                        title=f"Recon-ng discovered host: {host['host']}",
                        severity="info",
                        cwe="CWE-200",
                        endpoint=host["host"],
                        description=f"Discovered via recon-ng: {json.dumps(host)[:200]}",
                        impact="Additional attack surface discovered",
                        evidence=host,
                    ))
        except Exception as exc:
            log.debug("Error parsing recon-ng results: %s", exc)

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = parse_base_args()
    parser.add_argument("--domain", default=os.environ.get("DOMAIN", ""),
                        help="Target domain for Shodan/recon-ng")
    parser.add_argument("--tech-stack", nargs="*", default=[],
                        help="Detected technologies for searchsploit")
    parser.add_argument("--skip-shodan", action="store_true",
                        help="Skip Shodan lookup")
    parser.add_argument("--skip-searchsploit", action="store_true",
                        help="Skip SearchSploit lookup")
    args = parser.parse_args()
    config = load_config(args.config) if hasattr(args, "config") and args.config else {}

    domain = args.domain or urlparse(args.target).hostname or ""
    findings: list[Finding] = []

    if not args.skip_shodan and domain:
        log.info("Phase 1: Shodan host lookup for %s...", domain)
        findings.extend(query_shodan(domain, config, args.dry_run))

    if not args.skip_searchsploit:
        log.info("Phase 2: SearchSploit CVE lookup...")
        findings.extend(searchsploit_lookup(args.tech_stack, config, args.dry_run))

    log.info("Phase 3: Parsing recon-ng results...")
    findings.extend(parse_recon_ng_results(config))

    log.info("OSINT enrichment complete: %d findings", len(findings))
    save_findings(findings, "osint-enricher")


if __name__ == "__main__":
    main()
