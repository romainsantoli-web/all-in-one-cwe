#!/usr/bin/env python3
"""Tech stack auto-detection from httpx/whatweb/nuclei scan reports.

Parses tool output to build a tech fingerprint for the scanned target.
Used by Smart Scan to feed domain profiles into cross-target memory.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Header → technology mapping ─────────────────────────────────────────────

_HEADER_TECH: dict[str, list[str]] = {
    "x-powered-by": {
        "express": ["express", "node"],
        "next.js": ["nextjs", "react", "node"],
        "nuxt": ["nuxtjs", "vue", "node"],
        "php": ["php"],
        "asp.net": ["aspnet", "dotnet"],
        "flask": ["flask", "python"],
        "django": ["django", "python"],
        "ruby on rails": ["rails", "ruby"],
        "servlet": ["java"],
    },
    "server": {
        "nginx": ["nginx"],
        "apache": ["apache"],
        "cloudflare": ["cloudflare"],
        "gunicorn": ["gunicorn", "python"],
        "uvicorn": ["uvicorn", "python"],
        "microsoft-iis": ["iis", "dotnet"],
        "openresty": ["openresty", "nginx"],
        "litespeed": ["litespeed"],
        "caddy": ["caddy"],
    },
}

# ── WhatWeb / Wappalyzer keyword → tech mapping ─────────────────────────────

_KEYWORD_TECH: dict[str, list[str]] = {
    "wordpress": ["wordpress", "php"],
    "drupal": ["drupal", "php"],
    "joomla": ["joomla", "php"],
    "laravel": ["laravel", "php"],
    "symfony": ["symfony", "php"],
    "spring": ["spring", "java"],
    "tomcat": ["tomcat", "java"],
    "react": ["react"],
    "angular": ["angular"],
    "vue.js": ["vue"],
    "jquery": ["jquery"],
    "bootstrap": ["bootstrap"],
    "tailwind": ["tailwind"],
    "grafana": ["grafana"],
    "elasticsearch": ["elasticsearch"],
    "redis": ["redis"],
    "mongodb": ["mongodb"],
    "postgresql": ["postgresql"],
    "mysql": ["mysql"],
    "mariadb": ["mariadb"],
    "sqlite": ["sqlite"],
    "aws": ["aws"],
    "azure": ["azure"],
    "gcp": ["gcp"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes"],
    "varnish": ["varnish"],
    "akamai": ["akamai"],
    "fastly": ["fastly"],
    "amazon s3": ["s3", "aws"],
    "amazon cloudfront": ["cloudfront", "aws"],
    "heroku": ["heroku"],
    "vercel": ["vercel"],
    "netlify": ["netlify"],
    "firebase": ["firebase", "gcp"],
}


def detect_from_httpx(report_path: str | Path) -> set[str]:
    """Extract tech signals from httpx JSON/JSONL output."""
    techs: set[str] = set()
    path = Path(report_path)
    if not path.exists():
        return techs

    lines = path.read_text(errors="replace").strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # httpx stores tech in "tech" field
        for t in entry.get("tech", []):
            _match_keyword(t, techs)

        # Parse headers
        headers = entry.get("header", {})
        if isinstance(headers, dict):
            for hdr_name, mapping in _HEADER_TECH.items():
                val = headers.get(hdr_name, "")
                if isinstance(val, str):
                    _match_header(val, mapping, techs)

        # Title may reveal CMS
        title = entry.get("title", "")
        if title:
            _match_keyword(title, techs)

    return techs


def detect_from_whatweb(report_path: str | Path) -> set[str]:
    """Extract tech signals from whatweb JSON output."""
    techs: set[str] = set()
    path = Path(report_path)
    if not path.exists():
        return techs

    try:
        data = json.loads(path.read_text(errors="replace"))
    except json.JSONDecodeError:
        return techs

    entries = data if isinstance(data, list) else [data]
    for entry in entries:
        plugins = entry.get("plugins", {})
        for plugin_name in plugins:
            _match_keyword(plugin_name, techs)

    return techs


def detect_from_nuclei(report_path: str | Path) -> set[str]:
    """Extract tech signals from nuclei JSONL output (tech-detect templates)."""
    techs: set[str] = set()
    path = Path(report_path)
    if not path.exists():
        return techs

    lines = path.read_text(errors="replace").strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        template_id = entry.get("template-id", "")
        if "tech-detect" in template_id or entry.get("type") == "tech":
            matched = entry.get("matched-at", entry.get("info", {}).get("name", ""))
            _match_keyword(matched, techs)

        # Tags often contain tech names
        for tag in entry.get("info", {}).get("tags", []):
            _match_keyword(tag, techs)

    return techs


def detect_tech_stack(
    reports_dir: str | Path = "reports",
    target: str | None = None,
) -> list[str]:
    """Auto-detect tech stack from available scan reports.

    Scans reports/{httpx,whatweb,nuclei}/ for output files.
    Returns sorted, deduplicated list of tech identifiers.

    Args:
        reports_dir: Base reports directory.
        target: Optional target filter (unused for now, for future per-target reports).

    Returns:
        Sorted list like ["aws", "nextjs", "node", "react", "nginx"].
    """
    reports_dir = Path(reports_dir)
    all_techs: set[str] = set()

    # httpx reports (JSONL)
    httpx_dir = reports_dir / "httpx"
    if httpx_dir.is_dir():
        for f in httpx_dir.glob("*.json*"):
            all_techs |= detect_from_httpx(f)

    # whatweb reports (JSON)
    whatweb_dir = reports_dir / "whatweb"
    if whatweb_dir.is_dir():
        for f in whatweb_dir.glob("*.json"):
            all_techs |= detect_from_whatweb(f)

    # nuclei reports (JSONL)
    nuclei_dir = reports_dir / "nuclei"
    if nuclei_dir.is_dir():
        for f in nuclei_dir.glob("*.json*"):
            all_techs |= detect_from_nuclei(f)

    result = sorted(all_techs)
    logger.info("Detected tech stack: %s", result)
    return result


# ── Private helpers ─────────────────────────────────────────────────────────


def _match_keyword(text: str, techs: set[str]) -> None:
    """Match text against keyword→tech mapping."""
    lower = text.lower()
    for keyword, tech_list in _KEYWORD_TECH.items():
        if keyword in lower:
            techs.update(tech_list)


def _match_header(value: str, mapping: dict[str, list[str]], techs: set[str]) -> None:
    """Match header value against header→tech mapping."""
    lower = value.lower()
    for keyword, tech_list in mapping.items():
        if keyword in lower:
            techs.update(tech_list)
