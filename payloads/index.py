"""PATT Indexer — Parses PayloadsAllTheThings and builds a structured index.

Scans the PATT submodule directory, maps categories to CWEs, indexes
Intruder/Intruders payload files, and caches the result to .cache/patt-index.json.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("payloads.index")

# ---------------------------------------------------------------------------
# PATT root (relative to project root)
# ---------------------------------------------------------------------------
PATT_ROOT = Path(__file__).parent / "PayloadsAllTheThings"
CACHE_DIR = Path(__file__).resolve().parent.parent / ".cache"
CACHE_FILE = CACHE_DIR / "patt-index.json"

# ---------------------------------------------------------------------------
# Category → CWE mapping (60+ entries)
# ---------------------------------------------------------------------------
CATEGORY_CWE_MAP: dict[str, str] = {
    "API Key Leaks": "CWE-798",
    "Account Takeover": "CWE-287",
    "Brute Force Rate Limit": "CWE-307",
    "Business Logic Errors": "CWE-840",
    "CORS Misconfiguration": "CWE-942",
    "CRLF Injection": "CWE-93",
    "CSS Injection": "CWE-79",
    "CSV Injection": "CWE-1236",
    "CVE Exploits": "CWE-1395",
    "Clickjacking": "CWE-1021",
    "Client Side Path Traversal": "CWE-22",
    "Command Injection": "CWE-78",
    "Cross-Site Request Forgery": "CWE-352",
    "DNS Rebinding": "CWE-350",
    "DOM Clobbering": "CWE-79",
    "Denial of Service": "CWE-400",
    "Dependency Confusion": "CWE-427",
    "Directory Traversal": "CWE-22",
    "Encoding Transformations": "CWE-838",
    "External Variable Modification": "CWE-621",
    "File Inclusion": "CWE-98",
    "Google Web Toolkit": "CWE-200",
    "GraphQL Injection": "CWE-89",
    "HTTP Parameter Pollution": "CWE-235",
    "Headless Browser": "CWE-94",
    "Hidden Parameters": "CWE-912",
    "Insecure Deserialization": "CWE-502",
    "Insecure Direct Object References": "CWE-639",
    "Insecure Management Interface": "CWE-749",
    "Insecure Randomness": "CWE-330",
    "Insecure Source Code Management": "CWE-527",
    "JSON Web Token": "CWE-347",
    "Java RMI": "CWE-502",
    "LDAP Injection": "CWE-90",
    "LaTeX Injection": "CWE-94",
    "Mass Assignment": "CWE-915",
    "NoSQL Injection": "CWE-943",
    "OAuth Misconfiguration": "CWE-346",
    "ORM Leak": "CWE-200",
    "Open Redirect": "CWE-601",
    "Prompt Injection": "CWE-77",
    "Prototype Pollution": "CWE-1321",
    "Race Condition": "CWE-362",
    "Regular Expression": "CWE-1333",
    "Request Smuggling": "CWE-444",
    "Reverse Proxy Misconfigurations": "CWE-441",
    "SAML Injection": "CWE-347",
    "SQL Injection": "CWE-89",
    "Server Side Include Injection": "CWE-97",
    "Server Side Request Forgery": "CWE-918",
    "Server Side Template Injection": "CWE-94",
    "Tabnabbing": "CWE-1022",
    "Type Juggling": "CWE-843",
    "Upload Insecure Files": "CWE-434",
    "Virtual Hosts": "CWE-200",
    "Web Cache Deception": "CWE-524",
    "Web Sockets": "CWE-1385",
    "XPATH Injection": "CWE-643",
    "XS-Leak": "CWE-203",
    "XSLT Injection": "CWE-91",
    "XSS Injection": "CWE-79",
    "XXE Injection": "CWE-611",
    "Zip Slip": "CWE-22",
}

# Directories to skip (not vulnerability categories)
_SKIP_DIRS = {
    "_LEARNING_AND_SOCIALS",
    "_template_vuln",
    "Methodology and Resources",
    ".git",
}


def _get_patt_commit_info() -> dict[str, str]:
    """Get the current PATT submodule commit hash and date."""
    info: dict[str, str] = {"patt_commit_hash": "", "patt_commit_date": ""}
    if not PATT_ROOT.exists():
        return info
    try:
        result = subprocess.run(
            ["git", "-C", str(PATT_ROOT), "log", "-1", "--format=%H/%ci"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split("/", 1)
            if len(parts) == 2:
                info["patt_commit_hash"] = parts[0]
                info["patt_commit_date"] = parts[1]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        log.warning("Could not get PATT commit info")
    return info


def _find_payload_files(category_dir: Path) -> list[Path]:
    """Find all .txt payload files in Intruder/ or Intruders/ subdirectories."""
    payload_files: list[Path] = []
    for subdir_name in ("Intruder", "Intruders", "Files"):
        subdir = category_dir / subdir_name
        if subdir.is_dir():
            payload_files.extend(sorted(subdir.glob("*.txt")))
    return payload_files


def _count_payloads(file_path: Path) -> int:
    """Count non-empty lines in a payload file."""
    try:
        return sum(
            1
            for line in file_path.read_text(errors="replace").splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
    except OSError:
        return 0


def build_index(force: bool = False) -> dict[str, Any]:
    """Build or load the PATT index.

    Returns a dict with:
      - categories: list of {name, cwe, dir, payload_files: [{name, path, count}]}
      - patt_commit_hash, patt_commit_date, indexed_at
      - stats: {total_categories, total_files, total_payloads}
    """
    if not force and CACHE_FILE.exists():
        try:
            cached = json.loads(CACHE_FILE.read_text())
            if cached.get("categories"):
                log.info(
                    "Loaded cached PATT index: %d categories, %d files",
                    cached["stats"]["total_categories"],
                    cached["stats"]["total_files"],
                )
                return cached
        except (json.JSONDecodeError, KeyError, OSError):
            log.warning("Cache invalid, rebuilding index")

    if not PATT_ROOT.exists():
        log.error("PATT submodule not found at %s", PATT_ROOT)
        return {
            "categories": [],
            "stats": {"total_categories": 0, "total_files": 0, "total_payloads": 0},
            "patt_commit_hash": "",
            "patt_commit_date": "",
            "indexed_at": "",
        }

    commit_info = _get_patt_commit_info()
    categories: list[dict[str, Any]] = []
    total_files = 0
    total_payloads = 0

    for entry in sorted(PATT_ROOT.iterdir()):
        if not entry.is_dir() or entry.name in _SKIP_DIRS:
            continue

        cwe = CATEGORY_CWE_MAP.get(entry.name, "")
        payload_files = _find_payload_files(entry)

        files_info: list[dict[str, Any]] = []
        for pf in payload_files:
            count = _count_payloads(pf)
            files_info.append({
                "name": pf.name,
                "path": str(pf.relative_to(PATT_ROOT)),
                "count": count,
            })
            total_payloads += count

        categories.append({
            "name": entry.name,
            "cwe": cwe,
            "dir": str(entry.relative_to(PATT_ROOT)),
            "payload_files": files_info,
        })
        total_files += len(files_info)

    index: dict[str, Any] = {
        "categories": categories,
        "stats": {
            "total_categories": len(categories),
            "total_files": total_files,
            "total_payloads": total_payloads,
        },
        **commit_info,
        "indexed_at": datetime.now(timezone.utc).isoformat(),
    }

    # Cache to disk
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(index, indent=2, ensure_ascii=False))
        log.info(
            "Built PATT index: %d categories, %d files, %d payloads → %s",
            len(categories),
            total_files,
            total_payloads,
            CACHE_FILE,
        )
    except OSError as e:
        log.warning("Could not cache PATT index: %s", e)

    return index


def get_cwe_for_category(category: str) -> str:
    """Look up the CWE for a PATT category name."""
    return CATEGORY_CWE_MAP.get(category, "")


def get_categories_for_cwe(cwe: str) -> list[str]:
    """Find all PATT categories matching a CWE ID."""
    return [cat for cat, c in CATEGORY_CWE_MAP.items() if c == cwe]


def patt_age_days() -> int | None:
    """Return the age in days of the PATT submodule commit, or None if unknown."""
    info = _get_patt_commit_info()
    date_str = info.get("patt_commit_date", "")
    if not date_str:
        return None
    try:
        # Format: "2026-03-20 14:30:00 +0100"
        commit_dt = datetime.fromisoformat(date_str.strip())
        now = datetime.now(timezone.utc)
        return (now - commit_dt).days
    except (ValueError, TypeError):
        return None


__all__ = [
    "CATEGORY_CWE_MAP",
    "PATT_ROOT",
    "build_index",
    "get_categories_for_cwe",
    "get_cwe_for_category",
    "patt_age_days",
]
