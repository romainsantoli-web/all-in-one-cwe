"""Security All-in-One CWE — Shared Python scanner library.

Provides: HTTP session with rate limiting, Finding model, scope enforcement,
CLI parsing, and result storage. All custom Python scanners import from here.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BASE_UA = "SecurityAllInOneCWE/1.0 (BugBounty Scanner)"
_UA_SUFFIX = os.environ.get("UA_SUFFIX", "")
USER_AGENT = f"{_BASE_UA} {_UA_SUFFIX}".strip() if _UA_SUFFIX else _BASE_UA
DEFAULT_RATE_LIMIT = 10.0  # max req/s — conservative default
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "/output"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cwe-scanner")

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single vulnerability finding — compatible with merge-reports.py."""

    title: str
    severity: str  # critical / high / medium / low / info
    cwe: str = ""  # e.g. CWE-639
    endpoint: str = ""
    method: str = "GET"
    description: str = ""
    steps: list[str] = field(default_factory=list)
    impact: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Rate-limited session
# ---------------------------------------------------------------------------


class RateLimitedSession:
    """requests.Session wrapper enforcing max req/s and User-Agent."""

    def __init__(
        self,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        auth_token: str | None = None,
        auth_header: str | None = None,
        csrf_token: str | None = None,
        extra_cookies: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.min_interval = 1.0 / rate_limit
        self._last_request = 0.0

        if auth_token:
            self.session.headers["Authorization"] = f"Bearer {auth_token}"
        if auth_header:
            self.session.headers["Authorization"] = auth_header
        if csrf_token:
            self.session.headers["X-CSRF-Token"] = csrf_token
        if extra_cookies:
            for k, v in extra_cookies.items():
                self.session.cookies.set(k, v)
        if extra_headers:
            self.session.headers.update(extra_headers)

    def _wait(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_request = time.monotonic()

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        self._wait()
        kwargs.setdefault("timeout", 15)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        self._wait()
        kwargs.setdefault("timeout", 15)
        return self.session.post(url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        self._wait()
        kwargs.setdefault("timeout", 15)
        return self.session.put(url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        self._wait()
        kwargs.setdefault("timeout", 15)
        return self.session.delete(url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> requests.Response:
        self._wait()
        kwargs.setdefault("timeout", 15)
        return self.session.options(url, **kwargs)


# ---------------------------------------------------------------------------
# Result storage
# ---------------------------------------------------------------------------


def save_findings(findings: list[Finding], tool_name: str) -> Path:
    """Persist findings to OUTPUT_DIR as JSON (merge-reports.py compatible)."""
    out = OUTPUT_DIR
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Fallback for local testing (Docker /output is read-only outside container)
        out = Path.cwd() / "reports" / tool_name
        out.mkdir(parents=True, exist_ok=True)
    scan_date = os.environ.get("SCAN_DATE", "latest")
    path = out / f"scan-{scan_date}.json"

    data = []
    for f in findings:
        data.append({
            "tool": tool_name,
            "id": f.cwe or f.title[:50],
            "name": f.title,
            "severity": f.severity,
            "cwe": f.cwe,
            "url": f.endpoint,
            "description": f.description,
            "method": f.method,
            "steps": f.steps,
            "impact": f.impact,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "timestamp": f.timestamp,
        })

    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    # Always update scan-latest.json so dashboard/runner read the freshest results
    latest = out / "scan-latest.json"
    latest.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    log.info("Saved %d findings → %s", len(findings), path)
    return path


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------


def get_session_from_env() -> RateLimitedSession:
    """Build session from environment variables.

    If no AUTH_TOKEN is set, attempts to source auth.env from the project root
    (generated by auth_extractor.py via Chrome CDP).
    """
    _load_auth_env_if_needed()
    return RateLimitedSession(
        rate_limit=float(os.environ.get("SCANNER_RATE_LIMIT", DEFAULT_RATE_LIMIT)),
        auth_token=os.environ.get("AUTH_TOKEN") or None,
        auth_header=os.environ.get("AUTH_HEADER") or None,
        csrf_token=os.environ.get("CSRF_TOKEN") or None,
        extra_cookies=json.loads(os.environ.get("AUTH_COOKIES", "{}")) or None,
        extra_headers=json.loads(os.environ.get("AUTH_HEADERS", "{}")) or None,
    )


def _load_auth_env_if_needed() -> None:
    """Auto-load auth.env if no auth env vars are set."""
    if os.environ.get("AUTH_TOKEN") or os.environ.get("AUTH_COOKIES", "{}") != "{}":
        return  # Already have auth configured

    # Look for auth.env in common locations
    search_paths = [
        Path.cwd() / "auth.env",
        Path.cwd().parent / "auth.env",
        Path(__file__).resolve().parent.parent.parent / "auth.env",  # project root
    ]
    for env_path in search_paths:
        if env_path.is_file():
            log.info("Auto-loading auth from %s", env_path)
            _source_env_file(env_path)
            return


def _source_env_file(path: Path) -> None:
    """Parse a shell-style .env file and inject into os.environ."""
    import re
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip 'export ' prefix
        if line.startswith("export "):
            line = line[7:]
        match = re.match(r"""([A-Za-z_][A-Za-z0-9_]*)=(.*)""", line)
        if not match:
            continue
        key, val = match.group(1), match.group(2)
        # Remove surrounding quotes
        if (val.startswith('"') and val.endswith('"')) or \
           (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        os.environ[key] = val


def parse_base_args():
    """Minimal argparse shared by all scanners."""
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--target", default=os.environ.get("TARGET", "https://example.com"),
                   help="Target base URL")
    p.add_argument("--dry-run", action="store_true",
                   help="Print actions without sending requests")
    p.add_argument("--rate-limit", type=float,
                   default=float(os.environ.get("SCANNER_RATE_LIMIT", DEFAULT_RATE_LIMIT)))
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--config", type=str, default=None,
                   help="Path to YAML config file for scanner-specific settings")
    return p


def load_config(config_path: str | None) -> dict:
    """Load YAML config (endpoints, payloads, etc.) — returns {} if none."""
    if not config_path or not os.path.isfile(config_path):
        return {}
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        # Fall back to JSON if PyYAML not available
        with open(config_path) as f:
            return json.load(f)
