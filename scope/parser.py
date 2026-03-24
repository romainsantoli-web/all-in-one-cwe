"""Scope parser — loads scope definitions from Markdown, YAML, or JSON.

Supports:
  - Bug bounty scope files (YesWeHack/HackerOne Markdown format)
  - YAML scope definitions
  - JSON scope definitions
  - Simple URL list files
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ScopeTarget:
    """A single target in scope."""

    url: str
    type: str = "web"  # web, api, mobile, network
    asset_value: str = "medium"  # low, medium, high, critical
    notes: str = ""


@dataclass
class ScopeConfig:
    """Parsed scope configuration."""

    name: str = ""
    targets: list[ScopeTarget] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    qualifying_vulns: list[str] = field(default_factory=list)
    non_qualifying_vulns: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    rewards: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def target_urls(self) -> list[str]:
        return [t.url for t in self.targets]

    @property
    def target_domains(self) -> list[str]:
        """Extract unique domains from target URLs."""
        domains: list[str] = []
        for t in self.targets:
            match = re.search(r"https?://([^/]+)", t.url)
            if match:
                domain = match.group(1)
                if domain not in domains:
                    domains.append(domain)
        return domains

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is in scope."""
        if not self.targets:
            return True  # No scope = everything in scope
        # Explicit targets always win over out-of-scope wildcards
        for target in self.targets:
            if self._matches(url, target.url):
                return True
        # Then check out-of-scope
        for pattern in self.out_of_scope:
            if self._matches(url, pattern):
                return False
        return False

    @staticmethod
    def _matches(url: str, pattern: str) -> bool:
        """Check if URL matches a scope pattern (supports wildcards)."""
        # Exact match
        if url == pattern or url.startswith(pattern):
            return True
        # Wildcard domain (*.example.com)
        if pattern.startswith("*."):
            domain = pattern[2:]
            return domain in url
        # Domain match
        match = re.search(r"https?://([^/]+)", pattern)
        if match and match.group(1) in url:
            return True
        return False


class ScopeParser:
    """Parse scope from various formats."""

    @staticmethod
    def from_file(path: str | Path) -> ScopeConfig:
        """Auto-detect format and parse scope file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Scope file not found: {path}")

        suffix = path.suffix.lower()
        content = path.read_text()

        if suffix in (".yaml", ".yml"):
            return ScopeParser.from_yaml(content)
        elif suffix == ".json":
            return ScopeParser.from_json(content)
        elif suffix in (".md", ".markdown", ".txt"):
            return ScopeParser.from_markdown(content)
        else:
            # Try JSON, then YAML, then Markdown
            try:
                return ScopeParser.from_json(content)
            except (json.JSONDecodeError, KeyError):
                pass
            try:
                return ScopeParser.from_yaml(content)
            except Exception:
                pass
            return ScopeParser.from_markdown(content)

    @staticmethod
    def from_json(content: str) -> ScopeConfig:
        """Parse JSON scope definition."""
        data = json.loads(content)
        targets = []
        for t in data.get("targets", data.get("scopes", [])):
            if isinstance(t, str):
                targets.append(ScopeTarget(url=t))
            else:
                targets.append(ScopeTarget(
                    url=t.get("url", t.get("scope", "")),
                    type=t.get("type", "web"),
                    asset_value=t.get("asset_value", "medium"),
                ))
        return ScopeConfig(
            name=data.get("name", ""),
            targets=targets,
            out_of_scope=data.get("out_of_scope", []),
            qualifying_vulns=data.get("qualifying_vulns", []),
            non_qualifying_vulns=data.get("non_qualifying_vulns", []),
            rules=data.get("rules", []),
            rewards=data.get("rewards", {}),
            raw=data,
        )

    @staticmethod
    def from_yaml(content: str) -> ScopeConfig:
        """Parse YAML scope definition."""
        import yaml

        data = yaml.safe_load(content)
        return ScopeParser.from_json(json.dumps(data))

    @staticmethod
    def from_markdown(content: str) -> ScopeConfig:
        """Parse bug bounty scope from Markdown (YesWeHack/HackerOne format)."""
        config = ScopeConfig(raw={"format": "markdown"})

        # Extract program name
        title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        if title_match:
            config.name = title_match.group(1).strip()

        # Extract scopes table
        config.targets = ScopeParser._parse_scope_table(content)

        # Extract URLs from bold/link patterns (fallback)
        if not config.targets:
            url_pattern = re.compile(r"https?://[^\s\)\"<>]+")
            for url in url_pattern.findall(content):
                # Skip store/app/documentation URLs
                if any(skip in url for skip in ["play.google.com", "apps.apple.com", "itunes.apple.com"]):
                    config.targets.append(ScopeTarget(url=url, type="mobile"))
                elif not any(skip in url for skip in ["yeswehack.com", "hackerone.com", "bugcrowd.com"]):
                    config.targets.append(ScopeTarget(url=url))

        # Extract out-of-scope section
        oos_match = re.search(
            r"(?:OUT\s*OF\s*SCOPE|OUT-OF-SCOPE|EXCLUSIONS?)(.*?)(?=^##|\Z)",
            content, re.IGNORECASE | re.DOTALL | re.MULTILINE,
        )
        if oos_match:
            for line in oos_match.group(1).splitlines():
                line = line.strip().lstrip("*•- ")
                if line and not line.startswith("|") and not line.startswith("---"):
                    config.out_of_scope.append(line)

        # Extract qualifying vulnerabilities
        qual_match = re.search(
            r"QUALIFYING\s*VULNERABILIT(?:Y|IES)(.*?)(?=^##|\Z)",
            content, re.IGNORECASE | re.DOTALL | re.MULTILINE,
        )
        if qual_match:
            for line in qual_match.group(1).splitlines():
                line = line.strip().lstrip("*•- ")
                if line and not line.startswith("|") and not line.startswith("---"):
                    config.qualifying_vulns.append(line)

        # Extract non-qualifying
        nq_match = re.search(
            r"NON.QUALIFYING\s*VULNERABILIT(?:Y|IES)(.*?)(?=^##|\Z)",
            content, re.IGNORECASE | re.DOTALL | re.MULTILINE,
        )
        if nq_match:
            for line in nq_match.group(1).splitlines():
                line = line.strip().lstrip("*•- ")
                if line and not line.startswith("|") and not line.startswith("---"):
                    config.non_qualifying_vulns.append(line)

        # Extract rewards
        reward_pattern = re.compile(
            r"(Low|Medium|High|Critical)[^\d]*[€$£]?\s*(\d[\d,]*)",
            re.IGNORECASE,
        )
        for match in reward_pattern.finditer(content):
            sev = match.group(1).lower()
            amount = int(match.group(2).replace(",", ""))
            config.rewards[sev] = amount

        return config

    @staticmethod
    def _parse_scope_table(content: str) -> list[ScopeTarget]:
        """Parse a Markdown table of scopes."""
        targets: list[ScopeTarget] = []

        # Look for SCOPES section
        scope_match = re.search(
            r"##\s*SCOPES?(.*?)(?=^##|\Z)",
            content, re.IGNORECASE | re.DOTALL | re.MULTILINE,
        )
        if not scope_match:
            return targets

        section = scope_match.group(1)

        # Parse table rows
        for row in section.splitlines():
            if not row.strip().startswith("|"):
                continue
            cells = [c.strip() for c in row.split("|")]
            cells = [c for c in cells if c]

            # Skip header/separator
            if not cells or cells[0].startswith("---") or cells[0].upper() == "SCOPE":
                continue

            # Extract URL from first cell (may be bold/linked)
            url_match = re.search(r"https?://[^\s\)\"*]+", cells[0])
            if url_match:
                url = url_match.group(0)
                scope_type = "web"
                asset_value = "medium"

                if len(cells) > 1:
                    type_str = cells[1].lower()
                    if "android" in type_str:
                        scope_type = "mobile"
                    elif "ios" in type_str:
                        scope_type = "mobile"
                    elif "api" in type_str:
                        scope_type = "api"
                if len(cells) > 2:
                    val_str = cells[2].lower().strip("* ")
                    if val_str in ("low", "medium", "high", "critical"):
                        asset_value = val_str

                targets.append(ScopeTarget(
                    url=url,
                    type=scope_type,
                    asset_value=asset_value,
                ))

        return targets

    @staticmethod
    def from_urls(urls: list[str]) -> ScopeConfig:
        """Create scope from a simple list of URLs."""
        return ScopeConfig(
            targets=[ScopeTarget(url=u) for u in urls],
        )
