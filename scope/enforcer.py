"""Scope enforcer — filters scan results and restricts tool execution."""

from __future__ import annotations

import logging
import re
from typing import Any

from scope.parser import ScopeConfig

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    """Enforces scope restrictions on scan operations and results."""

    def __init__(self, scope: ScopeConfig):
        self._scope = scope
        self._out_of_scope_count = 0
        self._in_scope_count = 0

    @property
    def scope(self) -> ScopeConfig:
        return self._scope

    @property
    def stats(self) -> dict[str, int]:
        return {
            "in_scope": self._in_scope_count,
            "out_of_scope": self._out_of_scope_count,
            "targets": len(self._scope.targets),
        }

    def is_url_allowed(self, url: str) -> bool:
        """Check if a URL is within scope."""
        if not self._scope.targets:
            return True
        allowed = self._scope.is_in_scope(url)
        if allowed:
            self._in_scope_count += 1
        else:
            self._out_of_scope_count += 1
        return allowed

    def filter_findings(self, findings: list[dict]) -> list[dict]:
        """Filter findings to only include in-scope results."""
        if not self._scope.targets:
            return findings  # No scope = keep all

        filtered = []
        for f in findings:
            url = f.get("url", "")
            if not url or self.is_url_allowed(url):
                f["in_scope"] = True
                filtered.append(f)
            else:
                self._out_of_scope_count += 1

        logger.info(
            "Scope filter: %d/%d findings in scope", len(filtered), len(findings),
        )
        return filtered

    def get_target_args(self) -> dict[str, Any]:
        """Return tool-appropriate target arguments based on scope.

        Returns a dict with:
          - urls: list of target URLs
          - domains: list of target domains
          - in_scope_patterns: regex patterns for scope matching
        """
        return {
            "urls": self._scope.target_urls,
            "domains": self._scope.target_domains,
            "in_scope_patterns": [
                re.escape(d).replace(r"\*", ".*")
                for d in self._scope.target_domains
            ],
        }

    def annotate_findings(self, findings: list[dict]) -> list[dict]:
        """Add scope metadata to findings without filtering."""
        for f in findings:
            url = f.get("url", "")
            f["in_scope"] = not url or self._scope.is_in_scope(url)
            if f["in_scope"]:
                # Find matching target for asset value
                for t in self._scope.targets:
                    if ScopeConfig._matches(url, t.url):
                        f["asset_value"] = t.asset_value
                        break
        return findings

    def suggest_tools(self, available_tools: list[str]) -> list[str]:
        """Suggest which tools are relevant for the scope targets.

        Based on target types (web, api, mobile, network).
        """
        target_types = {t.type for t in self._scope.targets}

        # Tool relevance by target type
        type_tools: dict[str, list[str]] = {
            "web": [
                "nuclei", "zap", "nikto", "wapiti", "sqlmap", "xsstrike",
                "dalfox", "commix", "ssrfmap", "whatweb", "httpx",
                "katana", "gospider", "hakrawler", "gau",
            ],
            "api": [
                "nuclei", "zap", "sqlmap", "jwt_tool", "arjun",
                "httpx", "postman",
            ],
            "mobile": [
                "mobsf", "apktool", "frida", "objection",
            ],
            "network": [
                "nmap", "masscan", "subfinder", "amass",
                "dnsx", "tlsx",
            ],
        }

        suggested: list[str] = []
        for tt in target_types:
            for tool in type_tools.get(tt, []):
                if tool in available_tools and tool not in suggested:
                    suggested.append(tool)

        return suggested

    def summary(self) -> dict[str, Any]:
        """Generate scope summary for reports."""
        return {
            "program": self._scope.name,
            "targets": [
                {"url": t.url, "type": t.type, "value": t.asset_value}
                for t in self._scope.targets
            ],
            "out_of_scope": self._scope.out_of_scope[:10],
            "rewards": self._scope.rewards,
            "stats": self.stats,
        }
