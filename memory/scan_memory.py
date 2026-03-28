"""Scan Memory — ingest reports, recall past findings, provide AI context.

Bridges the security scanner with Memory OS to:
  - Remember past scan findings and their resolutions
  - Recall similar vulnerabilities found before
  - Provide historical context to the AI analyzer
  - Track remediation status over time
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from memory.client import MemoryClient

logger = logging.getLogger(__name__)


class ScanMemory:
    """Security-scanner-aware wrapper around MemoryClient."""

    def __init__(self, client: MemoryClient | None = None):
        self._client = client or MemoryClient(mode="auto")

    @property
    def available(self) -> bool:
        return self._client.available

    # ── Ingest ──────────────────────────────────────────────────────────────

    def ingest_report(self, report_path: str | Path) -> dict:
        """Ingest a scan report into memory.

        Each finding becomes a memory record keyed by a stable hash.
        Returns stats about what was ingested.
        """
        if not self._client.available:
            return {"ingested": 0, "skipped": 0, "error": "Memory OS not available"}

        report_path = Path(report_path)
        data = json.loads(report_path.read_text())
        findings = data.get("findings", data) if isinstance(data, dict) else data

        ingested = 0
        skipped = 0
        for f in findings:
            key = self._finding_key(f)
            existing = self._client.get(key)
            if existing:
                skipped += 1
                continue

            record = {
                "cwe": f.get("cwe_normalized", f.get("cwe", "")),
                "severity": f.get("severity", "unknown"),
                "tool": f.get("tool", "unknown"),
                "name": f.get("name", f.get("id", "")),
                "url": f.get("url", ""),
                "cvss": f.get("cvss_score", 0),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source": report_path.name,
            }
            if f.get("ai_analysis"):
                record["analysis"] = f["ai_analysis"].get("explanation", "")
                record["remediation"] = f["ai_analysis"].get("remediation", "")

            self._client.store(key, record, metadata={
                "type": "finding",
                "cwe": record["cwe"],
                "severity": record["severity"],
            })
            ingested += 1

        logger.info("Ingested %d findings, skipped %d duplicates", ingested, skipped)
        return {"ingested": ingested, "skipped": skipped, "total": len(findings)}

    def ingest_findings(
        self,
        findings: list[dict],
        domain: str = "",
        tech_stack: list[str] | None = None,
    ) -> int:
        """Ingest findings directly (not from file). Returns count ingested.

        Args:
            findings: List of finding dicts.
            domain: Target domain these findings belong to.
            tech_stack: Detected tech stack for cross-target memory.
        """
        if not self._client.available:
            return 0

        count = 0
        for f in findings:
            key = self._finding_key(f)
            record = {
                "cwe": f.get("cwe_normalized", f.get("cwe", "")),
                "severity": f.get("severity", "unknown"),
                "tool": f.get("tool", "unknown"),
                "name": f.get("name", ""),
                "url": f.get("url", ""),
                "cvss": f.get("cvss_score", 0),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "domain": domain or f.get("domain", ""),
                "tech_stack": tech_stack or f.get("tech_stack", []),
            }
            self._client.store(key, record, metadata={
                "type": "finding",
                "domain": record["domain"],
                "tech_stack": ",".join(record["tech_stack"]),
            })
            count += 1
        return count

    # ── Recall ──────────────────────────────────────────────────────────────

    def recall_similar(self, finding: dict, limit: int = 5) -> list[dict]:
        """Find similar past findings for context."""
        if not self._client.available:
            return []

        query = (
            f"{finding.get('cwe_normalized', '')} "
            f"{finding.get('name', '')} "
            f"{finding.get('severity', '')} "
            f"{finding.get('url', '')}"
        ).strip()

        results = self._client.search(query, limit=limit)
        return results

    def get_context_for_analysis(self, finding: dict) -> str:
        """Build memory context string to inject into LLM prompts."""
        similar = self.recall_similar(finding, limit=3)
        if not similar:
            return ""

        lines = ["## Previous similar findings from memory:\n"]
        for i, mem in enumerate(similar, 1):
            data = mem.get("data", mem)
            lines.append(
                f"{i}. CWE: {data.get('cwe', 'N/A')}, "
                f"Severity: {data.get('severity', 'N/A')}, "
                f"Tool: {data.get('tool', 'N/A')}"
            )
            if data.get("analysis"):
                lines.append(f"   Previous analysis: {data['analysis'][:200]}")
            if data.get("remediation"):
                lines.append(f"   Known remediation: {data['remediation'][:200]}")
            lines.append("")

        return "\n".join(lines)

    # ── Cross-Target Intelligence ───────────────────────────────────────────

    def recall_by_tech_stack(self, tech_stack: list[str], limit: int = 10) -> list[dict]:
        """Find past findings on targets with a similar tech stack.

        Searches memory for findings tagged with any of the given technologies.
        Useful for suggesting tools/vulns known to work on similar stacks.

        Args:
            tech_stack: e.g. ["nextjs", "react", "node", "aws"]
            limit: Max results to return.

        Returns:
            List of memory records with matching tech context.
        """
        if not self._client.available or not tech_stack:
            return []

        query = f"tech_stack {' '.join(tech_stack)}"
        results = self._client.search(query, limit=limit)
        return results

    def get_effectiveness_scores(self) -> dict[str, dict]:
        """Compute tool effectiveness scores from memory history.

        Aggregates past findings to rank tools by:
          - hit_rate: proportion of scans where this tool found something
          - avg_severity: average severity of findings (high/medium/low)
          - best_tech_stacks: tech stacks where this tool performs best

        Returns:
            {"nuclei": {"hit_count": 42, "avg_severity": "high", "tech_stacks": ["php", "laravel"]}}
        """
        if not self._client.available:
            return {}

        # Pull all findings from memory
        results = self._client.search("finding", limit=500)
        if not results:
            return {}

        # Aggregate by tool
        tool_stats: dict[str, dict] = {}
        severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        for mem in results:
            data = mem.get("data", mem)
            tool = data.get("tool", "")
            if not tool:
                continue

            if tool not in tool_stats:
                tool_stats[tool] = {
                    "hit_count": 0,
                    "severity_sum": 0,
                    "tech_stacks": {},
                }

            stats = tool_stats[tool]
            stats["hit_count"] += 1
            sev = data.get("severity", "low").lower()
            stats["severity_sum"] += severity_weight.get(sev, 1)

            for tech in data.get("tech_stack", []):
                stats["tech_stacks"][tech] = stats["tech_stacks"].get(tech, 0) + 1

        # Format output
        scores: dict[str, dict] = {}
        sev_labels = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
        for tool, raw in tool_stats.items():
            count = raw["hit_count"]
            avg_sev = round(raw["severity_sum"] / count) if count else 0
            top_techs = sorted(
                raw["tech_stacks"].items(), key=lambda x: x[1], reverse=True,
            )[:5]
            scores[tool] = {
                "hit_count": count,
                "avg_severity": sev_labels.get(avg_sev, "medium"),
                "tech_stacks": [t[0] for t in top_techs],
            }

        return scores

    def ingest_domain_profile(
        self,
        domain: str,
        tech_stack: list[str],
        findings_summary: dict | None = None,
    ) -> bool:
        """Store a domain profile in memory for future cross-target recall.

        Args:
            domain: e.g. "example.com"
            tech_stack: Detected tech stack.
            findings_summary: Optional {"total": N, "by_severity": {}, "by_cwe": {}}

        Returns:
            True if stored successfully.
        """
        if not self._client.available or not domain:
            return False

        key = f"domain_{hashlib.sha256(domain.encode()).hexdigest()[:12]}"
        record = {
            "domain": domain,
            "tech_stack": tech_stack,
            "last_scanned": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "findings_summary": findings_summary or {},
        }
        self._client.store(key, record, metadata={
            "type": "domain_profile",
            "domain": domain,
            "tech_stack": ",".join(tech_stack),
        })
        logger.info("Stored domain profile: %s (tech: %s)", domain, tech_stack)
        return True

    def recall_domain_profile(self, domain: str) -> dict | None:
        """Retrieve stored domain profile.

        Args:
            domain: Target domain.

        Returns:
            Domain profile dict or None.
        """
        if not self._client.available or not domain:
            return None

        key = f"domain_{hashlib.sha256(domain.encode()).hexdigest()[:12]}"
        result = self._client.get(key)
        if result:
            return result.get("data", result)
        return None

    # ── Stats ───────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return memory statistics."""
        return self._client.status()

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _finding_key(finding: dict) -> str:
        """Generate stable hash key for a finding."""
        parts = [
            finding.get("cwe_normalized", finding.get("cwe", "")),
            finding.get("url", ""),
            finding.get("name", finding.get("id", "")),
            finding.get("tool", ""),
        ]
        raw = "|".join(str(p) for p in parts)
        return f"finding_{hashlib.sha256(raw.encode()).hexdigest()[:12]}"
