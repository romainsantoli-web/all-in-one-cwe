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

    def ingest_findings(self, findings: list[dict]) -> int:
        """Ingest findings directly (not from file). Returns count ingested."""
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
            }
            self._client.store(key, record, metadata={"type": "finding"})
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
