"""PayloadEngine — Central interface for payload retrieval and management.

Provides lazy-loaded access to PATT payloads, curated payloads, and
AI-generated payloads (when generator is available). Default risk filter
is ≤ MEDIUM; use include_high=True to unlock dangerous payloads.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from payloads import PayloadSet, RiskLevel, classify_risk
from payloads.index import (
    CATEGORY_CWE_MAP,
    PATT_ROOT,
    build_index,
    get_categories_for_cwe,
    patt_age_days,
)

log = logging.getLogger("payloads.engine")

# ---------------------------------------------------------------------------
# Curated payloads directory
# ---------------------------------------------------------------------------
CURATED_DIR = Path(__file__).parent / "curated"


class PayloadEngine:
    """Central payload retrieval engine.

    Priority order: curated > PATT > generated.
    Default risk filter: ≤ MEDIUM (no reverse shells, no destructive payloads).
    """

    def __init__(self, include_high: bool = False) -> None:
        self._include_high = include_high
        self._index: dict[str, Any] | None = None
        self._cache: dict[str, list[PayloadSet]] = {}  # category → PayloadSets
        self._curated_cache: dict[str, list[PayloadSet]] = {}

    @property
    def index(self) -> dict[str, Any]:
        if self._index is None:
            self._index = build_index()
        return self._index

    @property
    def max_risk(self) -> RiskLevel:
        return RiskLevel.HIGH if self._include_high else RiskLevel.MEDIUM

    # ----- Core API ---------------------------------------------------------

    def get_payloads(
        self,
        category: str,
        include_high: bool | None = None,
    ) -> list[PayloadSet]:
        """Get all PayloadSets for a category, respecting risk filter.

        Args:
            category: PATT category name (e.g. "XSS Injection").
            include_high: Override instance-level include_high setting.
        """
        allow_high = include_high if include_high is not None else self._include_high

        results: list[PayloadSet] = []

        # 1. Curated payloads (highest priority)
        results.extend(self._load_curated(category))

        # 2. PATT payloads
        results.extend(self._load_patt(category))

        # 3. Apply risk filter
        if not allow_high:
            results = [ps.safe_only() for ps in results]

        return [ps for ps in results if ps.count > 0]

    def get_payloads_for_cwe(
        self,
        cwe: str,
        include_high: bool | None = None,
    ) -> list[PayloadSet]:
        """Get all PayloadSets matching a CWE ID.

        Args:
            cwe: CWE identifier (e.g. "CWE-79").
        """
        categories = get_categories_for_cwe(cwe)
        results: list[PayloadSet] = []
        for cat in categories:
            results.extend(self.get_payloads(cat, include_high=include_high))
        return results

    def search(self, query: str, max_results: int = 10) -> list[PayloadSet]:
        """Search payload sets by name/category keyword."""
        query_lower = query.lower()
        matches: list[PayloadSet] = []

        for cat_info in self.index.get("categories", []):
            cat_name = cat_info["name"]
            if query_lower in cat_name.lower():
                matches.extend(self.get_payloads(cat_name))
                if len(matches) >= max_results:
                    break

        return matches[:max_results]

    def all_categories(self) -> list[str]:
        """List all available PATT categories."""
        return [c["name"] for c in self.index.get("categories", [])]

    def stats(self) -> dict[str, Any]:
        """Return engine statistics including PATT freshness."""
        idx = self.index
        age = patt_age_days()
        curated_count = self._count_curated_files()

        return {
            "patt_categories": idx["stats"]["total_categories"],
            "patt_files": idx["stats"]["total_files"],
            "patt_payloads": idx["stats"]["total_payloads"],
            "patt_commit_hash": idx.get("patt_commit_hash", "")[:8],
            "patt_commit_date": idx.get("patt_commit_date", ""),
            "patt_age_days": age,
            "patt_stale": age is not None and age > 30,
            "curated_files": curated_count,
            "include_high": self._include_high,
            "indexed_at": idx.get("indexed_at", ""),
        }

    def rebuild_index(self) -> dict[str, Any]:
        """Force rebuild the PATT index (invalidate cache)."""
        self._index = build_index(force=True)
        self._cache.clear()
        return self._index

    # ----- Private loaders --------------------------------------------------

    def _load_patt(self, category: str) -> list[PayloadSet]:
        """Load PATT payload files for a category (cached)."""
        if category in self._cache:
            return self._cache[category]

        sets: list[PayloadSet] = []
        cwe = CATEGORY_CWE_MAP.get(category, "")

        # Find category in index
        cat_info = None
        for c in self.index.get("categories", []):
            if c["name"] == category:
                cat_info = c
                break

        if not cat_info:
            self._cache[category] = []
            return []

        for file_info in cat_info.get("payload_files", []):
            file_path = PATT_ROOT / file_info["path"]
            if not file_path.exists():
                continue

            payloads = self._read_payload_file(file_path)
            if not payloads:
                continue

            # Determine overall risk level from payload content
            levels = [classify_risk(p) for p in payloads]
            max_level = RiskLevel.LOW
            if RiskLevel.HIGH in levels:
                max_level = RiskLevel.HIGH
            elif RiskLevel.MEDIUM in levels:
                max_level = RiskLevel.MEDIUM

            sets.append(
                PayloadSet(
                    name=file_info["name"].replace(".txt", ""),
                    category=category,
                    cwe=cwe,
                    source="patt",
                    risk_level=max_level,
                    payloads=payloads,
                    file_path=str(file_path),
                    tags=["patt", category.lower().replace(" ", "-")],
                )
            )

        self._cache[category] = sets
        return sets

    def _load_curated(self, category: str) -> list[PayloadSet]:
        """Load curated payload files for a category."""
        if category in self._curated_cache:
            return self._curated_cache[category]

        sets: list[PayloadSet] = []
        cwe = CATEGORY_CWE_MAP.get(category, "")

        # Curated files are stored as: curated/<category-slug>/*.txt
        slug = category.lower().replace(" ", "-")
        curated_dir = CURATED_DIR / slug
        if not curated_dir.is_dir():
            self._curated_cache[category] = []
            return []

        for txt_file in sorted(curated_dir.glob("*.txt")):
            payloads = self._read_payload_file(txt_file)
            if not payloads:
                continue

            levels = [classify_risk(p) for p in payloads]
            max_level = RiskLevel.LOW
            if RiskLevel.HIGH in levels:
                max_level = RiskLevel.HIGH
            elif RiskLevel.MEDIUM in levels:
                max_level = RiskLevel.MEDIUM

            sets.append(
                PayloadSet(
                    name=txt_file.stem,
                    category=category,
                    cwe=cwe,
                    source="curated",
                    risk_level=max_level,
                    payloads=payloads,
                    file_path=str(txt_file),
                    tags=["curated", slug],
                )
            )

        self._curated_cache[category] = sets
        return sets

    @staticmethod
    def _read_payload_file(file_path: Path) -> list[str]:
        """Read a payload file, returning non-empty, non-comment lines."""
        try:
            text = file_path.read_text(errors="replace")
        except OSError:
            return []
        return [
            line
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def _count_curated_files(self) -> int:
        """Count .txt files in the curated/ directory."""
        if not CURATED_DIR.is_dir():
            return 0
        return sum(1 for _ in CURATED_DIR.rglob("*.txt"))


__all__ = ["PayloadEngine", "CURATED_DIR"]
