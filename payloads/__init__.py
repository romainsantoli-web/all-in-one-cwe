"""PayloadEngine — Intelligent payload management for security scanning.

Indexes PayloadsAllTheThings (git submodule), provides CWE-based lookup,
risk-level classification, and AI-powered payload generation.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator


class RiskLevel(str, Enum):
    """Payload risk classification."""

    LOW = "low"  # Passive detection (headers, recon, info disclosure)
    MEDIUM = "medium"  # Active injection (XSS alert, eval, basic SQLi)
    HIGH = "high"  # Dangerous (reverse shells, file deletion, data exfil)


# Regex patterns for HIGH risk classification
_HIGH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"nc\s+(-e|-c)\s",  # netcat reverse shell
        r"bash\s+-i\s+>&",  # bash reverse shell
        r"rm\s+-rf\s+/",  # destructive deletion
        r"curl\s+.*\|\s*bash",  # download & execute
        r"wget\s+.*\|\s*bash",
        r"/etc/(passwd|shadow)",  # sensitive file read
        r"mkfifo\s+/tmp/",  # named pipe reverse shell
        r"\bpython\s+-c\s+.*socket",  # python reverse shell
        r"powershell\s+.*-e\s+",  # encoded powershell
        r"certutil\s+.*-urlcache",  # Windows download
        r"\bchmod\s+[0-7]*777\b",  # world-writable
        r">(>)?\s*/etc/",  # overwrite system files
    ]
]

# Regex patterns for MEDIUM risk classification
_MEDIUM_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\balert\s*\(",  # XSS alert box
        r"\bonerror\s*=",  # XSS event handler
        r"\beval\s*\(",  # code eval
        r"<script",  # script injection
        r"UNION\s+SELECT",  # SQL injection
        r";\s*(ls|cat|id|whoami|uname)\b",  # command injection
        r"document\.cookie",  # cookie theft
        r"\bfetch\s*\(",  # data fetch
        r"XMLHttpRequest",  # XHR exfil
        r"\.\./\.\./",  # path traversal
    ]
]


def classify_risk(payload: str) -> RiskLevel:
    """Classify a single payload line by risk level."""
    for pat in _HIGH_PATTERNS:
        if pat.search(payload):
            return RiskLevel.HIGH
    for pat in _MEDIUM_PATTERNS:
        if pat.search(payload):
            return RiskLevel.MEDIUM
    return RiskLevel.LOW


@dataclass
class PayloadSet:
    """A collection of payloads for a specific category/CWE."""

    name: str
    category: str
    cwe: str = ""
    source: str = "patt"  # patt | curated | generated
    risk_level: RiskLevel = RiskLevel.MEDIUM
    payloads: list[str] = field(default_factory=list)
    file_path: str = ""  # Originating file (if from PATT/curated)
    tags: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.payloads)

    def safe_only(self) -> PayloadSet:
        """Return a new PayloadSet with HIGH-risk payloads removed."""
        safe = [p for p in self.payloads if classify_risk(p) != RiskLevel.HIGH]
        # Recalculate overall risk level
        levels = {classify_risk(p) for p in safe} if safe else {RiskLevel.LOW}
        max_level = (
            RiskLevel.MEDIUM if RiskLevel.MEDIUM in levels else RiskLevel.LOW
        )
        return PayloadSet(
            name=self.name,
            category=self.category,
            cwe=self.cwe,
            source=self.source,
            risk_level=max_level,
            payloads=safe,
            file_path=self.file_path,
            tags=self.tags,
        )

    def filter_by_risk(self, max_risk: RiskLevel = RiskLevel.MEDIUM) -> PayloadSet:
        """Return payloads at or below the given risk level."""
        order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}
        threshold = order[max_risk]
        filtered = [
            p for p in self.payloads if order[classify_risk(p)] <= threshold
        ]
        levels = {classify_risk(p) for p in filtered} if filtered else {RiskLevel.LOW}
        max_l = max(levels, key=lambda l: order[l])
        return PayloadSet(
            name=self.name,
            category=self.category,
            cwe=self.cwe,
            source=self.source,
            risk_level=max_l,
            payloads=filtered,
            file_path=self.file_path,
            tags=self.tags,
        )

    def __iter__(self) -> Iterator[str]:
        return iter(self.payloads)

    def __len__(self) -> int:
        return len(self.payloads)

    def __repr__(self) -> str:
        return (
            f"PayloadSet(name={self.name!r}, category={self.category!r}, "
            f"cwe={self.cwe!r}, count={self.count}, risk={self.risk_level.value})"
        )


__all__ = ["PayloadSet", "RiskLevel", "classify_risk"]
