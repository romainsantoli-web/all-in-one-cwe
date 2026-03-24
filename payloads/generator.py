"""AI-powered payload generator — uses the LLM engine to create context-aware payloads.

Given a target endpoint, vulnerability category, and optional context (headers,
technology stack, WAF info), generates tailored payloads or adapts existing ones.

Priority order: curated > PATT > generated (this module handles the "generated" tier).

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from payloads import PayloadSet, RiskLevel, classify_risk

log = logging.getLogger("payloads.generator")

# ---------------------------------------------------------------------------
# LLM provider (lazy import to avoid circular deps)
# ---------------------------------------------------------------------------
_llm = None


def _get_llm():
    """Lazy-load LLM provider from the llm/ module."""
    global _llm
    if _llm is None:
        try:
            from llm import get_provider

            provider_name = os.environ.get("PAYLOAD_LLM_PROVIDER", "claude")
            _llm = get_provider(provider_name)
            log.info("PayloadGenerator using LLM provider: %s", _llm.name)
        except (ImportError, KeyError) as e:
            log.warning("LLM provider not available: %s — generation disabled", e)
    return _llm


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_GENERATE_PROMPT = """You are an expert penetration tester specializing in {category}.
Generate {count} unique, creative payloads for testing {category} vulnerabilities.

Target context:
- Endpoint: {endpoint}
- Technology: {technology}
- WAF: {waf}
{extra_context}

Requirements:
- Each payload on its own line
- No comments, no explanations, no numbering
- Include encoding variations (URL, HTML, Unicode where relevant)
- Focus on bypass techniques for common WAF rules
- Do NOT include payloads that could cause permanent damage (no rm -rf, no DROP TABLE)
- Prioritize detection over exploitation

Output ONLY the payloads, one per line:"""

_ADAPT_PROMPT = """You are an expert penetration tester. Adapt the following payload
for the given target context. Generate {count} variations.

Original payload:
{original}

Target context:
- Endpoint: {endpoint}
- Technology: {technology}
- WAF: {waf}
{extra_context}

Generate {count} adapted variations. Output ONLY the payloads, one per line:"""

_SUGGEST_PROMPT = """Given these scan findings, suggest which payload categories
would be most effective for deeper testing:

Findings:
{findings_json}

Return a JSON array of objects with keys: "category", "reason", "priority" (1-5).
Example: [{{"category": "XSS Injection", "reason": "Reflected input found", "priority": 5}}]

JSON output:"""


class PayloadGenerator:
    """LLM-powered payload generation and adaptation."""

    def __init__(
        self,
        max_payloads: int = 20,
        max_risk: RiskLevel = RiskLevel.MEDIUM,
    ) -> None:
        self.max_payloads = max_payloads
        self.max_risk = max_risk

    def generate(
        self,
        category: str,
        endpoint: str = "",
        technology: str = "",
        waf: str = "unknown",
        extra_context: str = "",
        count: int | None = None,
    ) -> PayloadSet | None:
        """Generate new payloads for a vulnerability category.

        Returns PayloadSet or None if LLM is unavailable.
        """
        llm = _get_llm()
        if llm is None:
            log.warning("LLM unavailable — cannot generate payloads")
            return None

        n = min(count or self.max_payloads, 50)
        prompt = _GENERATE_PROMPT.format(
            category=category,
            count=n,
            endpoint=endpoint or "generic web application",
            technology=technology or "unknown",
            waf=waf,
            extra_context=f"- Additional: {extra_context}" if extra_context else "",
        )

        try:
            raw = llm.simple_chat(prompt, temperature=0.8, max_tokens=2048)
            payloads = self._parse_payloads(raw)
            payloads = self._apply_risk_filter(payloads)

            if not payloads:
                log.warning("LLM returned no valid payloads for %s", category)
                return None

            levels = [classify_risk(p) for p in payloads]
            max_level = max(levels, key=lambda l: _RISK_ORDER[l])

            return PayloadSet(
                name=f"ai-generated-{category.lower().replace(' ', '-')}",
                category=category,
                cwe="",
                source="generated",
                risk_level=max_level,
                payloads=payloads,
                tags=["generated", "ai", category.lower().replace(" ", "-")],
            )

        except Exception as e:
            log.error("Payload generation failed for %s: %s", category, e)
            return None

    def adapt_payload(
        self,
        original: str,
        endpoint: str = "",
        technology: str = "",
        waf: str = "unknown",
        extra_context: str = "",
        count: int = 5,
    ) -> list[str]:
        """Adapt an existing payload for a specific target context.

        Returns list of adapted payloads, or empty list if LLM unavailable.
        """
        llm = _get_llm()
        if llm is None:
            return []

        prompt = _ADAPT_PROMPT.format(
            original=original,
            count=min(count, 20),
            endpoint=endpoint or "generic web application",
            technology=technology or "unknown",
            waf=waf,
            extra_context=f"- Additional: {extra_context}" if extra_context else "",
        )

        try:
            raw = llm.simple_chat(prompt, temperature=0.8, max_tokens=1024)
            payloads = self._parse_payloads(raw)
            return self._apply_risk_filter(payloads)
        except Exception as e:
            log.error("Payload adaptation failed: %s", e)
            return []

    def suggest_categories(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Given scan findings, suggest which payload categories to test deeper.

        Returns list of {"category": str, "reason": str, "priority": int}.
        """
        llm = _get_llm()
        if llm is None:
            return []

        # Limit findings to avoid token overflow
        truncated = findings[:20]
        prompt = _SUGGEST_PROMPT.format(
            findings_json=json.dumps(truncated, indent=2, default=str)
        )

        try:
            raw = llm.simple_chat(prompt, temperature=0.3, max_tokens=1024)
            # Extract JSON from response
            match = re.search(r"\[.*\]", raw, re.DOTALL)
            if match:
                return json.loads(match.group())
        except Exception as e:
            log.error("Category suggestion failed: %s", e)
        return []

    def _parse_payloads(self, raw: str) -> list[str]:
        """Parse LLM output into clean payload lines."""
        lines = raw.strip().splitlines()
        payloads: list[str] = []
        for line in lines:
            line = line.strip()
            # Skip empty lines, markdown fences, numbering
            if not line or line.startswith("```") or line.startswith("---"):
                continue
            # Remove leading numbering (1. 2. etc.)
            cleaned = re.sub(r"^\d+[\.\)]\s*", "", line)
            if cleaned:
                payloads.append(cleaned)
        return payloads[:self.max_payloads]

    def _apply_risk_filter(self, payloads: list[str]) -> list[str]:
        """Remove payloads above the configured risk threshold."""
        threshold = _RISK_ORDER[self.max_risk]
        return [p for p in payloads if _RISK_ORDER[classify_risk(p)] <= threshold]


_RISK_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}


# ---------------------------------------------------------------------------
# Curated payload management
# ---------------------------------------------------------------------------

CURATED_DIR = Path(__file__).parent / "curated"


def save_curated_payload(
    category: str,
    name: str,
    payloads: list[str],
) -> Path:
    """Save a manually validated payload set to the curated/ directory."""
    slug = category.lower().replace(" ", "-")
    out_dir = CURATED_DIR / slug
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "", name)
    if not safe_name:
        safe_name = "custom"
    out_file = out_dir / f"{safe_name}.txt"

    out_file.write_text("\n".join(payloads) + "\n")
    log.info("Saved %d curated payloads → %s", len(payloads), out_file)
    return out_file


__all__ = ["PayloadGenerator", "save_curated_payload"]
