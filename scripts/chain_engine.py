#!/usr/bin/env python3
"""Bug chaining engine — detects, prioritizes, and graphs escalation paths.

Given a list of scan findings, this engine:
1. Matches each finding's CWE against known chain rules
2. Returns applicable escalation chains with next steps
3. Prioritizes chains by final severity and payout
4. Suggests follow-up tools to confirm each chain
5. Builds a graph structure for dashboard visualization

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from chain_rules import CHAIN_INDEX, CHAIN_RULES, ESCALATION_INDEX

logger = logging.getLogger("chain_engine")

_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class ChainMatch:
    """A matched chain rule with finding context."""
    rule_id: str
    trigger_cwe: str
    trigger_finding: dict
    next_steps: list[dict]
    final_impact: str
    severity: str
    typical_payout: str
    suggested_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "trigger_cwe": self.trigger_cwe,
            "trigger_finding_id": self.trigger_finding.get("id", ""),
            "trigger_finding_name": self.trigger_finding.get("name", ""),
            "trigger_url": self.trigger_finding.get("url", ""),
            "next_steps": self.next_steps,
            "final_impact": self.final_impact,
            "severity": self.severity,
            "typical_payout": self.typical_payout,
            "suggested_tools": self.suggested_tools,
        }


def detect_chains(findings: list[dict]) -> list[ChainMatch]:
    """Match findings against known chain rules.

    For each finding, look up its CWE in the chain index and return
    all applicable escalation paths.
    """
    matches: list[ChainMatch] = []
    seen: set[tuple[str, str]] = set()  # (rule_id, finding_id)

    for finding in findings:
        cwe = finding.get("cwe_normalized") or finding.get("cwe") or ""
        cwe = str(cwe).upper().strip()
        if not cwe:
            continue

        rules = CHAIN_INDEX.get(cwe, [])
        for rule in rules:
            finding_id = finding.get("id", finding.get("name", ""))
            key = (rule["id"], str(finding_id))
            if key in seen:
                continue
            seen.add(key)

            # Collect all tools suggested by chain steps
            tools: list[str] = []
            for step in rule["next_steps"]:
                tools.extend(step.get("tools", []))

            match = ChainMatch(
                rule_id=rule["id"],
                trigger_cwe=cwe,
                trigger_finding=finding,
                next_steps=rule["next_steps"],
                final_impact=rule["final_impact"],
                severity=rule.get("severity", "high"),
                typical_payout=rule.get("typical_payout", "N/A"),
                suggested_tools=list(dict.fromkeys(tools)),  # dedupe, preserve order
            )
            matches.append(match)
            logger.info("Chain detected: %s (trigger: %s on %s)",
                        rule["id"], cwe, finding.get("url", "N/A"))

    return matches


def prioritize_chains(chains: list[ChainMatch]) -> list[ChainMatch]:
    """Sort chains by severity (desc) then payout upper bound (desc)."""
    def _sort_key(chain: ChainMatch) -> tuple[int, int]:
        sev = _SEVERITY_WEIGHT.get(chain.severity.lower(), 0)
        # Parse upper bound of payout range: "$1K-$15K" → 15000
        payout_upper = _parse_payout_upper(chain.typical_payout)
        return (sev, payout_upper)

    return sorted(chains, key=_sort_key, reverse=True)


def _parse_payout_upper(payout_str: str) -> int:
    """Parse the upper bound from a payout range string."""
    try:
        # "$1K-$15K" → "15K" → 15000
        parts = payout_str.replace("$", "").replace(",", "").split("-")
        raw = parts[-1].strip()
        multiplier = 1
        if raw.upper().endswith("K"):
            multiplier = 1000
            raw = raw[:-1]
        return int(float(raw) * multiplier)
    except (ValueError, IndexError):
        return 0


def suggest_next_tools(chains: list[ChainMatch]) -> list[str]:
    """Return a deduplicated list of tools to run for chain confirmation."""
    tools: list[str] = []
    seen: set[str] = set()
    for chain in chains:
        for tool in chain.suggested_tools:
            if tool not in seen:
                tools.append(tool)
                seen.add(tool)
    return tools


def build_chain_graph(chains: list[ChainMatch]) -> dict:
    """Build a graph structure for visualization.

    Returns:
        {
            "nodes": [{"id": ..., "cwe": ..., "label": ..., "severity": ..., "type": "finding"|"escalation"}],
            "edges": [{"source": ..., "target": ..., "label": ..., "chain_id": ...}],
            "chains": [...],
        }
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()

    for chain in chains:
        finding = chain.trigger_finding
        finding_id = finding.get("id") or finding.get("name") or chain.trigger_cwe
        trigger_node_id = f"finding:{finding_id}"

        # Add trigger finding node
        if trigger_node_id not in node_ids:
            nodes.append({
                "id": trigger_node_id,
                "cwe": chain.trigger_cwe,
                "label": finding.get("name", chain.trigger_cwe),
                "url": finding.get("url", ""),
                "severity": finding.get("severity", "unknown"),
                "type": "finding",
            })
            node_ids.add(trigger_node_id)

        # Add escalation step nodes + edges
        prev_node_id = trigger_node_id
        for i, step in enumerate(chain.next_steps):
            esc_cwe = step.get("escalates_to", f"step-{i}")
            step_node_id = f"escalation:{chain.rule_id}:{esc_cwe}"

            if step_node_id not in node_ids:
                nodes.append({
                    "id": step_node_id,
                    "cwe": esc_cwe,
                    "label": step.get("action", esc_cwe),
                    "tools": step.get("tools", []),
                    "severity": chain.severity,
                    "type": "escalation",
                })
                node_ids.add(step_node_id)

            edges.append({
                "source": prev_node_id,
                "target": step_node_id,
                "label": step.get("action", "escalate"),
                "chain_id": chain.rule_id,
            })
            prev_node_id = step_node_id

    return {
        "nodes": nodes,
        "edges": edges,
        "chains": [c.to_dict() for c in chains],
    }


def get_chain_summary(chains: list[ChainMatch]) -> str:
    """Generate a human-readable summary of detected chains for LLM prompts."""
    if not chains:
        return ""

    lines = ["## Detected Exploit Chains"]
    for chain in chains:
        lines.append(
            f"- **{chain.rule_id}** ({chain.severity.upper()}) — {chain.final_impact} "
            f"[Payout: {chain.typical_payout}]"
        )
        for step in chain.next_steps:
            tools_str = ", ".join(step.get("tools", [])) or "manual"
            lines.append(f"  → {step['action']} (tools: {tools_str}) → {step.get('escalates_to', '?')}")
    lines.append("")
    lines.append("Suggest specific exploitation steps for THIS target based on the chains above.")
    return "\n".join(lines)
