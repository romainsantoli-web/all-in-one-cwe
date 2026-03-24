"""Dependency graph — models relationships between security tools.

Uses the DAG from orchestrator/config.py (PARALLEL_GROUPS, CWE_TRIGGERS,
TOOL_META) to build a networkx DiGraph with:
  - Group dependencies (recon → dast → injection)
  - CWE-triggered tool chains
  - Input type relationships (domain vs target vs code)

Provides:
  - Execution order computation (topological sort)
  - Minimal tool set for a given CWE or target type
  - Smart suggestions based on findings
  - DOT/JSON export for visualization
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Lazy import — only needed when graph is actually built
_nx = None


def _ensure_networkx():
    global _nx
    if _nx is None:
        try:
            import networkx as nx
            _nx = nx
        except ImportError:
            raise ImportError(
                "networkx is required for the dependency graph. "
                "Install it with: pip install networkx"
            )
    return _nx


class DependencyGraph:
    """Security tool dependency graph."""

    def __init__(self):
        nx = _ensure_networkx()
        self._graph = nx.DiGraph()
        self._groups: dict[str, list[str]] = {}
        self._group_deps: dict[str, list[str]] = {}
        self._cwe_triggers: dict[str, list[str]] = {}
        self._tool_meta: dict[str, dict] = {}
        self._built = False

    def build_from_config(self) -> "DependencyGraph":
        """Build graph from orchestrator config."""
        from orchestrator.config import (
            CWE_TRIGGERS,
            PARALLEL_GROUPS,
            TOOL_META,
        )

        self._cwe_triggers = dict(CWE_TRIGGERS)
        self._tool_meta = dict(TOOL_META)

        # Add group nodes and tool nodes
        for group in PARALLEL_GROUPS:
            name = group["name"]
            tools = group["tools"]
            deps = group.get("depends_on", [])
            self._groups[name] = tools
            self._group_deps[name] = deps

            for tool in tools:
                meta = TOOL_META.get(tool, {})
                self._graph.add_node(tool, **{
                    "group": name,
                    "type": "tool",
                    "requires": meta.get("requires", "target"),
                    "profile": meta.get("profile"),
                })

            # Add group→group edges (dependency)
            for dep in deps:
                dep_tools = []
                for g in PARALLEL_GROUPS:
                    if g["name"] == dep:
                        dep_tools = g["tools"]
                        break
                # Every tool in this group depends on all tools in dep group
                for tool in tools:
                    for dep_tool in dep_tools:
                        self._graph.add_edge(dep_tool, tool, relation="group_dep")

        # Add CWE trigger edges
        for cwe, triggered_tools in CWE_TRIGGERS.items():
            for tool in triggered_tools:
                if tool in self._graph:
                    self._graph.nodes[tool]["cwe_trigger"] = cwe

        self._built = True
        return self

    @property
    def tool_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    @property
    def groups(self) -> dict[str, list[str]]:
        return dict(self._groups)

    def all_tools(self) -> list[str]:
        """Return all tools in topological order."""
        nx = _ensure_networkx()
        try:
            return list(nx.topological_sort(self._graph))
        except nx.NetworkXUnfeasible:
            return sorted(self._graph.nodes)

    def execution_order(self, tools: list[str] | None = None) -> list[list[str]]:
        """Return tools grouped by execution wave (parallel within each wave).

        If tools is None, returns all tools. Otherwise returns the minimal
        set needed to run the specified tools (including dependencies).
        """
        if tools:
            needed = self._resolve_deps(tools)
        else:
            needed = set(self._graph.nodes)

        # Group by dependency depth
        nx = _ensure_networkx()
        subgraph = self._graph.subgraph(needed)

        waves: list[list[str]] = []
        remaining = set(needed)

        while remaining:
            # Tools with no unresolved dependencies in remaining set
            ready = [
                t for t in remaining
                if all(p not in remaining for p in subgraph.predecessors(t))
            ]
            if not ready:
                # Cycle or orphan — just add remaining
                waves.append(sorted(remaining))
                break
            waves.append(sorted(ready))
            remaining -= set(ready)

        return waves

    def _resolve_deps(self, tools: list[str]) -> set[str]:
        """Resolve all transitive dependencies for a set of tools."""
        nx = _ensure_networkx()
        needed: set[str] = set()
        for tool in tools:
            if tool in self._graph:
                needed.add(tool)
                needed.update(nx.ancestors(self._graph, tool))
        return needed

    def dependencies_of(self, tool: str) -> list[str]:
        """Return direct dependencies of a tool."""
        if tool not in self._graph:
            return []
        return [p for p in self._graph.predecessors(tool)]

    def dependents_of(self, tool: str) -> list[str]:
        """Return tools that depend on this tool."""
        if tool not in self._graph:
            return []
        return [s for s in self._graph.successors(tool)]

    def minimal_set_for_cwes(self, cwes: list[str]) -> list[str]:
        """Return minimal tool set to detect specific CWEs."""
        tools: set[str] = set()

        # Direct CWE triggers
        for cwe in cwes:
            cwe = cwe.upper()
            if cwe in self._cwe_triggers:
                tools.update(self._cwe_triggers[cwe])

        # Tools that cover these CWEs (from profiles/metadata)
        cwe_tool_map = self._build_cwe_tool_map()
        for cwe in cwes:
            cwe = cwe.upper()
            if cwe in cwe_tool_map:
                tools.update(cwe_tool_map[cwe])

        # Add minimal deps
        if tools:
            tools = self._resolve_deps(list(tools))

        return sorted(tools)

    def minimal_set_for_target_type(self, target_type: str) -> list[str]:
        """Return tools appropriate for a target type (domain, target, code, etc.)."""
        tools = [
            name for name, data in self._graph.nodes(data=True)
            if data.get("requires") == target_type or data.get("requires") is None
        ]
        return sorted(tools)

    def suggest_from_findings(self, findings: list[dict]) -> list[str]:
        """Suggest additional tools based on existing scan findings."""
        found_cwes: set[str] = set()
        for f in findings:
            cwe = f.get("cwe_normalized") or f.get("cwe") or ""
            if cwe:
                found_cwes.add(str(cwe).upper())

        suggestions: list[str] = []
        for cwe in found_cwes:
            if cwe in self._cwe_triggers:
                for tool in self._cwe_triggers[cwe]:
                    if tool not in suggestions:
                        suggestions.append(tool)

        return suggestions

    def _build_cwe_tool_map(self) -> dict[str, list[str]]:
        """Build reverse map: CWE → tools that detect it."""
        # This is a simplified mapping based on common knowledge
        cwe_map: dict[str, list[str]] = defaultdict(list)

        # From CWE_TRIGGERS (already known)
        for cwe, tools in self._cwe_triggers.items():
            cwe_map[cwe].extend(tools)

        # Common tool→CWE mappings
        tool_cwes: dict[str, list[str]] = {
            "nuclei": ["CWE-79", "CWE-89", "CWE-918", "CWE-22", "CWE-78", "CWE-601"],
            "zap": ["CWE-79", "CWE-89", "CWE-352", "CWE-200", "CWE-693"],
            "sqlmap": ["CWE-89"],
            "dalfox": ["CWE-79"],
            "sstimap": ["CWE-1336"],
            "ssrfmap": ["CWE-918"],
            "semgrep": ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-502"],
            "gitleaks": ["CWE-798", "CWE-312"],
            "trufflehog": ["CWE-798"],
            "testssl": ["CWE-326", "CWE-327", "CWE-295"],
            "nmap": ["CWE-200", "CWE-284"],
            "nikto": ["CWE-200", "CWE-693"],
        }
        for tool, cwes in tool_cwes.items():
            for cwe in cwes:
                if tool not in cwe_map[cwe]:
                    cwe_map[cwe].append(tool)

        return dict(cwe_map)

    # ── Export ────────────────────────────────────────────────────

    def to_dot(self) -> str:
        """Export graph as DOT format for Graphviz."""
        lines = ["digraph SecurityTools {", '  rankdir=LR;', '  node [shape=box];']

        # Color by group
        group_colors = [
            "#4CAF50", "#2196F3", "#FF9800", "#9C27B0", "#F44336",
            "#00BCD4", "#795548", "#607D8B", "#E91E63", "#3F51B5", "#CDDC39",
        ]
        for i, (group_name, tools) in enumerate(self._groups.items()):
            color = group_colors[i % len(group_colors)]
            lines.append(f'  subgraph cluster_{group_name} {{')
            lines.append(f'    label="{group_name}";')
            lines.append(f'    style=filled; color="{color}20";')
            for tool in tools:
                lines.append(f'    "{tool}" [fillcolor="{color}40", style=filled];')
            lines.append("  }")

        # Edges
        for u, v, data in self._graph.edges(data=True):
            style = "dashed" if data.get("relation") == "cwe_trigger" else "solid"
            lines.append(f'  "{u}" -> "{v}" [style={style}];')

        lines.append("}")
        return "\n".join(lines)

    def to_json(self) -> dict[str, Any]:
        """Export graph as JSON for the dashboard."""
        nodes = []
        for name, data in self._graph.nodes(data=True):
            nodes.append({
                "id": name,
                "group": data.get("group", "unknown"),
                "requires": data.get("requires", "target"),
                "profile": data.get("profile"),
            })

        links = []
        for u, v, data in self._graph.edges(data=True):
            links.append({
                "source": u,
                "target": v,
                "relation": data.get("relation", "group_dep"),
            })

        return {
            "nodes": nodes,
            "links": links,
            "groups": self._groups,
            "cwe_triggers": self._cwe_triggers,
            "stats": {
                "tools": self.tool_count,
                "edges": self.edge_count,
                "groups": len(self._groups),
            },
        }

    def export_json(self, path: str | Path) -> None:
        """Write graph JSON to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_json(), indent=2))
        logger.info("Graph exported to %s", path)

    def export_dot(self, path: str | Path) -> None:
        """Write graph DOT to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_dot())
        logger.info("DOT exported to %s", path)

    # ── Display ─────────────────────────────────────────────────

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"Dependency Graph: {self.tool_count} tools, {self.edge_count} edges, "
            f"{len(self._groups)} groups",
            "",
        ]
        for group_name, tools in self._groups.items():
            deps = self._group_deps.get(group_name, [])
            dep_str = f" (after {', '.join(deps)})" if deps else " (independent)"
            lines.append(f"  [{group_name}]{dep_str}: {', '.join(tools)}")

        lines.append(f"\nCWE triggers: {len(self._cwe_triggers)}")
        for cwe, tools in sorted(self._cwe_triggers.items()):
            lines.append(f"  {cwe} → {', '.join(tools)}")

        return "\n".join(lines)
