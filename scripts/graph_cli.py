#!/usr/bin/env python3
"""Dependency graph CLI — visualize and query tool relationships.

Usage:
    python scripts/graph_cli.py --show              # Print summary
    python scripts/graph_cli.py --order             # Execution order (all tools)
    python scripts/graph_cli.py --order --tools nuclei,sqlmap  # Minimal order
    python scripts/graph_cli.py --suggest -i report.json       # Suggest from findings
    python scripts/graph_cli.py --cwes CWE-79,CWE-89          # Minimal set for CWEs
    python scripts/graph_cli.py --export-dot graph.dot         # Graphviz export
    python scripts/graph_cli.py --export-json graph.json       # JSON export

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from graph import DependencyGraph  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Security tool dependency graph")
    parser.add_argument("--show", action="store_true", help="Print graph summary")
    parser.add_argument("--order", action="store_true", help="Show execution order")
    parser.add_argument("--tools", help="Comma-separated tool list for --order")
    parser.add_argument("--suggest", action="store_true",
                        help="Suggest tools from findings")
    parser.add_argument("--input", "-i", help="Input report JSON for --suggest")
    parser.add_argument("--cwes", help="Comma-separated CWEs → minimal tool set")
    parser.add_argument("--target-type", help="Filter tools by target type (domain/target/code)")
    parser.add_argument("--deps", help="Show dependencies of a specific tool")
    parser.add_argument("--export-dot", metavar="FILE", help="Export DOT file")
    parser.add_argument("--export-json", metavar="FILE", help="Export JSON file")
    args = parser.parse_args()

    g = DependencyGraph()
    g.build_from_config()

    if args.show:
        print(g.summary())

    elif args.order:
        tools = args.tools.split(",") if args.tools else None
        waves = g.execution_order(tools)
        for i, wave in enumerate(waves):
            print(f"Wave {i}: {', '.join(wave)}")
        total = sum(len(w) for w in waves)
        print(f"\nTotal: {total} tools in {len(waves)} waves")

    elif args.suggest:
        if not args.input:
            print("--suggest requires --input/-i report.json")
            sys.exit(1)
        data = json.loads(Path(args.input).read_text())
        findings = data.get("findings", data) if isinstance(data, dict) else data
        suggestions = g.suggest_from_findings(findings)
        if suggestions:
            print(f"Suggested tools based on {len(findings)} findings:")
            for tool in suggestions:
                print(f"  + {tool}")
        else:
            print("No additional tools suggested.")

    elif args.cwes:
        cwes = [c.strip() for c in args.cwes.split(",")]
        tools = g.minimal_set_for_cwes(cwes)
        print(f"Minimal tool set for {', '.join(cwes)}:")
        for tool in tools:
            print(f"  - {tool}")
        waves = g.execution_order(tools)
        print(f"\nExecution: {len(tools)} tools in {len(waves)} waves")

    elif args.target_type:
        tools = g.minimal_set_for_target_type(args.target_type)
        print(f"Tools for target type '{args.target_type}':")
        for tool in tools:
            print(f"  - {tool}")

    elif args.deps:
        deps = g.dependencies_of(args.deps)
        dependents = g.dependents_of(args.deps)
        print(f"Tool: {args.deps}")
        print(f"  Depends on: {', '.join(deps) if deps else '(none)'}")
        print(f"  Required by: {', '.join(dependents) if dependents else '(none)'}")

    elif args.export_dot:
        g.export_dot(args.export_dot)
        print(f"DOT exported to {args.export_dot}")

    elif args.export_json:
        g.export_json(args.export_json)
        print(f"JSON exported to {args.export_json}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
