#!/usr/bin/env python3
"""Phase 8 tests — Bug Chaining Engine.

⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

passed = 0
failed = 0


def ok(name: str):
    global passed
    passed += 1
    print(f"  ✅ {name}")


def fail(name: str, reason: str):
    global failed
    failed += 1
    print(f"  ❌ {name}: {reason}")


# ── chain_rules tests ──────────────────────────────────

from chain_rules import CHAIN_RULES, CHAIN_INDEX, ESCALATION_INDEX

# T1: At least 25 chain rules
if len(CHAIN_RULES) >= 25:
    ok(f"chain_rules: {len(CHAIN_RULES)} rules (>= 25)")
else:
    fail("chain_rules: count", f"only {len(CHAIN_RULES)} rules")

# T2: All rules have required keys
required_keys = {"id", "trigger_cwe", "next_steps", "final_impact", "severity", "typical_payout"}
all_have_keys = True
for rule in CHAIN_RULES:
    missing = required_keys - set(rule.keys())
    if missing:
        all_have_keys = False
        fail(f"chain_rules: {rule['id']} missing keys", str(missing))
        break
if all_have_keys:
    ok("chain_rules: all rules have required keys")

# T3: CHAIN_INDEX has SSRF
if "CWE-918" in CHAIN_INDEX:
    ok(f"CHAIN_INDEX has CWE-918 ({len(CHAIN_INDEX['CWE-918'])} rules)")
else:
    fail("CHAIN_INDEX", "CWE-918 missing")

# T4: CHAIN_INDEX has XSS
if "CWE-79" in CHAIN_INDEX:
    ok(f"CHAIN_INDEX has CWE-79 ({len(CHAIN_INDEX['CWE-79'])} rules)")
else:
    fail("CHAIN_INDEX", "CWE-79 missing")

# T5: ESCALATION_INDEX populated
if len(ESCALATION_INDEX) > 5:
    ok(f"ESCALATION_INDEX has {len(ESCALATION_INDEX)} CWEs")
else:
    fail("ESCALATION_INDEX", f"only {len(ESCALATION_INDEX)} entries")

# T6: No duplicate rule IDs
rule_ids = [r["id"] for r in CHAIN_RULES]
dupes = [x for x in rule_ids if rule_ids.count(x) > 1]
if not dupes:
    ok("chain_rules: no duplicate IDs")
else:
    fail("chain_rules: duplicate IDs", str(set(dupes)))


# ── chain_engine tests ─────────────────────────────────

from chain_engine import (
    detect_chains,
    prioritize_chains,
    suggest_next_tools,
    build_chain_graph,
    get_chain_summary,
    ChainMatch,
)

# T7: detect_chains finds SSRF chain
ssrf_findings = [
    {"id": "f1", "cwe_normalized": "CWE-918", "name": "SSRF", "url": "https://example.com/fetch", "severity": "high"},
]
ssrf_chains = detect_chains(ssrf_findings)
if len(ssrf_chains) >= 1:
    ok(f"detect_chains: SSRF → {len(ssrf_chains)} chains")
else:
    fail("detect_chains: SSRF", "no chains found")

# T8: detect_chains finds XSS chains
xss_findings = [
    {"id": "f2", "cwe_normalized": "CWE-79", "name": "Reflected XSS", "url": "https://example.com/search", "severity": "high"},
]
xss_chains = detect_chains(xss_findings)
if len(xss_chains) >= 2:
    ok(f"detect_chains: XSS → {len(xss_chains)} chains")
else:
    fail("detect_chains: XSS", f"only {len(xss_chains)} chains")

# T9: detect_chains handles empty findings
empty_chains = detect_chains([])
if len(empty_chains) == 0:
    ok("detect_chains: empty input → 0 chains")
else:
    fail("detect_chains: empty", f"expected 0, got {len(empty_chains)}")

# T10: detect_chains handles finding with no CWE
no_cwe_chains = detect_chains([{"id": "x", "severity": "low"}])
if len(no_cwe_chains) == 0:
    ok("detect_chains: no CWE → 0 chains")
else:
    fail("detect_chains: no CWE", f"expected 0, got {len(no_cwe_chains)}")

# T11: prioritize_chains sorts by severity descending
mixed_findings = [
    {"id": "f1", "cwe_normalized": "CWE-918", "name": "SSRF", "severity": "high"},
    {"id": "f2", "cwe_normalized": "CWE-79", "name": "XSS", "severity": "medium"},
    {"id": "f3", "cwe_normalized": "CWE-89", "name": "SQLi", "severity": "critical"},
]
mixed = detect_chains(mixed_findings)
ranked = prioritize_chains(mixed)
if len(ranked) >= 2:
    first_sev = ranked[0].severity.lower()
    if first_sev == "critical":
        ok("prioritize_chains: critical first")
    else:
        fail("prioritize_chains: order", f"first is {first_sev}, not critical")
else:
    fail("prioritize_chains", f"only {len(ranked)} chains")

# T12: suggest_next_tools returns tool list
tools = suggest_next_tools(ssrf_chains)
if isinstance(tools, list) and len(tools) > 0:
    ok(f"suggest_next_tools: {len(tools)} tools ({', '.join(tools[:3])})")
else:
    fail("suggest_next_tools", f"got {tools}")

# T13: build_chain_graph returns correct structure
graph = build_chain_graph(ssrf_chains)
if "nodes" in graph and "edges" in graph and "chains" in graph:
    ok(f"build_chain_graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
else:
    fail("build_chain_graph: structure", str(graph.keys()))

# T14: graph has finding nodes
finding_nodes = [n for n in graph["nodes"] if n["type"] == "finding"]
if len(finding_nodes) >= 1:
    ok(f"build_chain_graph: {len(finding_nodes)} finding nodes")
else:
    fail("build_chain_graph: finding nodes", "0 found")

# T15: graph has escalation nodes
esc_nodes = [n for n in graph["nodes"] if n["type"] == "escalation"]
if len(esc_nodes) >= 1:
    ok(f"build_chain_graph: {len(esc_nodes)} escalation nodes")
else:
    fail("build_chain_graph: escalation nodes", "0 found")

# T16: get_chain_summary produces text
summary = get_chain_summary(ssrf_chains)
if "Detected Exploit Chains" in summary and "SSRF" in summary:
    ok("get_chain_summary: contains chain info")
else:
    fail("get_chain_summary", f"unexpected: {summary[:100]}")

# T17: get_chain_summary empty input
empty_summary = get_chain_summary([])
if empty_summary == "":
    ok("get_chain_summary: empty → empty string")
else:
    fail("get_chain_summary: empty", f"got '{empty_summary}'")

# T18: ChainMatch.to_dict() has all required keys
if ssrf_chains:
    d = ssrf_chains[0].to_dict()
    expected = {"rule_id", "trigger_cwe", "next_steps", "final_impact", "severity", "typical_payout", "suggested_tools"}
    if expected.issubset(set(d.keys())):
        ok("ChainMatch.to_dict() has all keys")
    else:
        fail("ChainMatch.to_dict()", f"missing: {expected - set(d.keys())}")

# T19: SQLi chain detection
sqli_findings = [
    {"id": "f4", "cwe_normalized": "CWE-89", "name": "SQL Injection", "severity": "critical"},
]
sqli_chains = detect_chains(sqli_findings)
if len(sqli_chains) >= 2:
    ok(f"detect_chains: SQLi → {len(sqli_chains)} chains (exfil + RCE)")
else:
    fail("detect_chains: SQLi", f"only {len(sqli_chains)}, expected >= 2")

# T20: Deduplication — same finding doesn't produce duplicates
dup_findings = [
    {"id": "dup1", "cwe_normalized": "CWE-918", "name": "SSRF", "severity": "high"},
    {"id": "dup1", "cwe_normalized": "CWE-918", "name": "SSRF", "severity": "high"},
]
dup_chains = detect_chains(dup_findings)
ids = [(c.rule_id, c.trigger_finding.get("id")) for c in dup_chains]
unique_ids = set(ids)
if len(ids) == len(unique_ids):
    ok("detect_chains: no duplicates on same finding")
else:
    fail("detect_chains: duplicates", f"got {len(ids)} total, {len(unique_ids)} unique")


# ── smart_scan import test ─────────────────────────────

# T21: smart_scan imports chain_engine
try:
    import importlib
    smart_scan = importlib.import_module("smart_scan")
    source = Path(smart_scan.__file__).read_text()
    if "chain_engine" in source and "detect_chains" in source:
        ok("smart_scan imports chain_engine")
    else:
        fail("smart_scan import", "chain_engine not imported")
except Exception as e:
    fail("smart_scan import", str(e))

# T22: ai_analyzer imports chain_engine
try:
    ai_src = (Path(__file__).parent.parent / "scripts" / "ai_analyzer.py").read_text()
    if "chain_engine" in ai_src and "get_chain_summary" in ai_src:
        ok("ai_analyzer imports chain_engine")
    else:
        fail("ai_analyzer import", "chain_engine not imported")
except Exception as e:
    fail("ai_analyzer import", str(e))

# T23: analyze_with_llm has chain_context param
try:
    import inspect
    ai_mod = importlib.import_module("ai_analyzer")
    sig = inspect.signature(ai_mod.analyze_with_llm)
    if "chain_context" in sig.parameters:
        ok("analyze_with_llm has chain_context param")
    else:
        fail("analyze_with_llm params", str(list(sig.parameters.keys())))
except Exception as e:
    fail("analyze_with_llm inspection", str(e))


# ── Summary ─────────────────────────────────────────────

print(f"\nPhase 8 Tests: {passed} passed, {failed} failed")

if __name__ == "__main__":
    sys.exit(0 if failed == 0 else 1)
