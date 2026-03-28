// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { NextResponse } from "next/server";
import { readFile } from "fs/promises";
import { join } from "path";

export const dynamic = "force-dynamic";

function getProjectRoot(): string {
  return process.env.PROJECT_ROOT || process.env.REPORTS_DIR
    ? join(process.env.REPORTS_DIR || "", "..")
    : join(process.cwd(), "..");
}

function getReportsDir(): string {
  return process.env.REPORTS_DIR || join(getProjectRoot(), "reports");
}

export async function GET() {
  const reportsDir = getReportsDir();

  // Try analyzed-report.json first (has chains data), then scored/deduped
  const candidates = [
    "analyzed-report.json",
    "scored-report.json",
    "deduped-report.json",
  ];

  let findings: Array<Record<string, unknown>> = [];
  let chains: Array<Record<string, unknown>> = [];

  for (const name of candidates) {
    try {
      const raw = await readFile(join(reportsDir, name), "utf-8");
      const data = JSON.parse(raw);

      // If the report has pre-computed chains, use them
      if (data.chains && Array.isArray(data.chains)) {
        chains = data.chains;
      }

      findings = Array.isArray(data) ? data : (data.findings || []);
      break;
    } catch {
      continue;
    }
  }

  // If no pre-computed chains, detect them server-side via Python
  if (chains.length === 0 && findings.length > 0) {
    try {
      const { execFile } = await import("child_process");
      const { promisify } = await import("util");
      const execFileAsync = promisify(execFile);
      const pythonBin = process.env.PYTHON_BIN || "python3";
      const projectRoot = getProjectRoot();

      // Write findings to a temp file to avoid shell escaping issues
      const { writeFile: writeFileFs } = await import("fs/promises");
      const tmpPath = join(reportsDir, ".tmp-chain-detect.json");
      await writeFileFs(tmpPath, JSON.stringify(findings));

      const { stdout } = await execFileAsync(
        pythonBin,
        ["-c", `
import sys, json
sys.path.insert(0, "${projectRoot}")
sys.path.insert(0, "${join(projectRoot, "scripts")}")
from chain_engine import detect_chains, prioritize_chains, build_chain_graph

findings = json.loads(open("${tmpPath}").read())
raw_chains = detect_chains(findings)
ranked = prioritize_chains(raw_chains)
graph = build_chain_graph(ranked)
print(json.dumps(graph))
`],
        { cwd: projectRoot, timeout: 15000 },
      );

      // Clean up temp file
      try { await import("fs/promises").then((fs) => fs.unlink(tmpPath)); } catch { /* ignore */ }

      const graph = JSON.parse(stdout.trim());
      return NextResponse.json(graph);
    } catch (e) {
      // Fall through to empty response
      console.error("Chain detection failed:", e);
    }
  }

  // If we have pre-computed chains, build a minimal graph structure
  if (chains.length > 0) {
    // Build graph from pre-computed chains data
    const nodes: Array<Record<string, unknown>> = [];
    const edges: Array<Record<string, unknown>> = [];
    const nodeIds = new Set<string>();

    for (const chain of chains) {
      const triggerCwe = (chain.trigger_cwe || "") as string;
      const ruleId = (chain.rule_id || "") as string;
      const findingId = (chain.trigger_finding_id || triggerCwe) as string;
      const triggerId = `finding:${findingId}`;

      if (!nodeIds.has(triggerId)) {
        nodes.push({
          id: triggerId,
          cwe: triggerCwe,
          label: (chain.trigger_finding_name || triggerCwe) as string,
          severity: (chain.severity || "unknown") as string,
          type: "finding",
        });
        nodeIds.add(triggerId);
      }

      const steps = (chain.next_steps || []) as Array<Record<string, unknown>>;
      let prevId = triggerId;
      for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        const escCwe = (step.escalates_to || `step-${i}`) as string;
        const stepId = `escalation:${ruleId}:${escCwe}`;

        if (!nodeIds.has(stepId)) {
          nodes.push({
            id: stepId,
            cwe: escCwe,
            label: (step.action || escCwe) as string,
            tools: step.tools || [],
            severity: (chain.severity || "unknown") as string,
            type: "escalation",
          });
          nodeIds.add(stepId);
        }

        edges.push({
          source: prevId,
          target: stepId,
          label: (step.action || "escalate") as string,
          chain_id: ruleId,
        });
        prevId = stepId;
      }
    }

    return NextResponse.json({ nodes, edges, chains });
  }

  return NextResponse.json({ nodes: [], edges: [], chains: [] });
}
