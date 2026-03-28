// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useEffect, useState } from "react";

interface ChainStep {
  action: string;
  tools: string[];
  escalates_to: string;
}

interface Chain {
  rule_id: string;
  trigger_cwe: string;
  trigger_finding_id: string;
  trigger_finding_name: string;
  trigger_url: string;
  next_steps: ChainStep[];
  final_impact: string;
  severity: string;
  typical_payout: string;
  suggested_tools: string[];
}

interface GraphNode {
  id: string;
  cwe: string;
  label: string;
  severity: string;
  type: "finding" | "escalation";
  url?: string;
  tools?: string[];
}

interface GraphEdge {
  source: string;
  target: string;
  label: string;
  chain_id: string;
}

interface ChainGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  chains: Chain[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#6b7280",
  unknown: "#6b7280",
};

const SEVERITY_BG: Record<string, string> = {
  critical: "rgba(239, 68, 68, 0.15)",
  high: "rgba(249, 115, 22, 0.15)",
  medium: "rgba(234, 179, 8, 0.15)",
  low: "rgba(34, 197, 94, 0.15)",
  info: "rgba(107, 114, 128, 0.15)",
  unknown: "rgba(107, 114, 128, 0.15)",
};

function SeverityDot({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity.toLowerCase()] || SEVERITY_COLORS.unknown;
  return (
    <span
      style={{ backgroundColor: color }}
      className="inline-block w-2 h-2 rounded-full mr-1.5"
    />
  );
}

export default function ChainGraph() {
  const [data, setData] = useState<ChainGraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedChain, setSelectedChain] = useState<Chain | null>(null);
  const [viewMode, setViewMode] = useState<"list" | "graph">("list");

  useEffect(() => {
    fetch("/api/chains")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(setData)
      .catch((e) => console.error("ChainGraph fetch error:", e))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex items-center gap-2">
          <div className="animate-spin w-4 h-4 border-2 border-[var(--text-muted)] border-t-transparent rounded-full" />
          <span className="text-sm text-[var(--text-muted)]">
            Detecting exploit chains…
          </span>
        </div>
      </div>
    );
  }

  if (!data || data.chains.length === 0) {
    return (
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
        <h3 className="font-semibold text-sm mb-2 flex items-center gap-2">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
          </svg>
          Exploit Chains
        </h3>
        <p className="text-xs text-[var(--text-muted)]">
          No exploit chains detected. Run a scan with more findings to detect
          escalation paths.
        </p>
      </div>
    );
  }

  const chains = data.chains;
  const critCount = chains.filter((c) => c.severity === "critical").length;
  const highCount = chains.filter((c) => c.severity === "high").length;

  return (
    <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg">
      {/* Header */}
      <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
        <h3 className="font-semibold text-sm flex items-center gap-2">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
          </svg>
          Exploit Chains
          <span className="text-xs font-normal text-[var(--text-muted)]">
            {chains.length} detected
          </span>
        </h3>
        <div className="flex items-center gap-3">
          {critCount > 0 && (
            <span className="text-xs px-2 py-0.5 rounded bg-red-500/15 text-red-400">
              {critCount} critical
            </span>
          )}
          {highCount > 0 && (
            <span className="text-xs px-2 py-0.5 rounded bg-orange-500/15 text-orange-400">
              {highCount} high
            </span>
          )}
          <div className="flex text-xs border border-[var(--border)] rounded overflow-hidden">
            <button
              onClick={() => setViewMode("list")}
              className={`px-2 py-1 ${viewMode === "list" ? "bg-[var(--border)]" : ""}`}
            >
              List
            </button>
            <button
              onClick={() => setViewMode("graph")}
              className={`px-2 py-1 ${viewMode === "graph" ? "bg-[var(--border)]" : ""}`}
            >
              Graph
            </button>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="p-4">
        {viewMode === "list" ? (
          <ChainList
            chains={chains}
            selected={selectedChain}
            onSelect={setSelectedChain}
          />
        ) : (
          <ChainGraphView nodes={data.nodes} edges={data.edges} />
        )}
      </div>

      {/* Detail panel */}
      {selectedChain && (
        <div className="border-t border-[var(--border)] p-4">
          <ChainDetail chain={selectedChain} onClose={() => setSelectedChain(null)} />
        </div>
      )}
    </div>
  );
}

function ChainList({
  chains,
  selected,
  onSelect,
}: {
  chains: Chain[];
  selected: Chain | null;
  onSelect: (c: Chain | null) => void;
}) {
  return (
    <div className="space-y-2 max-h-[400px] overflow-y-auto">
      {chains.map((chain) => {
        const isSelected = selected?.rule_id === chain.rule_id;
        const sev = chain.severity.toLowerCase();
        return (
          <button
            key={chain.rule_id}
            onClick={() => onSelect(isSelected ? null : chain)}
            className={`w-full text-left p-3 rounded-lg border transition-colors ${
              isSelected
                ? "border-[var(--accent)] bg-[var(--accent)]/5"
                : "border-[var(--border)] hover:border-[var(--text-muted)]"
            }`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-sm font-medium">
                <SeverityDot severity={sev} />
                {chain.rule_id}
              </span>
              <span className="text-xs text-[var(--text-muted)]">
                {chain.typical_payout}
              </span>
            </div>
            <p className="text-xs text-[var(--text-muted)] line-clamp-1">
              {chain.final_impact}
            </p>
            <div className="flex items-center gap-2 mt-1.5">
              <span
                className="text-[10px] px-1.5 py-0.5 rounded"
                style={{
                  backgroundColor: SEVERITY_BG[sev],
                  color: SEVERITY_COLORS[sev],
                }}
              >
                {chain.severity.toUpperCase()}
              </span>
              <span className="text-[10px] text-[var(--text-muted)]">
                {chain.trigger_cwe}
              </span>
              {chain.suggested_tools.length > 0 && (
                <span className="text-[10px] text-[var(--text-muted)]">
                  → {chain.suggested_tools.slice(0, 3).join(", ")}
                </span>
              )}
            </div>
          </button>
        );
      })}
    </div>
  );
}

function ChainDetail({
  chain,
  onClose,
}: {
  chain: Chain;
  onClose: () => void;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h4 className="font-semibold text-sm">
          <SeverityDot severity={chain.severity} />
          {chain.rule_id}
        </h4>
        <button
          onClick={onClose}
          className="text-xs text-[var(--text-muted)] hover:text-[var(--text)]"
        >
          Close
        </button>
      </div>
      <p className="text-sm mb-3">{chain.final_impact}</p>

      {/* Escalation path */}
      <div className="space-y-2 mb-3">
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2 py-1 rounded bg-blue-500/15 text-blue-400 font-mono">
            {chain.trigger_cwe}
          </span>
          <span className="text-[var(--text-muted)]">
            {chain.trigger_finding_name || chain.trigger_url || "initial finding"}
          </span>
        </div>
        {chain.next_steps.map((step, i) => (
          <div key={i} className="flex items-center gap-2 text-xs ml-4">
            <span className="text-[var(--text-muted)]">↓</span>
            <span className="px-2 py-1 rounded bg-[var(--border)] font-mono">
              {step.action}
            </span>
            {step.tools.length > 0 && (
              <span className="text-[var(--text-muted)]">
                ({step.tools.join(", ")})
              </span>
            )}
            <span className="text-[var(--text-muted)]">→</span>
            <span className="px-2 py-1 rounded bg-red-500/10 text-red-400 font-mono">
              {step.escalates_to}
            </span>
          </div>
        ))}
      </div>

      {/* Suggested tools */}
      {chain.suggested_tools.length > 0 && (
        <div className="text-xs text-[var(--text-muted)]">
          <span className="font-medium">Run next: </span>
          {chain.suggested_tools.map((t, i) => (
            <code key={i} className="bg-[var(--border)] px-1.5 py-0.5 rounded mr-1">
              {t}
            </code>
          ))}
        </div>
      )}

      {/* Payout */}
      <div className="mt-2 text-xs text-[var(--text-muted)]">
        Typical payout: <span className="font-medium text-green-400">{chain.typical_payout}</span>
      </div>
    </div>
  );
}

function ChainGraphView({
  nodes,
  edges,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
}) {
  // Simple SVG graph layout — left-to-right flow
  const nodeWidth = 140;
  const nodeHeight = 40;
  const gapX = 60;
  const gapY = 20;
  const padding = 20;

  // Group nodes by depth (BFS from finding nodes)
  const findingNodes = nodes.filter((n) => n.type === "finding");
  const depths: Map<string, number> = new Map();
  const queue: string[] = [];

  for (const n of findingNodes) {
    depths.set(n.id, 0);
    queue.push(n.id);
  }
  while (queue.length > 0) {
    const current = queue.shift()!;
    const d = depths.get(current) || 0;
    for (const e of edges) {
      if (e.source === current && !depths.has(e.target)) {
        depths.set(e.target, d + 1);
        queue.push(e.target);
      }
    }
  }

  // Position nodes
  const columns: Map<number, GraphNode[]> = new Map();
  for (const n of nodes) {
    const d = depths.get(n.id) ?? 0;
    const col = columns.get(d) || [];
    col.push(n);
    columns.set(d, col);
  }

  const positions: Map<string, { x: number; y: number }> = new Map();
  const maxCol = Math.max(...Array.from(columns.keys()), 0);
  let maxY = 0;

  for (let col = 0; col <= maxCol; col++) {
    const colNodes = columns.get(col) || [];
    for (let row = 0; row < colNodes.length; row++) {
      const x = padding + col * (nodeWidth + gapX);
      const y = padding + row * (nodeHeight + gapY);
      positions.set(colNodes[row].id, { x, y });
      if (y + nodeHeight > maxY) maxY = y + nodeHeight;
    }
  }

  const svgWidth = padding * 2 + (maxCol + 1) * (nodeWidth + gapX);
  const svgHeight = maxY + padding;

  return (
    <div className="overflow-x-auto">
      <svg
        width={svgWidth}
        height={svgHeight}
        className="min-w-full"
        style={{ minHeight: 120 }}
      >
        {/* Edges */}
        {edges.map((e, i) => {
          const from = positions.get(e.source);
          const to = positions.get(e.target);
          if (!from || !to) return null;
          const x1 = from.x + nodeWidth;
          const y1 = from.y + nodeHeight / 2;
          const x2 = to.x;
          const y2 = to.y + nodeHeight / 2;
          const midX = (x1 + x2) / 2;
          return (
            <g key={`edge-${i}`}>
              <path
                d={`M${x1},${y1} C${midX},${y1} ${midX},${y2} ${x2},${y2}`}
                fill="none"
                stroke="var(--text-muted)"
                strokeWidth={1.5}
                opacity={0.5}
                markerEnd="url(#arrowhead)"
              />
              <text
                x={midX}
                y={Math.min(y1, y2) - 4}
                textAnchor="middle"
                fontSize={9}
                fill="var(--text-muted)"
              >
                {e.label}
              </text>
            </g>
          );
        })}
        {/* Arrow marker */}
        <defs>
          <marker
            id="arrowhead"
            markerWidth="8"
            markerHeight="6"
            refX="8"
            refY="3"
            orient="auto"
          >
            <polygon
              points="0 0, 8 3, 0 6"
              fill="var(--text-muted)"
              opacity={0.6}
            />
          </marker>
        </defs>
        {/* Nodes */}
        {nodes.map((n) => {
          const pos = positions.get(n.id);
          if (!pos) return null;
          const sev = n.severity.toLowerCase();
          const color = SEVERITY_COLORS[sev] || SEVERITY_COLORS.unknown;
          const bg = SEVERITY_BG[sev] || SEVERITY_BG.unknown;
          return (
            <g key={n.id}>
              <rect
                x={pos.x}
                y={pos.y}
                width={nodeWidth}
                height={nodeHeight}
                rx={6}
                fill={bg}
                stroke={color}
                strokeWidth={1.5}
              />
              <text
                x={pos.x + nodeWidth / 2}
                y={pos.y + 16}
                textAnchor="middle"
                fontSize={10}
                fontWeight={600}
                fill={color}
              >
                {n.cwe}
              </text>
              <text
                x={pos.x + nodeWidth / 2}
                y={pos.y + 30}
                textAnchor="middle"
                fontSize={8}
                fill="var(--text-muted)"
              >
                {n.label.length > 18 ? n.label.slice(0, 18) + "…" : n.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
