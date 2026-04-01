// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useRef, useEffect, useState, useCallback, useMemo } from "react";
import dynamic from "next/dynamic";
import {
  PARALLEL_GROUPS,
  CWE_TRIGGERS,
  LIGHT_TOOLS,
  MEDIUM_TOOLS,
  getAllTools,
} from "@/lib/tools-data";

// Dynamically import to avoid SSR issues with three.js
const ForceGraph3D = dynamic(() => import("react-force-graph-3d"), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-[600px] text-sm text-[var(--text-muted)]">
      Loading 3D engine…
    </div>
  ),
});

const GROUP_COLORS: Record<string, string> = {
  recon: "#4CAF50",
  dast: "#2196F3",
  injection: "#FF9800",
  specialized: "#9C27B0",
  "python-scanners": "#F44336",
  "code-analysis": "#00BCD4",
  conditional: "#795548",
  "waf-bypass": "#607D8B",
  "web-advanced": "#E91E63",
  iac: "#3F51B5",
  "api-fuzzing": "#CDDC39",
  "waf-evasion": "#FF5722",
  "business-logic": "#8BC34A",
  discovery: "#FFC107",
  "oauth-session": "#673AB7",
  "cdp-scanners": "#009688",
  "crypto-ctf": "#FFEB3B",
  forensics: "#795548",
  reversing: "#9E9E9E",
  privesc: "#D32F2F",
};

interface GraphNode {
  id: string;
  group: string;
  type: "tool" | "cwe";
  color: string;
  val: number;
}

interface GraphLink {
  source: string;
  target: string;
  type: "group_dep" | "cwe_trigger";
  color: string;
}

function buildForce3DData(selectedProfile: string) {
  const profileSet = new Set(
    selectedProfile === "light"
      ? LIGHT_TOOLS
      : selectedProfile === "medium"
        ? MEDIUM_TOOLS
        : getAllTools().map((t) => t.name),
  );

  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];
  const seen = new Set<string>();

  // Tool nodes
  for (const group of PARALLEL_GROUPS) {
    for (const tool of group.tools) {
      if (seen.has(tool)) continue;
      seen.add(tool);
      const inProfile = profileSet.has(tool);
      const color = GROUP_COLORS[group.name] || "#666";
      nodes.push({
        id: tool,
        group: group.name,
        type: "tool",
        color: inProfile ? color : `${color}44`,
        val: inProfile ? 3 : 1,
      });
    }
  }

  // CWE nodes
  for (const cwe of Object.keys(CWE_TRIGGERS)) {
    nodes.push({
      id: cwe,
      group: "cwe",
      type: "cwe",
      color: "#f59e0b",
      val: 2,
    });
  }

  // Group dependency edges
  for (const group of PARALLEL_GROUPS) {
    for (const dep of group.dependsOn) {
      const depGroup = PARALLEL_GROUPS.find((g) => g.name === dep);
      if (!depGroup) continue;
      // Connect last tool of dep to first tool of current
      const src = depGroup.tools[depGroup.tools.length - 1];
      const dst = group.tools[0];
      if (seen.has(src) && seen.has(dst)) {
        links.push({
          source: src,
          target: dst,
          type: "group_dep",
          color: "rgba(100,100,100,0.4)",
        });
      }
    }
  }

  // CWE trigger edges
  for (const [cwe, tools] of Object.entries(CWE_TRIGGERS)) {
    for (const tool of tools) {
      if (seen.has(tool)) {
        links.push({
          source: cwe,
          target: tool,
          type: "cwe_trigger",
          color: "rgba(245,158,11,0.5)",
        });
      }
    }
  }

  return { nodes, links };
}

export default function ToolGraph3D() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [profile, setProfile] = useState("full");
  const [highlight, setHighlight] = useState<string | null>(null);

  const graphData = useMemo(() => buildForce3DData(profile), [profile]);

  useEffect(() => {
    function measure() {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        setDimensions({ width: rect.width, height: 600 });
      }
    }
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, []);

  const handleNodeClick = useCallback((node: any) => {
    setHighlight((prev) => (prev === node.id ? null : (node.id as string)));
  }, []);

  const tools = getAllTools();

  return (
    <div>
      {/* Controls */}
      <div className="flex items-center gap-4 mb-4">
        <div className="flex items-center gap-2">
          <label className="text-sm text-[var(--text-muted)]">Profile:</label>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            className="bg-[var(--card-bg)] border border-[var(--border)] text-sm rounded px-3 py-1.5 text-[var(--text)]"
          >
            <option value="full">Full ({tools.length})</option>
            <option value="medium">Medium ({MEDIUM_TOOLS.length})</option>
            <option value="light">Light ({LIGHT_TOOLS.length})</option>
          </select>
        </div>
        {highlight && (
          <span className="text-xs text-[var(--accent)] bg-[var(--accent)]/10 px-2 py-1 rounded">
            Selected: {highlight}
            <button onClick={() => setHighlight(null)} className="ml-2 text-[var(--text-muted)]">✕</button>
          </span>
        )}
      </div>

      {/* 3D Graph */}
      <div
        ref={containerRef}
        className="bg-[#0a0a0f] border border-[var(--border)] rounded-lg overflow-hidden"
        style={{ height: 600 }}
      >
        <ForceGraph3D
          width={dimensions.width}
          height={dimensions.height}
          graphData={graphData}
          nodeLabel={(node: any) =>
            `${node.id} (${node.group})`
          }
          nodeColor={(node: any) =>
            highlight && node.id !== highlight ? `${node.color}33` : node.color
          }
          nodeVal={(node: any) => node.val}
          nodeOpacity={0.9}
          linkColor={(link: any) => link.color}
          linkWidth={(link: any) =>
            link.type === "cwe_trigger" ? 0.5 : 1
          }
          linkDirectionalParticles={(link: any) =>
            link.type === "group_dep" ? 2 : 0
          }
          linkDirectionalParticleSpeed={0.005}
          onNodeClick={handleNodeClick}
          backgroundColor="#0a0a0f"
          showNavInfo={false}
        />
      </div>

      {/* Legend */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mt-4">
        <h3 className="font-semibold text-sm mb-3">Legend</h3>
        <div className="flex flex-wrap gap-4">
          {Object.entries(GROUP_COLORS).map(([name, color]) => (
            <div key={name} className="flex items-center gap-2 text-xs">
              <span className="w-3 h-3 rounded-full" style={{ background: color }} />
              <span className="text-[var(--text-muted)]">{name}</span>
            </div>
          ))}
          <div className="flex items-center gap-2 text-xs">
            <span className="w-3 h-3 rounded-full" style={{ background: "#f59e0b" }} />
            <span className="text-[var(--text-muted)]">CWE trigger</span>
          </div>
        </div>
        <p className="text-xs text-[var(--text-muted)] mt-2">
          Click a node to highlight it. Drag to rotate, scroll to zoom, right-click to pan.
        </p>
      </div>
    </div>
  );
}
