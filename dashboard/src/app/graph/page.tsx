// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { PARALLEL_GROUPS, CWE_TRIGGERS, TOOL_META, LIGHT_TOOLS, MEDIUM_TOOLS, getAllTools } from "@/lib/tools-data";

const ToolGraph3D = dynamic(() => import("@/components/ToolGraph3D"), { ssr: false });
const SiteMap3D = dynamic(() => import("@/components/SiteMap3D"), { ssr: false });

type TabKey = "2d" | "3d" | "site-map";

const TABS: { key: TabKey; label: string; icon: string }[] = [
  { key: "2d", label: "Pipeline 2D", icon: "📊" },
  { key: "3d", label: "Pipeline 3D", icon: "🧊" },
  { key: "site-map", label: "Site Map", icon: "🌐" },
];

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
};

interface NodePos {
  x: number;
  y: number;
  group: string;
  name: string;
}

function drawGraph(canvas: HTMLCanvasElement, highlight: string | null, selectedProfile: string) {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, rect.width, rect.height);

  const W = rect.width;
  const H = rect.height;
  const padding = 40;

  // Layout: groups as columns/rows
  const groups = PARALLEL_GROUPS;
  const positions: Record<string, NodePos> = {};

  // Determine execution depth of each group (BFS from roots)
  const depths: Record<string, number> = {};
  const queue: string[] = [];
  for (const g of groups) {
    if (g.dependsOn.length === 0) {
      depths[g.name] = 0;
      queue.push(g.name);
    }
  }
  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const g of groups) {
      if (g.dependsOn.includes(cur)) {
        const newDepth = depths[cur] + 1;
        if (depths[g.name] === undefined || newDepth > depths[g.name]) {
          depths[g.name] = newDepth;
          queue.push(g.name);
        }
      }
    }
  }

  const maxDepth = Math.max(...Object.values(depths), 0);
  const colWidth = (W - padding * 2) / (maxDepth + 1);

  // Place groups by depth, tools vertically within group
  const depthGroups: Record<number, string[]> = {};
  for (const g of groups) {
    const d = depths[g.name] ?? 0;
    if (!depthGroups[d]) depthGroups[d] = [];
    depthGroups[d].push(g.name);
  }

  for (const [depthStr, gNames] of Object.entries(depthGroups)) {
    const depth = parseInt(depthStr);
    const x = padding + depth * colWidth + colWidth / 2;
    let totalTools = 0;
    for (const gn of gNames) {
      const g = groups.find((gg) => gg.name === gn)!;
      totalTools += g.tools.length;
    }
    const rowH = Math.max(18, (H - padding * 2) / Math.max(totalTools, 1));
    let yOff = padding;

    for (const gn of gNames) {
      const g = groups.find((gg) => gg.name === gn)!;
      for (let i = 0; i < g.tools.length; i++) {
        positions[g.tools[i]] = {
          x,
          y: yOff + i * rowH + rowH / 2,
          group: gn,
          name: g.tools[i],
        };
      }
      yOff += g.tools.length * rowH + 10;
    }
  }

  // Profile filter
  const profileSet = new Set(
    selectedProfile === "light" ? LIGHT_TOOLS :
    selectedProfile === "medium" ? MEDIUM_TOOLS :
    getAllTools().map((t) => t.name)
  );

  // Draw group dependency edges
  for (const g of groups) {
    for (const dep of g.dependsOn) {
      const depGroup = groups.find((gg) => gg.name === dep);
      if (!depGroup) continue;
      // Draw from last tool of dep group to first tool of current group
      const srcTool = depGroup.tools[depGroup.tools.length - 1];
      const dstTool = g.tools[0];
      const src = positions[srcTool];
      const dst = positions[dstTool];
      if (src && dst) {
        ctx.beginPath();
        ctx.moveTo(src.x + 50, src.y);
        ctx.bezierCurveTo(src.x + 80, src.y, dst.x - 80, dst.y, dst.x - 50, dst.y);
        ctx.strokeStyle = "rgba(100, 100, 100, 0.3)";
        ctx.lineWidth = 1;
        ctx.stroke();
      }
    }
  }

  // Draw CWE trigger edges (dashed)
  for (const [cwe, tools] of Object.entries(CWE_TRIGGERS)) {
    for (const tool of tools) {
      const pos = positions[tool];
      if (!pos) continue;
      // Draw a marker to indicate CWE trigger
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(pos.x - 80, pos.y);
      ctx.lineTo(pos.x - 50, pos.y);
      ctx.strokeStyle = "#f59e0b88";
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.setLineDash([]);

      // CWE label
      ctx.fillStyle = "#f59e0b88";
      ctx.font = "9px monospace";
      ctx.textAlign = "right";
      ctx.fillText(cwe, pos.x - 84, pos.y + 3);
    }
  }

  // Draw nodes
  for (const [name, pos] of Object.entries(positions)) {
    const color = GROUP_COLORS[pos.group] || "#666";
    const isHighlighted = highlight === name || highlight === pos.group;
    const isInProfile = profileSet.has(name);
    const alpha = isInProfile ? 1 : 0.25;

    // Node box
    const boxW = 90;
    const boxH = 20;
    ctx.globalAlpha = alpha;
    ctx.fillStyle = isHighlighted ? color : `${color}40`;
    ctx.strokeStyle = isHighlighted ? color : `${color}80`;
    ctx.lineWidth = isHighlighted ? 2 : 1;
    ctx.beginPath();
    ctx.roundRect(pos.x - boxW / 2, pos.y - boxH / 2, boxW, boxH, 4);
    ctx.fill();
    ctx.stroke();

    // Label
    ctx.fillStyle = isHighlighted ? "#fff" : "var(--text, #eee)";
    ctx.font = `${isHighlighted ? "bold " : ""}10px system-ui, sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(name.length > 14 ? name.slice(0, 13) + "…" : name, pos.x, pos.y);
    ctx.globalAlpha = 1;
  }

  // Draw depth labels
  for (let d = 0; d <= maxDepth; d++) {
    const x = padding + d * colWidth + colWidth / 2;
    ctx.fillStyle = "#666";
    ctx.font = "11px system-ui";
    ctx.textAlign = "center";
    ctx.fillText(`Wave ${d}`, x, 20);
  }
}

export default function GraphPage() {
  const [activeTab, setActiveTab] = useState<TabKey>("2d");

  return (
    <main className="px-6 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Dependency Graph</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Tool pipeline visualization, 3D exploration &amp; site architecture mapping
        </p>
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-[var(--border)] mb-6">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.key
                ? "border-[var(--accent)] text-[var(--accent)]"
                : "border-transparent text-[var(--text-muted)] hover:text-[var(--text)]"
            }`}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === "2d" && <Pipeline2DView />}
      {activeTab === "3d" && <ToolGraph3D />}
      {activeTab === "site-map" && <SiteMap3D />}
    </main>
  );
}

function Pipeline2DView() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [highlight, setHighlight] = useState<string | null>(null);
  const [profile, setProfile] = useState("full");

  useEffect(() => {
    if (canvasRef.current) drawGraph(canvasRef.current, highlight, profile);
  }, [highlight, profile]);

  useEffect(() => {
    const onResize = () => {
      if (canvasRef.current) drawGraph(canvasRef.current, highlight, profile);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [highlight, profile]);

  const tools = getAllTools();
  const lightSet = new Set(LIGHT_TOOLS);
  const mediumSet = new Set(MEDIUM_TOOLS);
  const totalEdges = PARALLEL_GROUPS.reduce(
    (sum, g) => sum + g.dependsOn.length * g.tools.length, 0
  ) + Object.values(CWE_TRIGGERS).reduce((sum, arr) => sum + arr.length, 0);

  return (
    <div>
      <p className="text-xs text-[var(--text-muted)] mb-4">
        {tools.length} tools · {totalEdges} edges · {PARALLEL_GROUPS.length} groups · {Object.keys(CWE_TRIGGERS).length} CWE triggers
      </p>

      {/* Controls */}
      <div className="flex items-center gap-4 mb-4">
        <div className="flex items-center gap-2">
          <label className="text-sm text-[var(--text-muted)]">Profile filter:</label>
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
        <div className="flex items-center gap-2">
          <label className="text-sm text-[var(--text-muted)]">Highlight:</label>
          <select
            value={highlight || ""}
            onChange={(e) => setHighlight(e.target.value || null)}
            className="bg-[var(--card-bg)] border border-[var(--border)] text-sm rounded px-3 py-1.5 text-[var(--text)]"
          >
            <option value="">None</option>
            <optgroup label="Groups">
              {PARALLEL_GROUPS.map((g) => (
                <option key={g.name} value={g.name}>{g.name}</option>
              ))}
            </optgroup>
            <optgroup label="Tools">
              {tools.slice(0, 20).map((t) => (
                <option key={t.name} value={t.name}>{t.name}</option>
              ))}
            </optgroup>
          </select>
        </div>
      </div>

      {/* Graph canvas */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-2 mb-6">
        <canvas
          ref={canvasRef}
          className="w-full"
          style={{ height: "600px" }}
        />
      </div>

      {/* Legend */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
        <h3 className="font-semibold text-sm mb-3">Legend</h3>
        <div className="flex flex-wrap gap-4">
          {Object.entries(GROUP_COLORS).map(([name, color]) => (
            <div key={name} className="flex items-center gap-2 text-xs">
              <span className="w-3 h-3 rounded" style={{ background: color }} />
              <span className="text-[var(--text-muted)]">{name}</span>
            </div>
          ))}
          <div className="flex items-center gap-2 text-xs">
            <span className="w-8 border-t border-dashed border-yellow-500" />
            <span className="text-[var(--text-muted)]">CWE trigger</span>
          </div>
        </div>
      </div>

      {/* Execution waves table */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
        <h3 className="font-semibold text-sm mb-3">Execution Waves</h3>
        <p className="text-xs text-[var(--text-muted)] mb-3">
          Tools within the same wave run in parallel. Waves execute sequentially.
        </p>
        <div className="space-y-3">
          {(() => {
            // Compute depths
            const depths: Record<string, number> = {};
            const q: string[] = [];
            for (const g of PARALLEL_GROUPS) {
              if (g.dependsOn.length === 0) { depths[g.name] = 0; q.push(g.name); }
            }
            while (q.length > 0) {
              const c = q.shift()!;
              for (const g of PARALLEL_GROUPS) {
                if (g.dependsOn.includes(c)) {
                  const nd = depths[c] + 1;
                  if (depths[g.name] === undefined || nd > depths[g.name]) {
                    depths[g.name] = nd;
                    q.push(g.name);
                  }
                }
              }
            }
            const maxD = Math.max(...Object.values(depths), 0);
            return Array.from({ length: maxD + 1 }, (_, d) => {
              const waveGroups = PARALLEL_GROUPS.filter((g) => depths[g.name] === d);
              const waveTools = waveGroups.flatMap((g) => g.tools);
              const profileTools = profile === "light" ? waveTools.filter((t) => lightSet.has(t)) :
                                   profile === "medium" ? waveTools.filter((t) => mediumSet.has(t)) :
                                   waveTools;
              return (
                <div key={d}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-bold text-[var(--accent)]">Wave {d}</span>
                    <span className="text-xs text-[var(--text-muted)]">
                      {waveGroups.map((g) => g.name).join(", ")} — {profileTools.length} tools
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {profileTools.map((t) => {
                      const g = waveGroups.find((gg) => gg.tools.includes(t));
                      const color = GROUP_COLORS[g?.name || ""] || "#666";
                      return (
                        <span
                          key={t}
                          className="text-[10px] font-mono px-2 py-0.5 rounded"
                          style={{ background: `${color}20`, color }}
                        >
                          {t}
                        </span>
                      );
                    })}
                  </div>
                </div>
              );
            });
          })()}
        </div>
      </div>
    </div>
  );
}
