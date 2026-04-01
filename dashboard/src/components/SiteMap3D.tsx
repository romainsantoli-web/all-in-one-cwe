// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import dynamic from "next/dynamic";

const ForceGraph3D = dynamic(() => import("react-force-graph-3d"), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-[600px] text-sm text-[var(--text-muted)]">
      Loading 3D engine…
    </div>
  ),
});

interface CrawlNode {
  id: string;
  url: string;
  type: "page" | "api" | "asset" | "external" | "form" | "subdomain";
  status?: number;
  tech?: string[];
  depth: number;
  source?: string;
}

interface CrawlLink {
  source: string;
  target: string;
  type: "link" | "redirect" | "form" | "api" | "asset" | "subdomain";
}

interface SiteGraphData {
  nodes: CrawlNode[];
  links: CrawlLink[];
  meta: {
    target: string;
    total_urls: number;
    crawl_depth: number;
    duration_s: number;
    tools_used?: string[];
    tools_status?: Record<string, string>;
  };
}

const NODE_COLORS: Record<CrawlNode["type"], string> = {
  page: "#2196F3",
  api: "#FF9800",
  asset: "#9E9E9E",
  external: "#9C27B0",
  form: "#F44336",
  subdomain: "#00BCD4",
};

const LINK_COLORS: Record<CrawlLink["type"], string> = {
  link: "rgba(100,180,255,0.3)",
  redirect: "rgba(255,152,0,0.5)",
  form: "rgba(244,67,54,0.4)",
  api: "rgba(255,152,0,0.4)",
  asset: "rgba(158,158,158,0.15)",
  subdomain: "rgba(0,188,212,0.4)",
};

type CrawlStatus = "idle" | "starting" | "running" | "completed" | "error";

interface CachedResult {
  job_id: string;
  target: string;
  total_urls: number;
}

export default function SiteMap3D() {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  // Crawl state
  const [target, setTarget] = useState("");
  const [depth, setDepth] = useState(3);
  const [status, setStatus] = useState<CrawlStatus>("idle");
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [graphData, setGraphData] = useState<SiteGraphData | null>(null);
  const [cachedResults, setCachedResults] = useState<CachedResult[]>([]);

  // Display options
  const [showAssets, setShowAssets] = useState(false);
  const [showExternal, setShowExternal] = useState(true);
  const [showSubdomains, setShowSubdomains] = useState(true);
  const [highlight, setHighlight] = useState<string | null>(null);
  const [toolStatus, setToolStatus] = useState<Record<string, string>>({});
  const [progress, setProgress] = useState("");

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Load cached results on mount
  useEffect(() => {
    fetch("/api/graph/site-map")
      .then((r) => r.json())
      .then((data) => {
        if (data.results) setCachedResults(data.results);
      })
      .catch(() => {});
  }, []);

  // Measure container
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

  // Cleanup poll on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const startCrawl = async () => {
    if (!target) return;
    setError("");
    setStatus("starting");
    setGraphData(null);

    try {
      const res = await fetch("/api/graph/site-map", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, depth, rate_limit: 20 }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      setJobId(data.job_id);
      setStatus("running");

      // Start polling
      pollRef.current = setInterval(async () => {
        try {
          const pollRes = await fetch(`/api/graph/site-map?job_id=${data.job_id}`);
          const pollData = await pollRes.json();

          if (pollData.status === "completed") {
            if (pollRef.current) clearInterval(pollRef.current);
            setGraphData(pollData);
            setStatus("completed");
            setToolStatus(pollData.meta?.tools_status || {});
          } else if (pollData.status === "running") {
            if (pollData.tool_status) setToolStatus(pollData.tool_status);
            if (pollData.progress) setProgress(pollData.progress);
          } else {
            if (pollRef.current) clearInterval(pollRef.current);
            setStatus("error");
            setError(pollData.error || "Crawl failed");
          }
        } catch {
          // Network error — keep polling
        }
      }, 3000);
    } catch (err) {
      setStatus("error");
      setError((err as Error).message);
    }
  };

  const loadCached = async (cachedJobId: string) => {
    setStatus("running");
    setError("");
    try {
      const res = await fetch(`/api/graph/site-map?job_id=${cachedJobId}`);
      const data = await res.json();
      if (data.status === "completed") {
        setGraphData(data);
        setStatus("completed");
        setTarget(data.meta?.target || "");
      } else {
        setStatus("error");
        setError("Results not available");
      }
    } catch {
      setStatus("error");
      setError("Failed to load");
    }
  };

  // Filtered graph data
  const filteredData = useMemo(() => {
    if (!graphData) return { nodes: [], links: [] };

    const filteredNodes = graphData.nodes.filter((n) => {
      if (!showAssets && n.type === "asset") return false;
      if (!showExternal && n.type === "external") return false;
      if (!showSubdomains && n.type === "subdomain") return false;
      return true;
    });

    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    const filteredLinks = graphData.links.filter(
      (l) => nodeIds.has(l.source as string) && nodeIds.has(l.target as string),
    );

    return { nodes: filteredNodes, links: filteredLinks };
  }, [graphData, showAssets, showExternal, showSubdomains]);

  const handleNodeClick = useCallback((node: any) => {
    setHighlight((prev) => (prev === node.id ? null : (node.id as string)));
  }, []);

  return (
    <div>
      {/* Input bar */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-4">
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label className="block text-xs text-[var(--text-muted)] mb-1">Target URL</label>
            <input
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="w-full bg-[var(--bg)] border border-[var(--border)] rounded px-3 py-2 text-sm text-[var(--text)] placeholder:text-[var(--text-muted)]"
              disabled={status === "running"}
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Depth</label>
            <select
              value={depth}
              onChange={(e) => setDepth(Number(e.target.value))}
              className="bg-[var(--bg)] border border-[var(--border)] text-sm rounded px-3 py-2 text-[var(--text)]"
              disabled={status === "running"}
            >
              {[1, 2, 3, 4, 5].map((d) => (
                <option key={d} value={d}>Depth {d}</option>
              ))}
            </select>
          </div>
          <button
            onClick={startCrawl}
            disabled={!target || status === "running" || status === "starting"}
            className="px-4 py-2 text-sm bg-[var(--accent)] text-white rounded hover:opacity-90 disabled:opacity-50 whitespace-nowrap"
          >
            {status === "running" || status === "starting" ? (
              <span className="flex items-center gap-2">
                <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Crawling…
              </span>
            ) : (
              "🕸️ Map Site"
            )}
          </button>
        </div>

        {error && (
          <p className="text-xs text-red-400 mt-2">{error}</p>
        )}

        {/* Cached results */}
        {cachedResults.length > 0 && status === "idle" && (
          <div className="mt-3 pt-3 border-t border-[var(--border)]">
            <p className="text-xs text-[var(--text-muted)] mb-2">Previous scans:</p>
            <div className="flex flex-wrap gap-2">
              {cachedResults.map((r) => (
                <button
                  key={r.job_id}
                  onClick={() => loadCached(r.job_id)}
                  className="text-xs px-2 py-1 bg-[var(--border)] rounded hover:bg-[var(--accent)]/10"
                >
                  {new URL(r.target).hostname} ({r.total_urls} URLs)
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Status running indicator */}
      {status === "running" && (
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-6 mb-4 text-center">
          <div className="inline-block w-8 h-8 border-3 border-[var(--accent)] border-t-transparent rounded-full animate-spin mb-3" />
          <p className="text-sm text-[var(--text-muted)]">
            Mapping <span className="text-[var(--text)] font-mono">{target}</span> at depth {depth}…
          </p>
          {progress && <p className="text-xs text-[var(--accent)] mt-1">{progress}</p>}
          {Object.keys(toolStatus).length > 0 && (
            <div className="flex justify-center gap-4 mt-3">
              {Object.entries(toolStatus).map(([tool, st]) => (
                <span key={tool} className="flex items-center gap-1.5 text-xs">
                  <span className={`w-2 h-2 rounded-full ${st === "running" ? "bg-yellow-400 animate-pulse" : st === "done" ? "bg-green-400" : st === "failed" ? "bg-red-400" : "bg-gray-500"}`} />
                  <span className="text-[var(--text-muted)]">{tool}</span>
                </span>
              ))}
            </div>
          )}
          <p className="text-xs text-[var(--text-muted)] mt-2">This may take 30s to 3 minutes.</p>
        </div>
      )}

      {/* Graph */}
      {graphData && status === "completed" && (
        <>
          {/* Stats bar */}
          <div className="flex items-center gap-4 mb-4 flex-wrap">
            <span className="text-xs text-[var(--text-muted)]">
              {graphData.meta.total_urls} URLs · {graphData.links.length} links · depth {graphData.meta.crawl_depth} · {graphData.meta.duration_s}s
              {graphData.meta.tools_used && graphData.meta.tools_used.length > 0 && (
                <> · tools: {graphData.meta.tools_used.join(", ")}</>
              )}
            </span>
            <label className="flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
              <input type="checkbox" checked={showAssets} onChange={(e) => setShowAssets(e.target.checked)} />
              Assets
            </label>
            <label className="flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
              <input type="checkbox" checked={showExternal} onChange={(e) => setShowExternal(e.target.checked)} />
              External
            </label>
            <label className="flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
              <input type="checkbox" checked={showSubdomains} onChange={(e) => setShowSubdomains(e.target.checked)} />
              Subdomains
            </label>
            {highlight && (
              <span className="text-xs text-[var(--accent)] bg-[var(--accent)]/10 px-2 py-1 rounded">
                {filteredData.nodes.find((n) => n.id === highlight)?.url || highlight}
                <button onClick={() => setHighlight(null)} className="ml-2 text-[var(--text-muted)]">✕</button>
              </span>
            )}
          </div>

          {/* 3D Visualization */}
          <div
            ref={containerRef}
            className="bg-[#0a0a0f] border border-[var(--border)] rounded-lg overflow-hidden"
            style={{ height: 600 }}
          >
            <ForceGraph3D
              width={dimensions.width}
              height={dimensions.height}
              graphData={filteredData}
              nodeLabel={(node: any) => {
                const parts = [node.url];
                if (node.status) parts.push(`HTTP ${node.status}`);
                if (node.tech?.length) parts.push(`Tech: ${node.tech.join(", ")}`);
                return parts.join("\n");
              }}
              nodeColor={(node: any) => {
                if (highlight && node.id !== highlight) {
                  return `${NODE_COLORS[node.type as keyof typeof NODE_COLORS]}33`;
                }
                return NODE_COLORS[node.type as keyof typeof NODE_COLORS] || "#666";
              }}
              nodeVal={(node: any) => {
                if (node.type === "page") return 4;
                if (node.type === "api") return 5;
                if (node.type === "form") return 4;
                if (node.type === "external") return 2;
                if (node.type === "subdomain") return 3;
                return 1;
              }}
              nodeOpacity={0.9}
              linkColor={(link: any) => LINK_COLORS[link.type as keyof typeof LINK_COLORS] || "rgba(100,100,100,0.2)"}
              linkWidth={0.5}
              linkDirectionalParticles={1}
              linkDirectionalParticleSpeed={0.003}
              onNodeClick={handleNodeClick}
              backgroundColor="#0a0a0f"
              showNavInfo={false}
            />
          </div>

          {/* Legend */}
          <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mt-4">
            <h3 className="font-semibold text-sm mb-3">Legend</h3>
            <div className="flex flex-wrap gap-4">
              {Object.entries(NODE_COLORS).map(([type, color]) => (
                <div key={type} className="flex items-center gap-2 text-xs">
                  <span className="w-3 h-3 rounded-full" style={{ background: color }} />
                  <span className="text-[var(--text-muted)] capitalize">{type}</span>
                </div>
              ))}
            </div>
            <p className="text-xs text-[var(--text-muted)] mt-2">
              Node size reflects type importance. Click a node for details. Drag to rotate, scroll to zoom.
            </p>
          </div>
        </>
      )}

      {/* Empty state */}
      {status === "idle" && !graphData && (
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-12 text-center">
          <div className="text-4xl mb-3">🌐</div>
          <h3 className="font-semibold mb-1">Site Architecture Mapper</h3>
          <p className="text-sm text-[var(--text-muted)] max-w-md mx-auto">
            Enter a target URL to map its architecture using multiple tools:
            <strong> katana</strong> (JS-aware crawling),
            <strong> httpx</strong> (HTTP probing + tech detection),
            <strong> subfinder</strong> (subdomain enumeration).
            Results merge into an interactive 3D graph.
          </p>
          <p className="text-xs text-[var(--text-muted)] mt-3">
            Tools auto-detected from PATH. Install via: <code className="bg-[var(--border)] px-1 rounded">brew install katana httpx subfinder</code>
          </p>
        </div>
      )}
    </div>
  );
}
