// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { readFile, readdir, stat } from "fs/promises";
import { join } from "path";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

interface MemoryStats {
  available: boolean;
  mode: string;
  recordCount: number;
  lastIngest: string | null;
  reportsIngested: string[];
}

async function getMemoryStats(): Promise<MemoryStats> {
  const stats: MemoryStats = {
    available: false,
    mode: "unknown",
    recordCount: 0,
    lastIngest: null,
    reportsIngested: [],
  };

  // Check if memory-os-ai data directory exists
  const memoryDirs = [
    join(PROJECT_ROOT, ".memory"),
    join(PROJECT_ROOT, "memory_data"),
  ];

  for (const dir of memoryDirs) {
    try {
      const files = await readdir(dir);
      stats.available = true;
      stats.mode = "library";
      stats.recordCount = files.filter((f) => f.endsWith(".json")).length;

      // Find latest modified file for last ingest time
      let latestMtime = 0;
      for (const f of files) {
        try {
          const s = await stat(join(dir, f));
          if (s.mtimeMs > latestMtime) {
            latestMtime = s.mtimeMs;
          }
        } catch { /* skip */ }
      }
      if (latestMtime > 0) {
        stats.lastIngest = new Date(latestMtime).toISOString();
      }
      break;
    } catch { /* try next */ }
  }

  // Check reports that have been ingested (look for processing markers)
  try {
    const reportDir = process.env.REPORTS_DIR || join(PROJECT_ROOT, "reports");
    const files = await readdir(reportDir);
    stats.reportsIngested = files
      .filter((f) => f.startsWith("unified-report") && f.endsWith(".json"))
      .sort()
      .reverse();
  } catch { /* skip */ }

  return stats;
}

export default async function MemoryPage() {
  const stats = await getMemoryStats();

  return (
    <main className="px-6 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Memory OS</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Hebbian memory system — stores and recalls past scan findings for AI context
        </p>
      </div>

      {/* Status KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Status</div>
          <div className={`text-lg font-bold ${stats.available ? "text-green-400" : "text-red-400"}`}>
            {stats.available ? "Connected" : "Offline"}
          </div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Mode</div>
          <div className="text-lg font-bold">{stats.mode}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Records</div>
          <div className="text-2xl font-bold">{stats.recordCount}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Reports Available</div>
          <div className="text-2xl font-bold">{stats.reportsIngested.length}</div>
        </div>
      </div>

      {/* Architecture */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5 mb-6">
        <h3 className="font-semibold text-sm mb-4">Architecture</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[var(--bg)] rounded-lg p-4">
            <h4 className="text-sm font-medium mb-2 text-green-400">📚 Library Mode</h4>
            <p className="text-xs text-[var(--text-muted)] mb-2">
              Direct Python import — same process, lowest latency.
            </p>
            <div className="text-[10px] font-mono text-[var(--text-dim)]">
              import memory_os_ai<br />
              memory = HebbianMemory()
            </div>
          </div>
          <div className="bg-[var(--bg)] rounded-lg p-4">
            <h4 className="text-sm font-medium mb-2 text-blue-400">🌐 HTTP Mode</h4>
            <p className="text-xs text-[var(--text-muted)] mb-2">
              MCP SSE server on port 8765 — for Docker / remote setups.
            </p>
            <div className="text-[10px] font-mono text-[var(--text-dim)]">
              POST http://localhost:8765/mcp<br />
              {`{"method": "tools/call", "params": {...}}`}
            </div>
          </div>
        </div>
      </div>

      {/* Features */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5 mb-6">
        <h3 className="font-semibold text-sm mb-4">Capabilities</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { icon: "📥", title: "Report Ingest", desc: "Auto-ingest findings from scan reports into memory" },
            { icon: "🔍", title: "Semantic Search", desc: "Find similar past findings using vector similarity" },
            { icon: "🧠", title: "AI Context", desc: "Provide historical context to LLM during analysis" },
            { icon: "📊", title: "Remediation Tracking", desc: "Track resolution status of past vulnerabilities" },
            { icon: "🔗", title: "CWE Correlation", desc: "Link findings by CWE across different scan runs" },
            { icon: "⚡", title: "Hebbian Learning", desc: "Adaptive weights — frequently seen patterns rise" },
            { icon: "🗑️", title: "Deduplication", desc: "Stable hash keys prevent duplicate memories" },
            { icon: "📈", title: "Drift Detection", desc: "Detect when vulnerability patterns shift over time" },
          ].map((cap) => (
            <div key={cap.title} className="bg-[var(--bg)] rounded-lg p-3">
              <div className="text-lg mb-1">{cap.icon}</div>
              <div className="text-sm font-medium mb-1">{cap.title}</div>
              <div className="text-[11px] text-[var(--text-muted)]">{cap.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Reports available for ingest */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5">
        <h3 className="font-semibold text-sm mb-3">Available Reports</h3>
        {stats.reportsIngested.length === 0 ? (
          <p className="text-sm text-[var(--text-muted)]">No unified reports found. Run a scan first.</p>
        ) : (
          <div className="space-y-2">
            {stats.reportsIngested.map((r) => (
              <div
                key={r}
                className="flex items-center justify-between bg-[var(--bg)] rounded px-3 py-2"
              >
                <span className="font-mono text-xs text-[var(--text)]">{r}</span>
                <span className="text-[10px] text-[var(--text-muted)]">
                  {r.match(/(\d{8}-\d{6})/)?.[1]?.replace(/(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})/, "$1-$2-$3 $4:$5:$6") || ""}
                </span>
              </div>
            ))}
          </div>
        )}
        {stats.lastIngest && (
          <p className="text-xs text-[var(--text-dim)] mt-3">
            Last memory update: {new Date(stats.lastIngest).toLocaleString()}
          </p>
        )}
      </div>
    </main>
  );
}
