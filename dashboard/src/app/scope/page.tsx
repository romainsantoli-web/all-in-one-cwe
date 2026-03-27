// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { readFile } from "fs/promises";
import { join } from "path";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";

interface ScopeTarget {
  url: string;
  type: string;
  asset_value: string;
}

interface ScopeData {
  name: string;
  targets: ScopeTarget[];
  outOfScope: string[];
  qualifyingVulns: string[];
  nonQualifyingVulns: string[];
  rules: string[];
  raw: string;
  file: string;
}

async function loadScope(): Promise<ScopeData | null> {
  const candidates = [
    "configs/scope-example.yaml",
    "scope.yaml",
    "scope.json",
    "configs/scope.yaml",
    "configs/scope.json",
  ];

  for (const candidate of candidates) {
    try {
      const raw = await readFile(join(PROJECT_ROOT, candidate), "utf-8");

      // Simple YAML parsing for known fields
      const targets: ScopeTarget[] = [];
      const outOfScope: string[] = [];
      const qualifyingVulns: string[] = [];
      let name = "";

      // Extract name
      const nameMatch = raw.match(/^name:\s*"?([^"\n]+)"?/m);
      if (nameMatch) name = nameMatch[1].trim();

      // Extract targets block
      const targetsBlock = raw.match(/targets:\n((?:\s+-[^\n]+\n?|\s+\w+:[^\n]+\n?)*)/);
      if (targetsBlock) {
        const urlMatches = [...targetsBlock[1].matchAll(/url:\s*"?([^"\n]+)"?/g)];
        const typeMatches = [...targetsBlock[1].matchAll(/type:\s*(\w+)/g)];
        const valueMatches = [...targetsBlock[1].matchAll(/asset_value:\s*(\w+)/g)];
        for (let i = 0; i < urlMatches.length; i++) {
          targets.push({
            url: urlMatches[i][1].trim(),
            type: typeMatches[i]?.[1] || "web",
            asset_value: valueMatches[i]?.[1] || "medium",
          });
        }
      }

      // Extract out_of_scope
      const oosBlock = raw.match(/out_of_scope:\n((?:\s+-[^\n]+\n?)*)/);
      if (oosBlock) {
        const lines = [...oosBlock[1].matchAll(/\s+-\s*"?([^"\n]+)"?/g)];
        for (const m of lines) outOfScope.push(m[1].trim());
      }

      // Extract qualifying_vulns
      const qvBlock = raw.match(/qualifying_vulns:\n((?:\s+-[^\n]+\n?)*)/);
      if (qvBlock) {
        const lines = [...qvBlock[1].matchAll(/\s+-\s*"?([^"\n]+)"?/g)];
        for (const m of lines) qualifyingVulns.push(m[1].trim());
      }

      return {
        name,
        targets,
        outOfScope,
        qualifyingVulns,
        nonQualifyingVulns: [],
        rules: [],
        raw,
        file: candidate,
      };
    } catch { /* try next */ }
  }
  return null;
}

const ASSET_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

export default async function ScopePage() {
  const scope = await loadScope();

  return (
    <main className="px-6 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Scope</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Target scope management — in-scope targets, exclusions, qualifying vulnerabilities
        </p>
      </div>

      {!scope ? (
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-8 text-center">
          <p className="text-lg font-medium mb-2">No scope file found</p>
          <p className="text-sm text-[var(--text-muted)] mb-4">
            Create a scope file to define your target boundaries.
          </p>
          <code className="block bg-[var(--bg)] rounded p-4 text-xs font-mono text-left max-w-lg mx-auto text-[var(--text-muted)]">
            {`# configs/scope.yaml\nname: "My Audit"\ntargets:\n  - url: "https://app.example.com"\n    type: web\n    asset_value: high\nout_of_scope:\n  - "*.internal.example.com"`}
          </code>
        </div>
      ) : (
        <>
          {/* Scope Header */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
              <div className="text-xs text-[var(--text-muted)] mb-1">Program</div>
              <div className="text-sm font-bold">{scope.name || "Unnamed"}</div>
            </div>
            <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
              <div className="text-xs text-green-400 mb-1">In-Scope Targets</div>
              <div className="text-2xl font-bold text-green-400">{scope.targets.length}</div>
            </div>
            <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
              <div className="text-xs text-red-400 mb-1">Out-of-Scope</div>
              <div className="text-2xl font-bold text-red-400">{scope.outOfScope.length}</div>
            </div>
            <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
              <div className="text-xs text-[var(--text-muted)] mb-1">Source</div>
              <div className="text-xs font-mono">{scope.file}</div>
            </div>
          </div>

          {/* Targets table */}
          <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
            <h3 className="font-semibold text-sm mb-3">In-Scope Targets</h3>
            {scope.targets.length === 0 ? (
              <p className="text-sm text-[var(--text-muted)]">No targets defined.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-[var(--text-muted)] text-xs border-b border-[var(--border)]">
                      <th className="text-left py-2 px-3">URL</th>
                      <th className="text-left py-2 px-3">Type</th>
                      <th className="text-left py-2 px-3">Asset Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scope.targets.map((t, i) => (
                      <tr key={i} className="border-b border-[var(--border)]/30 hover:bg-[var(--bg)]">
                        <td className="py-2 px-3 font-mono text-xs">{t.url}</td>
                        <td className="py-2 px-3">
                          <span className="text-xs bg-blue-900/30 text-blue-400 px-2 py-0.5 rounded">
                            {t.type}
                          </span>
                        </td>
                        <td className="py-2 px-3">
                          <span
                            className="text-xs px-2 py-0.5 rounded font-medium"
                            style={{
                              color: ASSET_COLOR[t.asset_value] || "#888",
                              background: `${ASSET_COLOR[t.asset_value] || "#888"}20`,
                            }}
                          >
                            {t.asset_value}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Out of scope */}
          {scope.outOfScope.length > 0 && (
            <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
              <h3 className="font-semibold text-sm mb-3 text-red-400">Out-of-Scope</h3>
              <div className="space-y-1">
                {scope.outOfScope.map((item, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm bg-[var(--bg)] rounded px-3 py-2">
                    <span className="text-red-400">✕</span>
                    <span className="font-mono text-xs text-[var(--text-muted)]">{item}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Qualifying Vulnerabilities */}
          {scope.qualifyingVulns.length > 0 && (
            <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
              <h3 className="font-semibold text-sm mb-3">Qualifying Vulnerabilities</h3>
              <div className="flex flex-wrap gap-2">
                {scope.qualifyingVulns.map((v, i) => (
                  <span key={i} className="text-xs bg-green-900/30 text-green-400 px-2 py-1 rounded">
                    {v}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Raw config */}
          <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
            <h3 className="font-semibold text-sm mb-3">
              Raw Configuration
              <span className="text-[var(--text-dim)] font-normal ml-2">{scope.file}</span>
            </h3>
            <pre className="text-xs font-mono bg-[var(--bg)] rounded p-4 overflow-x-auto max-h-[500px] overflow-y-auto text-[var(--text-muted)]">
              {scope.raw}
            </pre>
          </div>
        </>
      )}
    </main>
  );
}
