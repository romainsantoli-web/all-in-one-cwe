// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { loadPayloadStats } from "@/lib/data";

export const dynamic = "force-dynamic";

export default async function PayloadsPage() {
  const stats = await loadPayloadStats();

  if (!stats) {
    return (
      <main className="px-6 py-6">
        <h1 className="text-2xl font-bold mb-4">Payload Engine</h1>
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-8 text-center">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--text-dim)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" className="mx-auto mb-3">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <p className="text-[var(--text-muted)]">
            No payload stats found. Generate with:{" "}
            <code className="bg-[var(--bg)] px-2 py-1 rounded text-sm">
              make payload-stats
            </code>
          </p>
        </div>
      </main>
    );
  }

  const topCategories = stats.categories.slice(0, 20);
  const maxPayloads = topCategories[0]?.payloads || 1;

  return (
    <main className="px-6 py-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Payload Engine</h1>
          <p className="text-sm text-[var(--text-muted)] mt-0.5">
            PayloadsAllTheThings integration · {stats.patt_payloads.toLocaleString()} payloads indexed
          </p>
        </div>
        {stats.patt_stale && (
          <span className="px-3 py-1.5 bg-[var(--medium)]20 text-[var(--medium)] rounded-lg text-xs font-semibold">
            PATT outdated ({stats.patt_age_days}d old)
          </span>
        )}
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Total Payloads</div>
          <div className="text-2xl font-bold text-[var(--accent)]">
            {stats.patt_payloads.toLocaleString()}
          </div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Categories</div>
          <div className="text-2xl font-bold">{stats.patt_categories}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Payload Files</div>
          <div className="text-2xl font-bold">{stats.patt_files}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Curated Sets</div>
          <div className="text-2xl font-bold text-[var(--low)]">{stats.curated_files}</div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">PATT Age</div>
          <div className="text-2xl font-bold" style={{ color: stats.patt_stale ? "var(--medium)" : "var(--low)" }}>
            {stats.patt_age_days ?? "—"}d
          </div>
        </div>
        <div className="stat-card bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] mb-1">Commit</div>
          <div className="text-sm font-mono mt-1 text-[var(--text-muted)]">{stats.patt_commit_hash}</div>
          <div className="text-xs text-[var(--text-dim)] mt-0.5">{stats.patt_commit_date?.split(" ")[0]}</div>
        </div>
      </div>

      {/* CWE coverage matrix */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 mb-6">
        <h3 className="font-semibold text-sm mb-3">CWE Coverage</h3>
        <div className="flex flex-wrap gap-2">
          {stats.categories
            .filter((c) => c.cwe)
            .map((c) => (
              <span
                key={c.cwe + c.name}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs border border-[var(--border)]"
                title={`${c.name}: ${c.payloads.toLocaleString()} payloads`}
              >
                <span className="font-semibold text-[var(--info)]">{c.cwe}</span>
                <span className="text-[var(--text-muted)]">{c.payloads.toLocaleString()}</span>
              </span>
            ))}
        </div>
      </div>

      {/* Category breakdown table */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg">
        <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
          <h3 className="font-semibold text-sm">Category Breakdown</h3>
          <span className="text-xs text-[var(--text-muted)]">{stats.categories.length} categories</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-left text-[var(--text-muted)]">
                <th className="p-3">Category</th>
                <th className="p-3">CWE</th>
                <th className="p-3 text-right">Files</th>
                <th className="p-3 text-right">Payloads</th>
                <th className="p-3 w-1/3">Distribution</th>
              </tr>
            </thead>
            <tbody>
              {topCategories.map((cat) => (
                <tr key={cat.name} className="border-b border-[var(--border)] hover:bg-[var(--bg)]">
                  <td className="p-3 font-medium">{cat.name}</td>
                  <td className="p-3">
                    {cat.cwe ? (
                      <span className="text-[var(--info)] text-xs font-mono">{cat.cwe}</span>
                    ) : (
                      <span className="text-[var(--text-dim)]">—</span>
                    )}
                  </td>
                  <td className="p-3 text-right font-mono text-[var(--text-muted)]">{cat.files}</td>
                  <td className="p-3 text-right font-mono font-semibold">{cat.payloads.toLocaleString()}</td>
                  <td className="p-3">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-2 bg-[var(--bg)] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.max((cat.payloads / maxPayloads) * 100, 1)}%`,
                            backgroundColor: "var(--accent)",
                            opacity: 0.7,
                          }}
                        />
                      </div>
                      <span className="text-[10px] text-[var(--text-dim)] w-10 text-right">
                        {((cat.payloads / stats.patt_payloads) * 100).toFixed(1)}%
                      </span>
                    </div>
                  </td>
                </tr>
              ))}
              {stats.categories.length > 20 && (
                <tr>
                  <td colSpan={5} className="p-3 text-center text-[var(--text-muted)] text-xs">
                    +{stats.categories.length - 20} more categories with fewer payloads
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer */}
      <p className="text-xs text-[var(--text-dim)] mt-4">
        Last indexed: {stats.indexed_at ? new Date(stats.indexed_at).toLocaleString() : "—"}
      </p>
    </main>
  );
}
