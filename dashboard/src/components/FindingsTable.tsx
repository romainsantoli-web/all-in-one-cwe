// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useMemo, Fragment } from "react";
import type { Finding } from "@/lib/types";
import SeverityBadge from "./SeverityBadge";
import AskAIButton from "./AskAIButton";
import { SEVERITY_ORDER } from "@/lib/types";

export default function FindingsTable({ findings }: { findings: Finding[] }) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [toolFilter, setToolFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [sortField, setSortField] = useState<"severity" | "cvss" | "tool">(
    "severity"
  );
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const tools = useMemo(
    () => [...new Set(findings.map((f) => f.tool))].sort(),
    [findings]
  );

  const filtered = useMemo(() => {
    let result = [...findings];

    // Filter
    if (severityFilter !== "all") {
      result = result.filter(
        (f) => (f.severity || "info").toLowerCase() === severityFilter
      );
    }
    if (toolFilter !== "all") {
      result = result.filter((f) => f.tool === toolFilter);
    }
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (f) =>
          (f.title || "").toLowerCase().includes(q) ||
          (f.cwe_id || f.cwe || "").toLowerCase().includes(q) ||
          (f.url || f.endpoint || "").toLowerCase().includes(q) ||
          (f.description || "").toLowerCase().includes(q)
      );
    }

    // Sort
    result.sort((a, b) => {
      let cmp = 0;
      if (sortField === "severity") {
        cmp =
          SEVERITY_ORDER.indexOf((a.severity || "info").toLowerCase()) -
          SEVERITY_ORDER.indexOf((b.severity || "info").toLowerCase());
      } else if (sortField === "cvss") {
        cmp = (b.cvss_score || 0) - (a.cvss_score || 0);
      } else {
        cmp = a.tool.localeCompare(b.tool);
      }
      return sortDir === "asc" ? cmp : -cmp;
    });

    return result;
  }, [findings, severityFilter, toolFilter, search, sortField, sortDir]);

  const toggleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  };

  return (
    <div>
      {/* Filters */}
      <div className="flex gap-3 p-4 border-b border-[var(--border)] flex-wrap">
        <input
          type="text"
          placeholder="Search findings..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="px-3 py-1.5 bg-[var(--bg)] border border-[var(--border)] rounded text-sm flex-1 min-w-[200px]"
        />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-1.5 bg-[var(--bg)] border border-[var(--border)] rounded text-sm"
        >
          <option value="all">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
        <select
          value={toolFilter}
          onChange={(e) => setToolFilter(e.target.value)}
          className="px-3 py-1.5 bg-[var(--bg)] border border-[var(--border)] rounded text-sm"
        >
          <option value="all">All tools</option>
          {tools.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <span className="text-[var(--text-muted)] text-sm self-center">
          {filtered.length} / {findings.length}
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border)] text-left text-[var(--text-muted)]">
              <th
                className="p-3 cursor-pointer hover:text-[var(--text)]"
                onClick={() => toggleSort("severity")}
              >
                Severity {sortField === "severity" && (sortDir === "asc" ? "↑" : "↓")}
              </th>
              <th className="p-3">Title</th>
              <th className="p-3">CWE</th>
              <th
                className="p-3 cursor-pointer hover:text-[var(--text)]"
                onClick={() => toggleSort("tool")}
              >
                Tool {sortField === "tool" && (sortDir === "asc" ? "↑" : "↓")}
              </th>
              <th
                className="p-3 cursor-pointer hover:text-[var(--text)]"
                onClick={() => toggleSort("cvss")}
              >
                CVSS {sortField === "cvss" && (sortDir === "asc" ? "↑" : "↓")}
              </th>
              <th className="p-3">URL</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f, i) => {
              const key = f.id || `${f.tool}-${i}`;
              const isExpanded = expandedId === key;
              return (
                <Fragment key={key}>
                  <tr
                    className="border-b border-[var(--border)] hover:bg-[var(--bg)] cursor-pointer"
                    onClick={() => setExpandedId(isExpanded ? null : key)}
                  >
                    <td className="p-3">
                      <SeverityBadge severity={f.severity || "info"} />
                    </td>
                    <td className="p-3 font-medium max-w-xs truncate">
                      {f.title || "Untitled"}
                    </td>
                    <td className="p-3 text-[var(--text-muted)]">
                      {f.cwe_id || f.cwe || "—"}
                    </td>
                    <td className="p-3 text-[var(--text-muted)]">{f.tool}</td>
                    <td className="p-3 font-mono">
                      {f.cvss_score ? f.cvss_score.toFixed(1) : "—"}
                    </td>
                    <td className="p-3 text-[var(--text-muted)] max-w-xs truncate">
                      {f.url || f.endpoint || "—"}
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr key={`${key}-detail`} className="bg-[var(--bg)]">
                      <td colSpan={6} className="p-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                          {f.description && (
                            <div>
                              <strong className="text-[var(--text-muted)]">
                                Description
                              </strong>
                              <p className="mt-1 whitespace-pre-wrap">
                                {f.description}
                              </p>
                            </div>
                          )}
                          {f.evidence && (
                            <div>
                              <strong className="text-[var(--text-muted)]">
                                Evidence
                              </strong>
                              <pre className="mt-1 bg-[var(--card-bg)] p-2 rounded text-xs overflow-x-auto">
                                {f.evidence}
                              </pre>
                            </div>
                          )}
                          {f.remediation && (
                            <div>
                              <strong className="text-[var(--text-muted)]">
                                Remediation
                              </strong>
                              <p className="mt-1 whitespace-pre-wrap">
                                {f.remediation}
                              </p>
                            </div>
                          )}
                          {f.ai_analysis && (
                            <div>
                              <strong className="text-[var(--text-muted)]">
                                AI Analysis
                              </strong>
                              <p className="mt-1 whitespace-pre-wrap">
                                {f.ai_analysis}
                              </p>
                            </div>
                          )}
                          <div className="flex gap-4 text-xs text-[var(--text-muted)]">
                            {f.cvss_vector && (
                              <span>CVSS: {f.cvss_vector}</span>
                            )}
                            {f.epss_score !== undefined && (
                              <span>
                                EPSS: {(f.epss_score * 100).toFixed(1)}%
                              </span>
                            )}
                            {f.composite_score !== undefined && (
                              <span>
                                Composite: {f.composite_score.toFixed(2)}
                              </span>
                            )}
                          </div>
                          <AskAIButton finding={f} />
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="p-8 text-center text-[var(--text-muted)]"
                >
                  No findings match your filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
