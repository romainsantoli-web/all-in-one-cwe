// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import SeverityBadge from "@/components/SeverityBadge";
import type { Finding, ScanReport } from "@/lib/types";
import { SEVERITY_ORDER, SEVERITY_COLORS } from "@/lib/types";

export default function ComparePage() {
  const [files, setFiles] = useState<string[]>([]);
  const [scanA, setScanA] = useState<string>("");
  const [scanB, setScanB] = useState<string>("");
  const [reportA, setReportA] = useState<ScanReport | null>(null);
  const [reportB, setReportB] = useState<ScanReport | null>(null);

  // Load file list on mount
  useEffect(() => {
    fetch("/api/scans")
      .then((r) => r.json())
      .then((data: string[]) => {
        setFiles(data);
        if (data.length >= 2) {
          setScanA(data[0]);
          setScanB(data[1]);
        }
      })
      .catch(() => setFiles([]));
  }, []);

  // Load reports when selection changes
  useEffect(() => {
    if (scanA) {
      fetch(`/api/scans/${encodeURIComponent(scanA)}`)
        .then((r) => r.json())
        .then(setReportA)
        .catch(() => setReportA(null));
    }
  }, [scanA]);

  useEffect(() => {
    if (scanB) {
      fetch(`/api/scans/${encodeURIComponent(scanB)}`)
        .then((r) => r.json())
        .then(setReportB)
        .catch(() => setReportB(null));
    }
  }, [scanB]);

  const diff = useMemo(() => {
    if (!reportA || !reportB) return null;

    const key = (f: Finding) =>
      `${f.tool}:${f.cwe_id || f.cwe || ""}:${f.url || f.endpoint || ""}:${f.title || ""}`;

    const keysA = new Set(reportA.findings.map(key));
    const keysB = new Set(reportB.findings.map(key));

    const newFindings = reportB.findings.filter((f) => !keysA.has(key(f)));
    const fixedFindings = reportA.findings.filter((f) => !keysB.has(key(f)));
    const unchanged = reportB.findings.filter((f) => keysA.has(key(f)));

    return { newFindings, fixedFindings, unchanged };
  }, [reportA, reportB]);

  return (
    <main className="max-w-6xl mx-auto px-4 py-8">
      <div className="flex items-center gap-4 mb-6">
        <Link
          href="/"
          className="text-[var(--text-muted)] hover:text-[var(--text)]"
        >
          ← Dashboard
        </Link>
        <h1 className="text-2xl font-bold">Compare Scans</h1>
      </div>

      {/* Selectors */}
      <div className="flex gap-4 mb-8 flex-wrap">
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">
            Previous scan (A)
          </label>
          <select
            value={scanA}
            onChange={(e) => setScanA(e.target.value)}
            className="px-3 py-2 bg-[var(--card-bg)] border border-[var(--border)] rounded text-sm"
          >
            <option value="">Select...</option>
            {files.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        </div>
        <div className="self-end text-[var(--text-muted)]">→</div>
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">
            Current scan (B)
          </label>
          <select
            value={scanB}
            onChange={(e) => setScanB(e.target.value)}
            className="px-3 py-2 bg-[var(--card-bg)] border border-[var(--border)] rounded text-sm"
          >
            <option value="">Select...</option>
            {files.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        </div>
      </div>

      {diff && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-3 gap-4 mb-8">
            <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-[var(--critical)]">
                +{diff.newFindings.length}
              </div>
              <div className="text-sm text-[var(--text-muted)]">
                New findings
              </div>
            </div>
            <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-[var(--low)]">
                -{diff.fixedFindings.length}
              </div>
              <div className="text-sm text-[var(--text-muted)]">Fixed</div>
            </div>
            <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 text-center">
              <div className="text-3xl font-bold text-[var(--text-muted)]">
                {diff.unchanged.length}
              </div>
              <div className="text-sm text-[var(--text-muted)]">Unchanged</div>
            </div>
          </div>

          {/* New findings */}
          {diff.newFindings.length > 0 && (
            <div className="mb-6">
              <h2 className="text-lg font-semibold mb-3 text-[var(--critical)]">
                New Findings (+{diff.newFindings.length})
              </h2>
              <div className="space-y-2">
                {diff.newFindings.map((f, i) => (
                  <div
                    key={i}
                    className="bg-[var(--card-bg)] border border-[var(--border)] rounded p-3 flex items-center gap-3"
                  >
                    <SeverityBadge severity={f.severity || "info"} />
                    <span className="font-medium flex-1">{f.title}</span>
                    <span className="text-xs text-[var(--text-muted)]">
                      {f.tool}
                    </span>
                    <span className="text-xs text-[var(--text-muted)]">
                      {f.cwe_id || f.cwe || ""}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Fixed findings */}
          {diff.fixedFindings.length > 0 && (
            <div>
              <h2 className="text-lg font-semibold mb-3 text-[var(--low)]">
                Fixed ({diff.fixedFindings.length})
              </h2>
              <div className="space-y-2">
                {diff.fixedFindings.map((f, i) => (
                  <div
                    key={i}
                    className="bg-[var(--card-bg)] border border-[var(--border)] rounded p-3 flex items-center gap-3 opacity-60"
                  >
                    <SeverityBadge severity={f.severity || "info"} />
                    <span className="font-medium flex-1 line-through">
                      {f.title}
                    </span>
                    <span className="text-xs text-[var(--text-muted)]">
                      {f.tool}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {!diff && scanA && scanB && (
        <p className="text-[var(--text-muted)]">Loading scan data...</p>
      )}
      {files.length < 2 && (
        <p className="text-[var(--text-muted)]">
          Need at least 2 scan reports to compare.
        </p>
      )}
    </main>
  );
}
