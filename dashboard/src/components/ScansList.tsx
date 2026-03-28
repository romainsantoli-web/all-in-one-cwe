// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import SeverityBadge from "@/components/SeverityBadge";
import ScanActions from "@/components/ScanActions";
import { SEVERITY_ORDER } from "@/lib/types";

export interface ScanItem {
  filename: string;
  target: string;
  date: string;
  total: number;
  profile?: string;
  tool_count?: number;
  severityCounts: Record<string, number>;
}

const POLL_INTERVAL = 5_000;

export default function ScansList({ initialScans }: { initialScans: ScanItem[] }) {
  const [scans, setScans] = useState(initialScans);

  const refresh = useCallback(async () => {
    try {
      const res = await fetch("/api/scans");
      if (!res.ok) return;
      const data: ScanItem[] = await res.json();
      setScans(data);
    } catch { /* ignore network errors during poll */ }
  }, []);

  useEffect(() => {
    const id = setInterval(refresh, POLL_INTERVAL);
    return () => clearInterval(id);
  }, [refresh]);

  function handleDeleted(filename: string) {
    setScans((prev) => prev.filter((s) => s.filename !== filename));
  }

  function handleRenamed(oldName: string, newName: string) {
    setScans((prev) =>
      prev.map((s) => (s.filename === oldName ? { ...s, filename: newName } : s))
    );
  }

  if (scans.length === 0) {
    return (
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-8 text-center">
        <p className="text-[var(--text-muted)]">
          No scan reports found. Run a scan first.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {scans.map((scan) => (
        <div
          key={scan.filename}
          className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 hover:border-[var(--border-hover)] transition-all"
        >
          <Link
            href={`/scans/${encodeURIComponent(scan.filename)}`}
            className="block"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-3">
                <span className="font-semibold">{scan.target}</span>
                {scan.profile && (
                  <span className="text-xs px-2 py-0.5 bg-[var(--accent)]20 text-[var(--accent)] rounded font-medium">
                    {scan.profile}
                  </span>
                )}
              </div>
              <span className="text-xs text-[var(--text-muted)]">{scan.date}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex gap-2">
                {SEVERITY_ORDER.map(
                  (sev) =>
                    (scan.severityCounts[sev] || 0) > 0 && (
                      <span key={sev} className="flex items-center gap-1">
                        <SeverityBadge severity={sev} />
                        <span className="text-xs font-mono">
                          {scan.severityCounts[sev]}
                        </span>
                      </span>
                    )
                )}
              </div>
              <span className="text-xs text-[var(--text-dim)]">
                {scan.total} findings
                {scan.tool_count ? ` · ${scan.tool_count} tools` : ""}
              </span>
            </div>
          </Link>
          <div className="flex items-center justify-between mt-3 pt-3 border-t border-[var(--border)]">
            <span className="text-[10px] font-mono text-[var(--text-dim)]">
              {scan.filename}
            </span>
            <ScanActions
              filename={scan.filename}
              onDeleted={handleDeleted}
              onRenamed={handleRenamed}
            />
          </div>
        </div>
      ))}
    </div>
  );
}
