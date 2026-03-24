// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import type { Finding } from "@/lib/types";

function findingsToCSV(findings: Finding[]): string {
  const headers = [
    "severity",
    "title",
    "cwe",
    "tool",
    "cvss_score",
    "epss_score",
    "url",
    "description",
    "remediation",
  ];
  const escape = (v: string) => {
    if (v.includes(",") || v.includes('"') || v.includes("\n")) {
      return `"${v.replace(/"/g, '""')}"`;
    }
    return v;
  };
  const rows = findings.map((f) =>
    [
      f.severity || "",
      f.title || "",
      f.cwe_id || f.cwe || "",
      f.tool || "",
      f.cvss_score?.toString() || "",
      f.epss_score?.toString() || "",
      f.url || f.endpoint || "",
      f.description || "",
      f.remediation || "",
    ]
      .map(escape)
      .join(",")
  );
  return [headers.join(","), ...rows].join("\n");
}

function download(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ExportButton({ findings }: { findings: Finding[] }) {
  return (
    <div className="flex gap-2">
      <button
        onClick={() =>
          download(findingsToCSV(findings), "findings.csv", "text/csv")
        }
        className="px-3 py-1.5 text-xs bg-[var(--card-bg)] border border-[var(--border)] rounded-lg hover:border-[var(--text-muted)] transition-colors flex items-center gap-1.5"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
        CSV
      </button>
      <button
        onClick={() =>
          download(
            JSON.stringify(findings, null, 2),
            "findings.json",
            "application/json"
          )
        }
        className="px-3 py-1.5 text-xs bg-[var(--card-bg)] border border-[var(--border)] rounded-lg hover:border-[var(--text-muted)] transition-colors flex items-center gap-1.5"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </svg>
        JSON
      </button>
    </div>
  );
}
