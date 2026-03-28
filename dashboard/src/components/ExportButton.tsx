// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";
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

const DownloadIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  </svg>
);

interface ExportButtonProps {
  findings: Finding[];
  reportFilename?: string;
}

export default function ExportButton({ findings, reportFilename }: ExportButtonProps) {
  const [pdfLoading, setPdfLoading] = useState(false);

  async function downloadPDF() {
    if (!reportFilename) return;
    setPdfLoading(true);
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(reportFilename)}/pdf`);
      if (!res.ok) throw new Error("PDF generation failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = reportFilename.replace(/\.json$/i, ".pdf");
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("PDF download error:", e);
    } finally {
      setPdfLoading(false);
    }
  }

  const btnClass =
    "px-3 py-1.5 text-xs bg-[var(--card-bg)] border border-[var(--border)] rounded-lg hover:border-[var(--text-muted)] transition-colors flex items-center gap-1.5";

  return (
    <div className="flex gap-2">
      {reportFilename && (
        <button onClick={downloadPDF} disabled={pdfLoading} className={`${btnClass} ${pdfLoading ? "opacity-50 cursor-wait" : ""}`}>
          {pdfLoading ? (
            <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10" strokeDasharray="31.4 31.4" strokeDashoffset="10" /></svg>
          ) : (
            <DownloadIcon />
          )}
          PDF
        </button>
      )}
      <button
        onClick={() =>
          download(findingsToCSV(findings), "findings.csv", "text/csv")
        }
        className={btnClass}
      >
        <DownloadIcon />
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
        className={btnClass}
      >
        <DownloadIcon />
        JSON
      </button>
    </div>
  );
}
