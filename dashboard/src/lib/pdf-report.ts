// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import type { Finding, ScanReport } from "./types";
import { SEVERITY_ORDER } from "./types";

const COLORS: Record<string, [number, number, number]> = {
  critical: [239, 68, 68],
  high: [249, 115, 22],
  medium: [234, 179, 8],
  low: [34, 197, 94],
  info: [59, 130, 246],
  unknown: [107, 114, 128],
};

const HEADER_BG: [number, number, number] = [17, 24, 39];
const ACCENT: [number, number, number] = [99, 102, 241];

function severityCounts(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    const sev = (f.severity || "info").toLowerCase();
    counts[sev] = (counts[sev] || 0) + 1;
  }
  return counts;
}

function truncate(text: string | undefined, max: number): string {
  if (!text) return "—";
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + "…";
}

export function generatePDF(report: ScanReport, filename?: string): Uint8Array {
  const doc = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const margin = 15;
  let y = 0;

  // ── Header band ──
  doc.setFillColor(...HEADER_BG);
  doc.rect(0, 0, pageW, 38, "F");

  doc.setFillColor(...ACCENT);
  doc.rect(0, 38, pageW, 2, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont("helvetica", "bold");
  doc.text("Security Scan Report", margin, 18);

  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  const meta: string[] = [];
  if (report.target) meta.push(`Target: ${report.target}`);
  if (report.scan_date) meta.push(`Date: ${report.scan_date}`);
  if (report.profile) meta.push(`Profile: ${report.profile}`);
  meta.push(`Findings: ${report.findings.length}`);
  doc.text(meta.join("  ·  "), margin, 28);

  if (filename) {
    doc.setFontSize(7);
    doc.setTextColor(160, 160, 160);
    doc.text(filename, margin, 34);
  }

  y = 48;

  // ── Executive Summary ──
  doc.setTextColor(17, 24, 39);
  doc.setFontSize(14);
  doc.setFont("helvetica", "bold");
  doc.text("Executive Summary", margin, y);
  y += 8;

  const counts = severityCounts(report.findings);
  const summaryData = SEVERITY_ORDER.filter((s) => (counts[s] || 0) > 0).map(
    (sev) => {
      const count = counts[sev] || 0;
      const pct = report.findings.length
        ? ((count / report.findings.length) * 100).toFixed(1)
        : "0";
      return [sev.toUpperCase(), String(count), `${pct}%`];
    }
  );

  if (summaryData.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Severity", "Count", "% of Total"]],
      body: summaryData,
      margin: { left: margin, right: margin },
      headStyles: {
        fillColor: HEADER_BG,
        textColor: [255, 255, 255],
        fontStyle: "bold",
        fontSize: 9,
      },
      bodyStyles: { fontSize: 9 },
      columnStyles: {
        0: { cellWidth: 40 },
        1: { cellWidth: 25, halign: "center" },
        2: { cellWidth: 30, halign: "center" },
      },
      didParseCell(data) {
        if (data.section === "body" && data.column.index === 0) {
          const sev = String(data.cell.raw).toLowerCase();
          const color = COLORS[sev];
          if (color) data.cell.styles.textColor = color;
          data.cell.styles.fontStyle = "bold";
        }
      },
      theme: "grid",
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    y = (doc as any).lastAutoTable.finalY + 10;
  }

  // ── Tool Breakdown ──
  const toolCounts: Record<string, number> = {};
  for (const f of report.findings) {
    toolCounts[f.tool] = (toolCounts[f.tool] || 0) + 1;
  }
  const toolEntries = Object.entries(toolCounts).sort((a, b) => b[1] - a[1]);

  if (toolEntries.length > 0) {
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.setTextColor(17, 24, 39);
    doc.text("Findings by Tool", margin, y);
    y += 6;

    autoTable(doc, {
      startY: y,
      head: [["Tool", "Findings"]],
      body: toolEntries.map(([tool, count]) => [tool, String(count)]),
      margin: { left: margin, right: margin },
      headStyles: {
        fillColor: HEADER_BG,
        textColor: [255, 255, 255],
        fontStyle: "bold",
        fontSize: 9,
      },
      bodyStyles: { fontSize: 9 },
      columnStyles: {
        1: { cellWidth: 30, halign: "center" },
      },
      theme: "grid",
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    y = (doc as any).lastAutoTable.finalY + 10;
  }

  // ── Findings Table ──
  doc.setFontSize(14);
  doc.setFont("helvetica", "bold");
  doc.setTextColor(17, 24, 39);

  // Check if we need a new page
  if (y > pageH - 40) {
    doc.addPage();
    y = 20;
  }
  doc.text("Detailed Findings", margin, y);
  y += 6;

  const sortedFindings = [...report.findings].sort((a, b) => {
    const ai = SEVERITY_ORDER.indexOf((a.severity || "unknown").toLowerCase());
    const bi = SEVERITY_ORDER.indexOf((b.severity || "unknown").toLowerCase());
    return ai - bi;
  });

  const findingsBody = sortedFindings.map((f) => [
    (f.severity || "info").toUpperCase(),
    truncate(f.title, 60),
    f.cwe_id || f.cwe || "—",
    f.tool || "—",
    f.cvss_score != null ? f.cvss_score.toFixed(1) : "—",
    truncate(f.description, 80),
    truncate(f.remediation, 60),
  ]);

  autoTable(doc, {
    startY: y,
    head: [["Severity", "Title", "CWE", "Tool", "CVSS", "Description", "Remediation"]],
    body: findingsBody,
    margin: { left: margin, right: margin },
    headStyles: {
      fillColor: HEADER_BG,
      textColor: [255, 255, 255],
      fontStyle: "bold",
      fontSize: 7,
    },
    bodyStyles: { fontSize: 7, cellPadding: 2 },
    columnStyles: {
      0: { cellWidth: 18, halign: "center" },
      1: { cellWidth: 38 },
      2: { cellWidth: 16, halign: "center" },
      3: { cellWidth: 22 },
      4: { cellWidth: 12, halign: "center" },
      5: { cellWidth: 42 },
      6: { cellWidth: 32 },
    },
    didParseCell(data) {
      if (data.section === "body" && data.column.index === 0) {
        const sev = String(data.cell.raw).toLowerCase();
        const color = COLORS[sev];
        if (color) data.cell.styles.textColor = color;
        data.cell.styles.fontStyle = "bold";
      }
    },
    theme: "grid",
  });

  // ── Footer on each page ──
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(150, 150, 150);
    doc.text(
      `Page ${i} of ${totalPages}`,
      pageW / 2,
      pageH - 8,
      { align: "center" }
    );
    doc.text(
      "Generated by Security Dashboard · Confidential",
      margin,
      pageH - 8
    );
    doc.text(
      new Date().toISOString().slice(0, 19),
      pageW - margin,
      pageH - 8,
      { align: "right" }
    );
  }

  return doc.output("arraybuffer") as unknown as Uint8Array;
}
