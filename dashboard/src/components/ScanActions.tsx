// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";

interface ScanActionsProps {
  filename: string;
  onDeleted: (filename: string) => void;
  onRenamed: (oldName: string, newName: string) => void;
}

export default function ScanActions({ filename, onDeleted, onRenamed }: ScanActionsProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [newName, setNewName] = useState(filename);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleDelete() {
    if (!confirm(`Delete "${filename}"? This cannot be undone.`)) return;
    setLoading("delete");
    setError(null);
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(filename)}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Delete failed");
      onDeleted(filename);
    } catch {
      setError("Delete failed");
    } finally {
      setLoading(null);
      setMenuOpen(false);
    }
  }

  async function handleRename() {
    if (!newName || newName === filename) {
      setRenaming(false);
      return;
    }
    const safeName = newName.endsWith(".json") ? newName : `${newName}.json`;
    setLoading("rename");
    setError(null);
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(filename)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ newName: safeName }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Rename failed");
      }
      onRenamed(filename, safeName);
      setRenaming(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Rename failed");
    } finally {
      setLoading(null);
    }
  }

  async function downloadPDF() {
    setLoading("pdf");
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(filename)}/pdf`);
      if (!res.ok) throw new Error("PDF generation failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename.replace(/\.json$/i, ".pdf");
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError("PDF download failed");
    } finally {
      setLoading(null);
      setMenuOpen(false);
    }
  }

  function downloadJSON() {
    const a = document.createElement("a");
    a.href = `/api/scans/${encodeURIComponent(filename)}`;
    a.download = filename;
    a.click();
    setMenuOpen(false);
  }

  async function downloadCSV() {
    setLoading("csv");
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(filename)}`);
      if (!res.ok) throw new Error("Load failed");
      const report = await res.json();
      const findings = report.findings || [];
      const headers = ["severity","title","cwe","tool","cvss_score","url","description","remediation"];
      const escape = (v: string) => {
        if (v.includes(",") || v.includes('"') || v.includes("\n")) return `"${v.replace(/"/g, '""')}"`;
        return v;
      };
      const rows = findings.map((f: Record<string, unknown>) =>
        [
          String(f.severity || ""),
          String(f.title || ""),
          String(f.cwe_id || f.cwe || ""),
          String(f.tool || ""),
          f.cvss_score != null ? String(f.cvss_score) : "",
          String(f.url || f.endpoint || ""),
          String(f.description || ""),
          String(f.remediation || ""),
        ].map(escape).join(",")
      );
      const csv = [headers.join(","), ...rows].join("\n");
      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename.replace(/\.json$/i, ".csv");
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError("CSV download failed");
    } finally {
      setLoading(null);
      setMenuOpen(false);
    }
  }

  const PLATFORMS = [
    { key: "yeswehack", label: "YesWeHack", color: "text-purple-500" },
    { key: "hackerone", label: "HackerOne", color: "text-emerald-500" },
    { key: "bugcrowd", label: "Bugcrowd", color: "text-orange-500" },
    { key: "intigriti", label: "Intigriti", color: "text-blue-500" },
    { key: "immunefi", label: "Immunefi", color: "text-cyan-500" },
    { key: "markdown", label: "Markdown", color: "text-gray-400" },
  ] as const;

  async function exportForPlatform(format: string) {
    setLoading(`export-${format}`);
    setError(null);
    try {
      const res = await fetch(
        `/api/scans/${encodeURIComponent(filename)}/export?format=${format}`
      );
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename.replace(/\.json$/i, `-${format}.md`);
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setError(`Export ${format} failed`);
    } finally {
      setLoading(null);
      setExportMenuOpen(false);
    }
  }

  if (renaming) {
    return (
      <div className="flex items-center gap-2" onClick={(e) => e.preventDefault()}>
        <input
          type="text"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleRename();
            if (e.key === "Escape") setRenaming(false);
          }}
          className="px-2 py-1 text-xs rounded border border-[var(--border)] bg-[var(--bg)] text-[var(--text)] focus:border-[var(--accent)] outline-none w-64"
          autoFocus
        />
        <button
          onClick={handleRename}
          disabled={loading === "rename"}
          className="text-xs px-2 py-1 rounded bg-[var(--accent)] text-white hover:opacity-90 disabled:opacity-50"
        >
          {loading === "rename" ? "…" : "Save"}
        </button>
        <button
          onClick={() => { setRenaming(false); setNewName(filename); }}
          className="text-xs px-2 py-1 rounded border border-[var(--border)] hover:border-[var(--text-muted)]"
        >
          Cancel
        </button>
        {error && <span className="text-xs text-red-500">{error}</span>}
      </div>
    );
  }

  return (
    <div className="relative flex items-center gap-2" onClick={(e) => e.preventDefault()}>
      {error && <span className="text-xs text-red-500 mr-2">{error}</span>}

      {/* Download dropdown */}
      <div className="relative">
        <button
          onClick={() => setMenuOpen(!menuOpen)}
          className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text-muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors"
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          Download
          <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
        </button>

        {menuOpen && (
          <>
            <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} />
            <div className="absolute right-0 top-full mt-1 z-20 bg-[var(--card-bg)] border border-[var(--border)] rounded-lg shadow-lg py-1 min-w-[140px]">
              <button
                onClick={downloadPDF}
                disabled={loading === "pdf"}
                className="w-full text-left px-3 py-2 text-xs hover:bg-[var(--bg)] transition-colors flex items-center gap-2 disabled:opacity-50"
              >
                <span className="w-6 text-red-500 font-bold text-[10px]">PDF</span>
                {loading === "pdf" ? "Generating…" : "Download PDF"}
              </button>
              <button
                onClick={downloadJSON}
                className="w-full text-left px-3 py-2 text-xs hover:bg-[var(--bg)] transition-colors flex items-center gap-2"
              >
                <span className="w-6 text-blue-500 font-bold text-[10px]">JSON</span>
                Download JSON
              </button>
              <button
                onClick={downloadCSV}
                disabled={loading === "csv"}
                className="w-full text-left px-3 py-2 text-xs hover:bg-[var(--bg)] transition-colors flex items-center gap-2 disabled:opacity-50"
              >
                <span className="w-6 text-green-500 font-bold text-[10px]">CSV</span>
                {loading === "csv" ? "Generating…" : "Download CSV"}
              </button>
            </div>
          </>
        )}
      </div>

      {/* Platform export dropdown */}
      <div className="relative">
        <button
          onClick={() => setExportMenuOpen(!exportMenuOpen)}
          className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--text-muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors"
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>
          Export for…
          <svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
        </button>

        {exportMenuOpen && (
          <>
            <div className="fixed inset-0 z-10" onClick={() => setExportMenuOpen(false)} />
            <div className="absolute right-0 top-full mt-1 z-20 bg-[var(--card-bg)] border border-[var(--border)] rounded-lg shadow-lg py-1 min-w-[170px]">
              {PLATFORMS.map((p) => (
                <button
                  key={p.key}
                  onClick={() => exportForPlatform(p.key)}
                  disabled={loading === `export-${p.key}`}
                  className="w-full text-left px-3 py-2 text-xs hover:bg-[var(--bg)] transition-colors flex items-center gap-2 disabled:opacity-50"
                >
                  <span className={`w-6 font-bold text-[10px] ${p.color}`}>
                    {p.label.slice(0, 3).toUpperCase()}
                  </span>
                  {loading === `export-${p.key}` ? "Generating…" : p.label}
                </button>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Rename */}
      <button
        onClick={() => setRenaming(true)}
        title="Rename"
        className="p-1.5 rounded border border-[var(--border)] text-[var(--text-muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
      </button>

      {/* Delete */}
      <button
        onClick={handleDelete}
        disabled={loading === "delete"}
        title="Delete"
        className="p-1.5 rounded border border-[var(--border)] text-[var(--text-muted)] hover:border-red-500 hover:text-red-500 transition-colors disabled:opacity-50"
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
      </button>
    </div>
  );
}
