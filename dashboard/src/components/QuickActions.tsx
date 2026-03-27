// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";
import Link from "next/link";

export default function QuickActions() {
  const [target, setTarget] = useState("");
  const [launching, setLaunching] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const launchQuick = async () => {
    if (!target) return;
    setLaunching(true);
    setError(null);
    try {
      const res = await fetch("/api/scans/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, profile: "light" }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setJobId(data.jobId);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
      {/* Quick Scan */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
        <h3 className="font-semibold text-sm mb-3 flex items-center gap-2">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <polygon points="5 3 19 12 5 21 5 3" />
          </svg>
          Quick Scan
        </h3>
        <div className="flex gap-2">
          <input
            type="url"
            placeholder="https://target.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="flex-1 px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded text-sm"
          />
          <button
            onClick={launchQuick}
            disabled={launching || !target}
            className="px-4 py-2 bg-[var(--accent)] text-white rounded text-sm font-medium hover:opacity-90 disabled:opacity-50"
          >
            {launching ? "..." : "Scan"}
          </button>
        </div>
        {jobId && (
          <p className="text-xs text-green-400 mt-2">
            Launched!{" "}
            <Link href="/launch" className="underline">View progress →</Link>
          </p>
        )}
        {error && <p className="text-xs text-red-400 mt-2">{error}</p>}
      </div>

      {/* AI Summary */}
      <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
        <h3 className="font-semibold text-sm mb-3 flex items-center gap-2">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </svg>
          AI Analysis
        </h3>
        <p className="text-xs text-[var(--text-muted)] mb-3">
          Get an AI-powered summary of your findings, top risks, and recommended next steps.
        </p>
        <Link
          href="/ai"
          className="inline-block px-4 py-2 bg-purple-600 text-white rounded text-sm font-medium hover:opacity-90"
        >
          Open AI Chat →
        </Link>
      </div>
    </div>
  );
}
