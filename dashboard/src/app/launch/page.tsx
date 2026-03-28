// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import ScanLauncher from "@/components/ScanLauncher";
import { useState, useEffect } from "react";
import { listJobs, type JobStatus } from "@/lib/api-client";
import Link from "next/link";

export default function LaunchPage() {
  const [recentJobs, setRecentJobs] = useState<JobStatus[]>([]);

  useEffect(() => {
    listJobs()
      .then((jobs) => setRecentJobs(jobs.slice(0, 10)))
      .catch(() => {});
    const interval = setInterval(() => {
      listJobs()
        .then((jobs) => setRecentJobs(jobs.slice(0, 10)))
        .catch(() => {});
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const statusColor = (s: string) => {
    switch (s) {
      case "completed": return "text-green-400";
      case "failed": return "text-red-400";
      case "running": return "text-blue-400";
      case "queued": return "text-yellow-400";
      case "cancelled": return "text-orange-400";
      default: return "text-[var(--text-muted)]";
    }
  };

  return (
    <main className="px-6 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Launch</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Trigger scans, select tools, and monitor progress in real-time.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ScanLauncher />
        </div>

        <div>
          <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4">
            <h3 className="font-bold text-sm mb-3">Recent Jobs</h3>
            {recentJobs.length === 0 ? (
              <p className="text-xs text-[var(--text-dim)]">No recent jobs</p>
            ) : (
              <div className="space-y-2">
                {recentJobs.map((job) => (
                  <Link
                    key={job.id}
                    href={`/launch/${job.id}`}
                    className="flex items-center justify-between py-2 px-3 rounded bg-[var(--bg)] text-xs hover:bg-[var(--bg)]/80 transition-colors group"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="font-mono truncate group-hover:text-[var(--accent)] transition-colors">{job.tool || job.tools.length + " tools"}</div>
                      <div className="text-[var(--text-dim)] truncate">{job.target}</div>
                    </div>
                    <div className="flex items-center gap-2 ml-2 shrink-0">
                      {job.findings > 0 && (
                        <span className="font-bold">{job.findings}</span>
                      )}
                      <span className={`font-medium ${statusColor(job.status)}`}>
                        {job.status}
                      </span>
                      <span className="text-[var(--text-dim)] opacity-0 group-hover:opacity-100 transition-opacity">→</span>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}
