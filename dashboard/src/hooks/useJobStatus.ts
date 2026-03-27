// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback, useRef } from "react";

export interface JobStatus {
  id: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  tool: string | null;
  target: string;
  tools: string[];
  findings: number;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

interface UseJobStatusOptions {
  jobId: string | null;
  pollInterval?: number;
}

export function useJobStatus({ jobId, pollInterval = 2000 }: UseJobStatusOptions) {
  const [job, setJob] = useState<JobStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatus = useCallback(async () => {
    if (!jobId) return;
    try {
      const res = await fetch(`/api/scans/jobs/${jobId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setJob(data);
      setError(null);
      // Stop polling on terminal states
      if (["completed", "failed", "cancelled"].includes(data.status)) {
        if (timerRef.current) {
          clearInterval(timerRef.current);
          timerRef.current = null;
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    }
  }, [jobId]);

  useEffect(() => {
    if (!jobId) {
      setJob(null);
      return;
    }
    setLoading(true);
    fetchStatus().finally(() => setLoading(false));

    timerRef.current = setInterval(fetchStatus, pollInterval);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [jobId, pollInterval, fetchStatus]);

  const cancel = useCallback(async () => {
    if (!jobId) return;
    try {
      await fetch(`/api/scans/jobs/${jobId}`, { method: "DELETE" });
      await fetchStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cancel failed");
    }
  }, [jobId, fetchStatus]);

  return { job, loading, error, cancel, refetch: fetchStatus };
}
