// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * Job store — JSON-file-based persistence for scan/tool execution jobs.
 * Stored in PROJECT_ROOT/reports/.jobs/<jobId>.json
 */

import { readdir, readFile, writeFile, mkdir, unlink } from "fs/promises";
import { join } from "path";
import { randomUUID } from "crypto";

/** Lazy eval — process.env may not be populated at module load time in Next.js */
function getJobsDir(): string {
  return join(process.env.PROJECT_ROOT || "/data", "reports", ".jobs");
}

export interface Job {
  id: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  tool: string | null;
  target: string;
  profile: string | null;
  tools: string[];
  progress: number;
  createdAt: string;
  updatedAt: string;
  findings: number;
  error?: string;
  pid?: number;
  logFile?: string;
  reportFile?: string;
}

async function ensureDir(): Promise<void> {
  await mkdir(getJobsDir(), { recursive: true });
}

function jobPath(id: string): string {
  // Prevent path traversal
  const safe = id.replace(/[^a-zA-Z0-9_-]/g, "");
  return join(getJobsDir(), `${safe}.json`);
}

export async function createJob(params: {
  target: string;
  profile?: string | null;
  tools: string[];
  tool?: string | null;
}): Promise<Job> {
  await ensureDir();
  const job: Job = {
    id: randomUUID(),
    status: "queued",
    tool: params.tool ?? null,
    target: params.target,
    profile: params.profile ?? null,
    tools: params.tools,
    progress: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    findings: 0,
  };
  await writeFile(jobPath(job.id), JSON.stringify(job, null, 2));
  return job;
}

export async function getJob(id: string): Promise<Job | null> {
  try {
    const raw = await readFile(jobPath(id), "utf-8");
    return JSON.parse(raw) as Job;
  } catch {
    return null;
  }
}

export async function updateJob(id: string, patch: Partial<Job>): Promise<Job | null> {
  const job = await getJob(id);
  if (!job) return null;
  const updated = { ...job, ...patch, updatedAt: new Date().toISOString() };
  await writeFile(jobPath(id), JSON.stringify(updated, null, 2));
  return updated;
}

export async function listJobs(): Promise<Job[]> {
  await ensureDir();
  try {
    const dir = getJobsDir();
    const files = await readdir(dir);
    const jobs: Job[] = [];
    for (const f of files) {
      if (!f.endsWith(".json")) continue;
      try {
        const raw = await readFile(join(dir, f), "utf-8");
        const parsed = JSON.parse(raw);
        // Only include valid Job objects (skip -summary.json and other non-Job files)
        if (parsed.id && parsed.status && parsed.createdAt) {
          jobs.push(parsed as Job);
        }
      } catch {
        // corrupt or unreadable file — skip silently
      }
    }
    return jobs.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  } catch {
    return [];
  }
}

export interface JobSummary {
  job_id: string;
  target: string;
  profile: string;
  tools_run: number;
  completed: number;
  failed: number;
  total_findings: number;
  results: Array<{
    tool: string;
    status: string;
    elapsed_s: number;
    findings: number;
  }>;
}

/** Load the runner summary for a given job (if it exists). */
export async function getJobSummary(id: string): Promise<JobSummary | null> {
  try {
    const safe = id.replace(/[^a-zA-Z0-9_-]/g, "");
    const raw = await readFile(join(getJobsDir(), `${safe}-summary.json`), "utf-8");
    return JSON.parse(raw) as JobSummary;
  } catch {
    return null;
  }
}

/** Delete a job file by id. Returns true if deleted. */
export async function deleteJob(id: string): Promise<boolean> {
  try {
    await unlink(jobPath(id));
    // Also try to remove the log file
    try { await unlink(jobPath(id).replace(/\.json$/, ".log")); } catch { /* no log */ }
    try { await unlink(jobPath(id).replace(/\.json$/, "-summary.json")); } catch { /* no summary */ }
    return true;
  } catch {
    return false;
  }
}
