// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * Job store — JSON-file-based persistence for scan/tool execution jobs.
 * Stored in PROJECT_ROOT/reports/.jobs/<jobId>.json
 */

import { readdir, readFile, writeFile, mkdir } from "fs/promises";
import { join } from "path";
import { randomUUID } from "crypto";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const JOBS_DIR = join(PROJECT_ROOT, "reports", ".jobs");

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
}

async function ensureDir(): Promise<void> {
  await mkdir(JOBS_DIR, { recursive: true });
}

function jobPath(id: string): string {
  // Prevent path traversal
  const safe = id.replace(/[^a-zA-Z0-9_-]/g, "");
  return join(JOBS_DIR, `${safe}.json`);
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
    const files = await readdir(JOBS_DIR);
    const jobs: Job[] = [];
    for (const f of files) {
      if (!f.endsWith(".json")) continue;
      try {
        const raw = await readFile(join(JOBS_DIR, f), "utf-8");
        jobs.push(JSON.parse(raw) as Job);
      } catch { /* skip corrupt files */ }
    }
    return jobs.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  } catch {
    return [];
  }
}
