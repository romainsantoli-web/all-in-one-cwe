// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * Site Map API — runs katana crawler + httpx probe to build the
 * architecture graph of a target website.
 *
 * POST  → start crawl job (returns job_id)
 * GET   → retrieve crawl results as graph data
 */

import { NextResponse } from "next/server";
import { spawn } from "child_process";
import { readFile, writeFile, mkdir } from "fs/promises";
import { join } from "path";
import { randomUUID } from "crypto";

export const dynamic = "force-dynamic";

const PROJECT_ROOT = process.env.PROJECT_ROOT || "/data";
const REPORTS_DIR = join(PROJECT_ROOT, "reports", "site-map");
const MAX_TARGET_LEN = 2048;
const MAX_DEPTH = 5;
const MAX_CONCURRENT_JOBS = 3;

const activeJobs = new Map<string, { status: string; target: string; startedAt: number }>();

function isValidTarget(target: string): boolean {
  try {
    const u = new URL(target);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    // Block internal/private IPs (SSRF protection)
    const host = u.hostname.toLowerCase();
    if (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "0.0.0.0" ||
      host === "::1" ||
      host.startsWith("10.") ||
      host.startsWith("192.168.") ||
      host.startsWith("169.254.") ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host)
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

interface CrawlNode {
  id: string;
  url: string;
  type: "page" | "api" | "asset" | "external" | "form";
  status?: number;
  tech?: string[];
  depth: number;
  size?: number;
}

interface CrawlLink {
  source: string;
  target: string;
  type: "link" | "redirect" | "form" | "api" | "asset";
}

interface SiteGraphData {
  nodes: CrawlNode[];
  links: CrawlLink[];
  meta: {
    target: string;
    total_urls: number;
    crawl_depth: number;
    duration_s: number;
  };
}

function classifyUrl(url: string, baseHost: string): CrawlNode["type"] {
  try {
    const u = new URL(url);
    if (u.hostname !== baseHost) return "external";
    const path = u.pathname.toLowerCase();
    if (/\/api\/|\/graphql|\/v[0-9]+\//.test(path)) return "api";
    if (/\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ico|webp|mp4|pdf)$/i.test(path)) return "asset";
    if (/\.(php|asp|jsp|action)$/i.test(path) && u.search) return "form";
    return "page";
  } catch {
    return "page";
  }
}

function urlToId(url: string): string {
  try {
    const u = new URL(url);
    return `${u.hostname}${u.pathname}${u.search}`.replace(/[^a-zA-Z0-9/_.-]/g, "_").slice(0, 200);
  } catch {
    return url.replace(/[^a-zA-Z0-9/_.-]/g, "_").slice(0, 200);
  }
}

/** Parse katana JSONL output into graph data */
function parseKatanaOutput(raw: string, target: string): SiteGraphData {
  const baseHost = new URL(target).hostname;
  const nodesMap = new Map<string, CrawlNode>();
  const linksSet = new Set<string>();
  const links: CrawlLink[] = [];

  const lines = raw.split("\n").filter((l) => l.trim());

  for (const line of lines) {
    let entry: Record<string, any>;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }

    const reqUrl = (entry.request?.url ?? entry.url ?? "") as string;
    const respUrl = (entry.response?.url ?? reqUrl) as string;
    const sourceUrl = (entry.source ?? "") as string;
    const depth = (typeof entry.depth === "number" ? entry.depth : 0) as number;
    const statusCode = (entry.response?.status_code ?? entry.status_code ?? 0) as number;
    const tech = (entry.tech ?? []) as string[];

    if (!reqUrl) continue;

    const nodeId = urlToId(reqUrl);
    if (!nodesMap.has(nodeId)) {
      nodesMap.set(nodeId, {
        id: nodeId,
        url: reqUrl,
        type: classifyUrl(reqUrl, baseHost),
        status: statusCode || undefined,
        tech: tech.length > 0 ? tech : undefined,
        depth,
      });
    }

    // Create link from source to this URL
    if (sourceUrl) {
      const sourceId = urlToId(sourceUrl);
      const linkKey = `${sourceId}->${nodeId}`;
      if (!linksSet.has(linkKey) && sourceId !== nodeId) {
        linksSet.add(linkKey);
        const nodeType = nodesMap.get(nodeId)?.type || "page";
        const linkType: CrawlLink["type"] =
          nodeType === "api" ? "api" :
          nodeType === "asset" ? "asset" :
          nodeType === "form" ? "form" :
          "link";
        links.push({ source: sourceId, target: nodeId, type: linkType });

        // Ensure source node exists
        if (!nodesMap.has(sourceId)) {
          nodesMap.set(sourceId, {
            id: sourceId,
            url: sourceUrl,
            type: classifyUrl(sourceUrl, baseHost),
            depth: Math.max(0, depth - 1),
          });
        }
      }
    }
  }

  return {
    nodes: Array.from(nodesMap.values()),
    links,
    meta: {
      target,
      total_urls: nodesMap.size,
      crawl_depth: Math.max(...Array.from(nodesMap.values()).map((n) => n.depth), 0),
      duration_s: 0,
    },
  };
}

/** POST — Start site crawl */
export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const target = body.target;
  if (typeof target !== "string" || target.length === 0 || target.length > MAX_TARGET_LEN) {
    return NextResponse.json({ error: "target: required URL (max 2048)" }, { status: 400 });
  }
  if (!isValidTarget(target)) {
    return NextResponse.json(
      { error: "target: must be a valid public http/https URL" },
      { status: 400 },
    );
  }

  const depth = Math.min(Math.max(1, Number(body.depth) || 3), MAX_DEPTH);
  const rateLimit = Math.min(Math.max(1, Number(body.rate_limit) || 20), 100);

  // Limit concurrent jobs
  const runningJobs = Array.from(activeJobs.values()).filter((j) => j.status === "running");
  if (runningJobs.length >= MAX_CONCURRENT_JOBS) {
    return NextResponse.json({ error: "Too many active crawl jobs" }, { status: 429 });
  }

  const jobId = randomUUID();
  await mkdir(REPORTS_DIR, { recursive: true });
  const outputFile = join(REPORTS_DIR, `${jobId}.jsonl`);
  const metaFile = join(REPORTS_DIR, `${jobId}.meta.json`);

  activeJobs.set(jobId, { status: "running", target: target, startedAt: Date.now() });

  // Check if katana is available via Docker
  const t0 = Date.now();

  const child = spawn("docker", [
    "run", "--rm",
    "-v", `${REPORTS_DIR}:/output`,
    "projectdiscovery/katana:latest",
    "-u", target,
    "-d", String(depth),
    "-jc",           // JS crawling
    "-kf", "all",    // known-files wordlist
    "-ef", "css,png,jpg,jpeg,gif,svg,woff,woff2,ico,webp,mp4",
    "-json",
    "-o", `/output/${jobId}.jsonl`,
    "-rate-limit", String(rateLimit),
    "-concurrency", "10",
    "-timeout", "10",
    "-silent",
  ], {
    cwd: PROJECT_ROOT,
    timeout: 180_000,
  });

  child.on("close", async (code) => {
    const elapsed = Math.round((Date.now() - t0) / 1000);
    const job = activeJobs.get(jobId);
    if (job) {
      job.status = code === 0 ? "completed" : "failed";
    }

    // Parse results and store graph data
    try {
      let raw = "";
      try {
        raw = await readFile(outputFile, "utf-8");
      } catch {
        raw = "";
      }

      const graphData = parseKatanaOutput(raw, target);
      graphData.meta.duration_s = elapsed;

      await writeFile(metaFile, JSON.stringify(graphData, null, 2));
    } catch {
      // Best effort
    }
  });

  child.on("error", () => {
    const job = activeJobs.get(jobId);
    if (job) job.status = "failed";
  });

  return NextResponse.json({
    job_id: jobId,
    status: "running",
    target,
    depth,
  });
}

/** GET — Retrieve crawl results */
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const jobId = searchParams.get("job_id");

  // If no job_id, return list of cached results
  if (!jobId) {
    const { readdir } = await import("fs/promises");
    try {
      await mkdir(REPORTS_DIR, { recursive: true });
      const files = await readdir(REPORTS_DIR);
      const metas = files.filter((f) => f.endsWith(".meta.json"));
      const results: { job_id: string; target: string; total_urls: number }[] = [];
      for (const f of metas.slice(-10)) {
        try {
          const raw = await readFile(join(REPORTS_DIR, f), "utf-8");
          const data = JSON.parse(raw);
          results.push({
            job_id: f.replace(".meta.json", ""),
            target: data.meta?.target || "unknown",
            total_urls: data.meta?.total_urls || 0,
          });
        } catch { /* skip */ }
      }
      return NextResponse.json({ results });
    } catch {
      return NextResponse.json({ results: [] });
    }
  }

  // Validate job_id format (UUID)
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(jobId)) {
    return NextResponse.json({ error: "Invalid job_id format" }, { status: 400 });
  }

  // Check active job status
  const job = activeJobs.get(jobId);
  if (job?.status === "running") {
    return NextResponse.json({ status: "running", target: job.target });
  }

  // Try to read results
  const metaFile = join(REPORTS_DIR, `${jobId}.meta.json`);
  try {
    const raw = await readFile(metaFile, "utf-8");
    const data: SiteGraphData = JSON.parse(raw);
    return NextResponse.json({ status: "completed", ...data });
  } catch {
    return NextResponse.json({ error: "Results not found" }, { status: 404 });
  }
}
