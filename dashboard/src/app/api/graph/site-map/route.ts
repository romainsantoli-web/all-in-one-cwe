// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * Site Map API — Multi-tool site architecture mapping.
 *
 * Runs in parallel: katana (JS-aware crawler) + httpx (HTTP prober + tech detect)
 *   + subfinder (passive subdomain enum) to build a comprehensive 3D graph.
 * Falls back gracefully: each tool is optional — results merge from whatever succeeds.
 *
 * POST  → start mapping job (returns job_id + tools used)
 * GET   → retrieve/poll results as graph data
 */

import { NextResponse } from "next/server";
import { execFile } from "child_process";
import { readFile, writeFile, mkdir, readdir } from "fs/promises";
import { join, resolve } from "path";
import { randomUUID } from "crypto";
import { existsSync } from "fs";

export const dynamic = "force-dynamic";

// Resolve PROJECT_ROOT to the actual repo root (parent of dashboard/)
function getProjectRoot(): string {
  if (process.env.PROJECT_ROOT) return process.env.PROJECT_ROOT;
  // dashboard runs from security-all-in-one-cwe/dashboard, so parent is project root
  const candidate = resolve(process.cwd(), "..");
  if (existsSync(join(candidate, "docker-compose.yml"))) return candidate;
  return process.cwd();
}

const PROJECT_ROOT = getProjectRoot();
const REPORTS_DIR = join(PROJECT_ROOT, "reports", "site-map");
const MAX_TARGET_LEN = 2048;
const MAX_DEPTH = 5;
const MAX_CONCURRENT_JOBS = 3;

interface JobState {
  status: "running" | "completed" | "failed";
  target: string;
  startedAt: number;
  tools: string[];
  toolStatus: Record<string, "running" | "done" | "failed" | "skipped">;
  progress?: string;
}

const activeJobs = new Map<string, JobState>();

function isValidTarget(target: string): boolean {
  try {
    const u = new URL(target);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
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
  type: "page" | "api" | "asset" | "external" | "form" | "subdomain";
  status?: number;
  tech?: string[];
  depth: number;
  size?: number;
  source?: string; // which tool discovered this
}

interface CrawlLink {
  source: string;
  target: string;
  type: "link" | "redirect" | "form" | "api" | "asset" | "subdomain";
}

interface SiteGraphData {
  nodes: CrawlNode[];
  links: CrawlLink[];
  meta: {
    target: string;
    total_urls: number;
    crawl_depth: number;
    duration_s: number;
    tools_used: string[];
    tools_status: Record<string, string>;
  };
}

function classifyUrl(url: string, baseHost: string): CrawlNode["type"] {
  try {
    const u = new URL(url);
    if (u.hostname !== baseHost && !u.hostname.endsWith(`.${baseHost}`)) return "external";
    const path = u.pathname.toLowerCase();
    if (/\/api\/|\/graphql|\/v[0-9]+\/|\/rest\/|\/ws\/?$/i.test(path)) return "api";
    if (/\.(js|css|png|jpg|jpeg|gif|svg|woff2?|ico|webp|mp4|pdf|map|json)$/i.test(path)) return "asset";
    if (/\.(php|asp|aspx|jsp|action|do)$/i.test(path) && u.search) return "form";
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

/** Detect which tools are available as local binaries */
async function detectTools(): Promise<Record<string, string | null>> {
  const tools: Record<string, string | null> = {
    katana: null,
    httpx: null,
    subfinder: null,
  };

  for (const name of Object.keys(tools)) {
    try {
      const result = await execPromise("which", [name]);
      if (result.stdout.trim()) tools[name] = result.stdout.trim();
    } catch { /* not found */ }
  }
  return tools;
}

function execPromise(cmd: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, {
      timeout: 300_000,
      maxBuffer: 50 * 1024 * 1024, // 50MB
    }, (error, stdout, stderr) => {
      if (error) reject(Object.assign(error, { stdout, stderr }));
      else resolve({ stdout, stderr });
    });
  });
}

// ─── Tool runners ──────────────────────────────────────────

/** Run katana: JS-aware web crawling */
async function runKatana(
  target: string, depth: number, rateLimit: number, outputFile: string
): Promise<string> {
  const args = [
    "-u", target,
    "-d", String(depth),
    "-jc",                    // JS crawling
    "-kf", "all",             // known-files wordlist
    "-ef", "css,png,jpg,jpeg,gif,svg,woff,woff2,ico,webp,mp4",
    "-jsonl",
    "-o", outputFile,
    "-rl", String(rateLimit),
    "-c", "10",
    "-silent",
  ];
  const { stdout } = await execPromise("katana", args);
  // Also read the output file (katana writes there)
  try {
    return await readFile(outputFile, "utf-8");
  } catch {
    return stdout;
  }
}

/** Run httpx: HTTP probing + tech detection + status codes */
async function runHttpx(urls: string[], outputFile: string): Promise<string> {
  // httpx reads from stdin, but we pass via temp file or pipe
  const inputFile = outputFile.replace(".json", ".input.txt");
  await writeFile(inputFile, urls.join("\n"));

  const args = [
    "-l", inputFile,
    "-sc",            // status code
    "-td",            // tech detection
    "-title",         // page title
    "-server",        // server header
    "-ct",            // content type
    "-location",      // redirect location
    "-favicon",       // favicon hash
    "-json",
    "-o", outputFile,
    "-rl", "30",
    "-t", "15",
    "-silent",
  ];
  await execPromise("httpx", args);
  try {
    return await readFile(outputFile, "utf-8");
  } catch {
    return "";
  }
}

/** Run subfinder: passive subdomain enumeration */
async function runSubfinder(domain: string, outputFile: string): Promise<string> {
  const args = [
    "-d", domain,
    "-all",
    "-oJ",
    "-o", outputFile,
    "-silent",
  ];
  await execPromise("subfinder", args);
  try {
    return await readFile(outputFile, "utf-8");
  } catch {
    return "";
  }
}

// ─── Parsers ───────────────────────────────────────────────

function parseKatanaOutput(
  raw: string, baseHost: string,
  nodesMap: Map<string, CrawlNode>, linksSet: Set<string>, links: CrawlLink[]
): void {
  for (const line of raw.split("\n").filter((l) => l.trim())) {
    let entry: Record<string, any>;
    try { entry = JSON.parse(line); } catch { continue; }

    const reqUrl = (entry.request?.endpoint ?? entry.request?.url ?? entry.url ?? "") as string;
    const sourceUrl = (entry.source ?? entry.request?.source ?? "") as string;
    const depth = (typeof entry.depth === "number" ? entry.depth : 0) as number;
    const statusCode = (entry.response?.status_code ?? entry.status_code ?? 0) as number;
    const tech = (entry.tech ?? []) as string[];
    const server = entry.response?.headers?.Server || entry.response?.headers?.server;
    if (server && !tech.includes(server)) tech.push(server);

    if (!reqUrl) continue;

    const nodeId = urlToId(reqUrl);
    if (!nodesMap.has(nodeId)) {
      nodesMap.set(nodeId, {
        id: nodeId, url: reqUrl,
        type: classifyUrl(reqUrl, baseHost),
        status: statusCode || undefined,
        tech: tech.length > 0 ? tech : undefined,
        depth, source: "katana",
      });
    }

    if (sourceUrl) {
      const sourceId = urlToId(sourceUrl);
      const linkKey = `${sourceId}->${nodeId}`;
      if (!linksSet.has(linkKey) && sourceId !== nodeId) {
        linksSet.add(linkKey);
        const nodeType = nodesMap.get(nodeId)?.type || "page";
        links.push({
          source: sourceId, target: nodeId,
          type: nodeType === "api" ? "api" : nodeType === "asset" ? "asset" : nodeType === "form" ? "form" : "link",
        });
        if (!nodesMap.has(sourceId)) {
          nodesMap.set(sourceId, {
            id: sourceId, url: sourceUrl,
            type: classifyUrl(sourceUrl, baseHost),
            depth: Math.max(0, depth - 1), source: "katana",
          });
        }
      }
    }
  }
}

function parseHttpxOutput(
  raw: string, baseHost: string,
  nodesMap: Map<string, CrawlNode>
): void {
  for (const line of raw.split("\n").filter((l) => l.trim())) {
    let entry: Record<string, any>;
    try { entry = JSON.parse(line); } catch { continue; }

    const url = (entry.url ?? entry.input ?? "") as string;
    if (!url) continue;

    const nodeId = urlToId(url);
    const existing = nodesMap.get(nodeId);
    const statusCode = entry.status_code as number | undefined;
    const tech: string[] = [];
    if (Array.isArray(entry.tech)) tech.push(...entry.tech);
    if (entry.webserver) tech.push(entry.webserver);
    if (entry.title) tech.push(`title:${entry.title}`);

    if (existing) {
      // Enrich existing node with httpx data
      if (statusCode && !existing.status) existing.status = statusCode;
      if (tech.length > 0) {
        existing.tech = [...new Set([...(existing.tech || []), ...tech])];
      }
    } else {
      nodesMap.set(nodeId, {
        id: nodeId, url,
        type: classifyUrl(url, baseHost),
        status: statusCode || undefined,
        tech: tech.length > 0 ? tech : undefined,
        depth: 0, source: "httpx",
      });
    }
  }
}

function parseSubfinderOutput(
  raw: string, baseHost: string, target: string,
  nodesMap: Map<string, CrawlNode>, linksSet: Set<string>, links: CrawlLink[]
): string[] {
  const subdomains: string[] = [];
  const rootId = urlToId(target);

  for (const line of raw.split("\n").filter((l) => l.trim())) {
    let entry: Record<string, any>;
    try { entry = JSON.parse(line); } catch {
      // subfinder can output plain hostnames too
      const host = line.trim();
      if (host && host.includes(".")) {
        subdomains.push(host);
      }
      continue;
    }

    const host = (entry.host ?? "") as string;
    if (host) subdomains.push(host);
  }

  // Add subdomain nodes  
  for (const sub of subdomains) {
    const subUrl = `https://${sub}`;
    const nodeId = urlToId(subUrl);
    if (!nodesMap.has(nodeId)) {
      nodesMap.set(nodeId, {
        id: nodeId, url: subUrl,
        type: "subdomain",
        depth: 1, source: "subfinder",
      });
      // Link root → subdomain
      const linkKey = `${rootId}->${nodeId}`;
      if (!linksSet.has(linkKey)) {
        linksSet.add(linkKey);
        links.push({ source: rootId, target: nodeId, type: "subdomain" });
      }
    }
  }

  return subdomains.map((s) => `https://${s}`);
}

// ─── Main pipeline ─────────────────────────────────────────

async function runMappingPipeline(
  jobId: string, target: string, depth: number, rateLimit: number
): Promise<void> {
  const t0 = Date.now();
  const job = activeJobs.get(jobId);
  if (!job) return;

  const jobDir = join(REPORTS_DIR, jobId);
  await mkdir(jobDir, { recursive: true });

  const baseHost = new URL(target).hostname;
  // Extract domain (remove www. prefix for subfinder)
  const domain = baseHost.replace(/^www\./, "");

  const availableTools = await detectTools();
  const nodesMap = new Map<string, CrawlNode>();
  const linksSet = new Set<string>();
  const links: CrawlLink[] = [];

  // Add root node
  const rootId = urlToId(target);
  nodesMap.set(rootId, {
    id: rootId, url: target,
    type: "page", depth: 0, source: "root",
  });

  // Phase 1: Run katana + subfinder in parallel
  job.progress = "Phase 1: Crawling + subdomain enum";

  const phase1: Promise<void>[] = [];

  if (availableTools.katana) {
    job.toolStatus.katana = "running";
    phase1.push(
      runKatana(target, depth, rateLimit, join(jobDir, "katana.jsonl"))
        .then((raw) => {
          parseKatanaOutput(raw, baseHost, nodesMap, linksSet, links);
          job.toolStatus.katana = "done";
        })
        .catch(() => { job.toolStatus.katana = "failed"; })
    );
  } else {
    job.toolStatus.katana = "skipped";
  }

  if (availableTools.subfinder) {
    job.toolStatus.subfinder = "running";
    phase1.push(
      runSubfinder(domain, join(jobDir, "subfinder.json"))
        .then((raw) => {
          parseSubfinderOutput(raw, baseHost, target, nodesMap, linksSet, links);
          job.toolStatus.subfinder = "done";
        })
        .catch(() => { job.toolStatus.subfinder = "failed"; })
    );
  } else {
    job.toolStatus.subfinder = "skipped";
  }

  await Promise.allSettled(phase1);

  // Phase 2: Run httpx on all discovered URLs for enrichment
  if (availableTools.httpx) {
    job.progress = "Phase 2: HTTP probing + tech detection";
    job.toolStatus.httpx = "running";

    const allUrls = Array.from(nodesMap.values())
      .map((n) => n.url)
      .filter((u) => {
        try { return new URL(u).protocol.startsWith("http"); }
        catch { return false; }
      });

    if (allUrls.length > 0) {
      try {
        const httpxRaw = await runHttpx(allUrls, join(jobDir, "httpx.json"));
        parseHttpxOutput(httpxRaw, baseHost, nodesMap);
        job.toolStatus.httpx = "done";
      } catch {
        job.toolStatus.httpx = "failed";
      }
    } else {
      job.toolStatus.httpx = "skipped";
    }
  } else {
    job.toolStatus.httpx = "skipped";
  }

  // Build final graph
  const elapsed = Math.round((Date.now() - t0) / 1000);
  const graphData: SiteGraphData = {
    nodes: Array.from(nodesMap.values()),
    links,
    meta: {
      target,
      total_urls: nodesMap.size,
      crawl_depth: Math.max(...Array.from(nodesMap.values()).map((n) => n.depth), 0),
      duration_s: elapsed,
      tools_used: Object.entries(job.toolStatus)
        .filter(([, s]) => s === "done")
        .map(([t]) => t),
      tools_status: { ...job.toolStatus },
    },
  };

  const metaFile = join(REPORTS_DIR, `${jobId}.meta.json`);
  await writeFile(metaFile, JSON.stringify(graphData, null, 2));

  job.status = "completed";
  job.progress = `Done — ${nodesMap.size} URLs mapped in ${elapsed}s`;
}

/** POST — Start multi-tool site mapping */
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

  // Detect available tools before starting
  const tools = await detectTools();
  const availableToolNames = Object.entries(tools)
    .filter(([, p]) => p !== null)
    .map(([n]) => n);

  if (availableToolNames.length === 0) {
    return NextResponse.json(
      { error: "No mapping tools found. Install katana, httpx, or subfinder via: brew install katana httpx subfinder" },
      { status: 500 },
    );
  }

  const jobId = randomUUID();
  await mkdir(REPORTS_DIR, { recursive: true });

  const jobState: JobState = {
    status: "running",
    target,
    startedAt: Date.now(),
    tools: availableToolNames,
    toolStatus: {},
    progress: "Initializing…",
  };
  activeJobs.set(jobId, jobState);

  // Run pipeline async (don't await)
  runMappingPipeline(jobId, target, depth, rateLimit).catch(() => {
    const job = activeJobs.get(jobId);
    if (job) job.status = "failed";
  });

  return NextResponse.json({
    job_id: jobId,
    status: "running",
    target,
    depth,
    tools: availableToolNames,
  });
}

/** GET — Retrieve/poll mapping results */
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const jobId = searchParams.get("job_id");

  // If no job_id, return list of cached results
  if (!jobId) {
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
    return NextResponse.json({
      status: "running",
      target: job.target,
      tools: job.tools,
      tool_status: job.toolStatus,
      progress: job.progress,
    });
  }

  // Try to read results file
  const metaFile = join(REPORTS_DIR, `${jobId}.meta.json`);
  try {
    const raw = await readFile(metaFile, "utf-8");
    const data: SiteGraphData = JSON.parse(raw);
    return NextResponse.json({ status: "completed", ...data });
  } catch {
    return NextResponse.json({ error: "Results not found" }, { status: 404 });
  }
}
