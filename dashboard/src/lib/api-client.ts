// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
/**
 * Typed API client for the Security Dashboard backend.
 * All POST bodies are validated server-side via manual checks (no Zod in browser bundle).
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface JobStatus {
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
}

export interface TriggerScanRequest {
  target: string;
  profile?: "light" | "medium" | "full";
  tools?: string[];
  rateLimit?: number;
  dryRun?: boolean;
}

export interface TriggerScanResponse {
  jobId: string;
  status: "queued";
}

export interface RunToolRequest {
  tool: string;
  target: string;
  options?: Record<string, string>;
}

export interface LLMAnalyzeRequest {
  findings: Array<{ title: string; severity: string; cwe?: string; description?: string }>;
  provider?: string;
  prompt?: string;
}

export interface LLMChatRequest {
  messages: Array<{ role: "user" | "assistant"; content: string }>;
  provider?: string;
  context?: string;
}

export interface LLMProviderStatus {
  name: string;
  model: string;
  envVar: string;
  available: boolean;
}

export interface LLMAgentRequest {
  goal: string;
  target: string;
  provider?: string;
  maxSteps?: number;
}

// ---------------------------------------------------------------------------
// Fetch helpers
// ---------------------------------------------------------------------------

async function apiFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Scans API
// ---------------------------------------------------------------------------

export async function triggerScan(req: TriggerScanRequest): Promise<TriggerScanResponse> {
  return apiFetch<TriggerScanResponse>("/api/scans/trigger", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}

export async function listJobs(): Promise<JobStatus[]> {
  return apiFetch<JobStatus[]>("/api/scans/jobs");
}

export async function getJob(id: string): Promise<JobStatus> {
  return apiFetch<JobStatus>(`/api/scans/jobs/${encodeURIComponent(id)}`);
}

export async function cancelJob(id: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(`/api/scans/jobs/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

// ---------------------------------------------------------------------------
// Tools API
// ---------------------------------------------------------------------------

export async function runTool(req: RunToolRequest): Promise<TriggerScanResponse> {
  return apiFetch<TriggerScanResponse>("/api/tools/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}

export async function getToolStatus(name: string): Promise<{ available: boolean; reason?: string }> {
  return apiFetch<{ available: boolean; reason?: string }>(`/api/tools/${encodeURIComponent(name)}/status`);
}

// ---------------------------------------------------------------------------
// LLM API
// ---------------------------------------------------------------------------

export async function listProviders(): Promise<LLMProviderStatus[]> {
  return apiFetch<LLMProviderStatus[]>("/api/llm/providers");
}

/** Stream LLM analysis via SSE. Returns a ReadableStream of text chunks. */
export function streamAnalyze(req: LLMAnalyzeRequest): ReadableStream<string> {
  return new ReadableStream<string>({
    async start(controller) {
      const res = await fetch("/api/llm/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      });
      if (!res.ok || !res.body) {
        controller.error(new Error(`LLM analyze error: ${res.status}`));
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const text = decoder.decode(value, { stream: true });
          // Parse SSE events
          for (const line of text.split("\n")) {
            if (line.startsWith("data: ")) {
              const data = line.slice(6);
              if (data === "[DONE]") {
                controller.close();
                return;
              }
              controller.enqueue(data);
            }
          }
        }
      } finally {
        reader.releaseLock();
        controller.close();
      }
    },
  });
}

/** Stream LLM chat via SSE. */
export function streamChat(req: LLMChatRequest): ReadableStream<string> {
  return new ReadableStream<string>({
    async start(controller) {
      const res = await fetch("/api/llm/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      });
      if (!res.ok || !res.body) {
        controller.error(new Error(`LLM chat error: ${res.status}`));
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const text = decoder.decode(value, { stream: true });
          for (const line of text.split("\n")) {
            if (line.startsWith("data: ")) {
              const data = line.slice(6);
              if (data === "[DONE]") {
                controller.close();
                return;
              }
              controller.enqueue(data);
            }
          }
        }
      } finally {
        reader.releaseLock();
        controller.close();
      }
    },
  });
}

/** Stream LLM agent loop via SSE, yielding typed events. */
export function streamAgent(req: LLMAgentRequest): ReadableStream<string> {
  return new ReadableStream<string>({
    async start(controller) {
      const res = await fetch("/api/llm/agent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      });
      if (!res.ok || !res.body) {
        controller.error(new Error(`LLM agent error: ${res.status}`));
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const text = decoder.decode(value, { stream: true });
          for (const line of text.split("\n")) {
            if (line.startsWith("data: ")) {
              const data = line.slice(6);
              if (data === "[DONE]") {
                controller.close();
                return;
              }
              controller.enqueue(data);
            }
          }
        }
      } finally {
        reader.releaseLock();
        controller.close();
      }
    },
  });
}

// ---------------------------------------------------------------------------
// SSE stream for scan job progress
// ---------------------------------------------------------------------------

export function streamJobProgress(jobId: string, onEvent: (data: JobStatus) => void): () => void {
  const es = new EventSource(`/api/stream/${encodeURIComponent(jobId)}`);
  es.onmessage = (ev) => {
    try {
      onEvent(JSON.parse(ev.data) as JobStatus);
    } catch { /* ignore parse errors */ }
  };
  es.onerror = () => {
    es.close();
  };
  return () => es.close();
}
