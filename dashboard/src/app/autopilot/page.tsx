// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useCallback, useRef, useState } from "react";
import CheckpointModal from "@/components/CheckpointModal";
import ChainGraph from "@/components/ChainGraph";
import ValidationBadge from "@/components/ValidationBadge";

type StepEvent = {
  event: "step";
  step: number;
  state: string;
  action: string;
  reasoning: string;
  result: Record<string, unknown>;
};

type CheckpointEvent = {
  event: "checkpoint";
  state: string;
  findings: Array<Record<string, unknown>>;
  chains: Array<Record<string, unknown>>;
  budget: {
    steps_used: number;
    steps_max: number;
    elapsed_seconds: number;
    max_time_seconds: number;
  };
};

type CompleteEvent = {
  event: "complete";
  target: string;
  findings_count: number;
  chains_count: number;
  tools_run: string[];
  steps_count: number;
};

type HuntEvent = StepEvent | CheckpointEvent | CompleteEvent | { event: string; [key: string]: unknown };

const MODES = [
  { value: "paranoid", label: "Paranoid", desc: "Pause after each finding" },
  { value: "normal", label: "Normal", desc: "Batch review every 5 min" },
  { value: "yolo", label: "YOLO", desc: "Minimal stops" },
];

const PROFILES = [
  { value: "light", label: "Light (15 tools)" },
  { value: "medium", label: "Medium (35 tools)" },
  { value: "full", label: "Full (67+ tools)" },
];

const STATE_COLORS: Record<string, string> = {
  scoping: "#4CAF50",
  profiling: "#9C27B0",
  recon: "#2196F3",
  hunting: "#FF9800",
  chaining: "#F44336",
  validating: "#6366f1",
  reporting: "#00BCD4",
  checkpoint: "#eab308",
  complete: "#10b981",
};

export default function AutopilotPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("normal");
  const [profile, setProfile] = useState("medium");
  const [maxSteps, setMaxSteps] = useState(50);
  const [maxTime, setMaxTime] = useState(3600);

  const [running, setRunning] = useState(false);
  const [events, setEvents] = useState<HuntEvent[]>([]);
  const [currentState, setCurrentState] = useState<string>("");
  const [checkpoint, setCheckpoint] = useState<CheckpointEvent | null>(null);
  const [summary, setSummary] = useState<CompleteEvent | null>(null);
  const [chains, setChains] = useState<Array<Record<string, unknown>>>([]);

  const abortRef = useRef<AbortController | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = useCallback(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, []);

  const startHunt = async () => {
    if (!target) return;
    try {
      new URL(target);
    } catch {
      return;
    }

    setRunning(true);
    setEvents([]);
    setSummary(null);
    setCheckpoint(null);
    setChains([]);
    setCurrentState("scoping");

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await fetch("/api/llm/agent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          mode: "autopilot",
          target,
          checkpointMode: mode,
          profile,
          maxSteps,
          maxTime,
        }),
        signal: controller.signal,
      });

      if (!res.ok || !res.body) {
        setRunning(false);
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const payload = line.slice(6).trim();
          if (payload === "[DONE]") continue;

          try {
            const evt = JSON.parse(payload) as HuntEvent;
            setEvents((prev) => [...prev, evt]);

            if (evt.event === "step") {
              const s = evt as StepEvent;
              setCurrentState(s.state);
            } else if (evt.event === "checkpoint") {
              setCheckpoint(evt as CheckpointEvent);
            } else if (evt.event === "complete") {
              setSummary(evt as CompleteEvent);
              setCurrentState("complete");
            } else if (evt.event === "chains") {
              const c = (evt as Record<string, unknown>).chains;
              if (Array.isArray(c)) setChains(c);
            }

            setTimeout(scrollToBottom, 50);
          } catch {
            // skip malformed JSON
          }
        }
      }
    } catch (err: unknown) {
      if ((err as Error).name !== "AbortError") {
        setEvents((prev) => [...prev, { event: "error", message: (err as Error).message }]);
      }
    } finally {
      setRunning(false);
      abortRef.current = null;
    }
  };

  const handleResume = () => {
    setCheckpoint(null);
    // SSE continues automatically — checkpoint is UI-only pause
  };

  const handleAbort = () => {
    setCheckpoint(null);
    abortRef.current?.abort();
    setRunning(false);
  };

  const stopHunt = () => {
    abortRef.current?.abort();
    setRunning(false);
  };

  const stepsOnly = events.filter((e) => e.event === "step") as StepEvent[];
  const findingsCount = summary?.findings_count ?? stepsOnly.filter(
    (s) => s.result && typeof s.result === "object" && "findings_added" in s.result && (s.result as Record<string, number>).findings_added > 0
  ).length;

  return (
    <main className="px-6 py-6 h-full flex flex-col">
      <div className="mb-4">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <span className="text-2xl">🤖</span> Autopilot
        </h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Autonomous ReAct hunting — observe → think → act → iterate
        </p>
      </div>

      {/* Config Panel */}
      {!running && !summary && (
        <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-5 mb-4">
          <h3 className="font-semibold text-sm mb-4">Hunt Configuration</h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Target */}
            <div className="md:col-span-2">
              <label className="block text-xs text-[var(--text-muted)] mb-1">Target URL</label>
              <input
                type="url"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="https://target.example.com"
                className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded-lg text-sm focus:outline-none focus:border-[var(--accent)]"
              />
            </div>

            {/* Mode */}
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Checkpoint Mode</label>
              <div className="space-y-1">
                {MODES.map((m) => (
                  <label
                    key={m.value}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-lg cursor-pointer text-sm ${
                      mode === m.value ? "bg-[var(--accent)]/10 border border-[var(--accent)]/30" : "hover:bg-[var(--bg)]"
                    }`}
                  >
                    <input
                      type="radio"
                      name="mode"
                      value={m.value}
                      checked={mode === m.value}
                      onChange={(e) => setMode(e.target.value)}
                      className="accent-[var(--accent)]"
                    />
                    <span className="font-medium">{m.label}</span>
                    <span className="text-[var(--text-muted)] text-xs">— {m.desc}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Profile */}
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Scan Profile</label>
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded-lg text-sm"
              >
                {PROFILES.map((p) => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>

              <label className="block text-xs text-[var(--text-muted)] mb-1 mt-3">Max Steps</label>
              <input
                type="number"
                min={5}
                max={200}
                value={maxSteps}
                onChange={(e) => setMaxSteps(Math.min(200, Math.max(5, Number(e.target.value))))}
                className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded-lg text-sm"
              />

              <label className="block text-xs text-[var(--text-muted)] mb-1 mt-3">Max Time (seconds)</label>
              <input
                type="number"
                min={60}
                max={7200}
                value={maxTime}
                onChange={(e) => setMaxTime(Math.min(7200, Math.max(60, Number(e.target.value))))}
                className="w-full px-3 py-2 bg-[var(--bg)] border border-[var(--border)] rounded-lg text-sm"
              />
            </div>
          </div>

          <button
            onClick={startHunt}
            disabled={!target}
            className="mt-4 px-6 py-2.5 rounded-lg bg-[var(--accent)] text-black font-semibold text-sm hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            🚀 Start Autonomous Hunt
          </button>
        </div>
      )}

      {/* Running / Results UI */}
      {(running || events.length > 0) && (
        <div className="flex-1 grid grid-cols-1 lg:grid-cols-3 gap-4 min-h-0">
          {/* Left: Live feed */}
          <div className="lg:col-span-2 flex flex-col min-h-0">
            {/* State bar */}
            <div className="flex items-center gap-3 mb-3">
              <div
                className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wide"
                style={{
                  background: `${STATE_COLORS[currentState] || "#666"}22`,
                  color: STATE_COLORS[currentState] || "#999",
                }}
              >
                {currentState || "idle"}
              </div>
              <div className="text-xs text-[var(--text-muted)]">
                Step {stepsOnly.length} / {maxSteps} · {findingsCount} findings
              </div>
              {running && (
                <button
                  onClick={stopHunt}
                  className="ml-auto px-3 py-1 text-xs rounded-lg border border-red-500/50 text-red-400 hover:bg-red-500/10"
                >
                  ■ Stop
                </button>
              )}
              {!running && summary && (
                <button
                  onClick={() => { setEvents([]); setSummary(null); setCurrentState(""); }}
                  className="ml-auto px-3 py-1 text-xs rounded-lg border border-[var(--border)] hover:bg-[var(--bg)]"
                >
                  New Hunt
                </button>
              )}
            </div>

            {/* Steps feed */}
            <div
              ref={feedRef}
              className="flex-1 bg-[var(--card-bg)] border border-[var(--border)] rounded-lg overflow-y-auto p-4 space-y-2 min-h-[300px]"
            >
              {stepsOnly.map((s, i) => (
                <div key={i} className="flex gap-3 text-xs">
                  <div className="shrink-0 w-6 h-6 rounded-full bg-[var(--bg)] flex items-center justify-center text-[10px] font-bold">
                    {s.step}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px] font-medium"
                        style={{
                          background: `${STATE_COLORS[s.state] || "#666"}22`,
                          color: STATE_COLORS[s.state] || "#999",
                        }}
                      >
                        {s.state}
                      </span>
                      <span className="font-mono text-[var(--accent)]">{s.action}</span>
                    </div>
                    <div className="text-[var(--text-muted)] mt-0.5">{s.reasoning}</div>
                    {s.result && (
                      <pre className="mt-1 text-[10px] text-[var(--text-dim)] bg-[var(--bg)] rounded px-2 py-1 overflow-x-auto">
                        {JSON.stringify(s.result, null, 0).slice(0, 200)}
                      </pre>
                    )}
                  </div>
                </div>
              ))}

              {running && (
                <div className="flex items-center gap-2 text-xs text-[var(--text-muted)] animate-pulse">
                  <div className="w-2 h-2 rounded-full bg-[var(--accent)]" />
                  Hunting...
                </div>
              )}

              {summary && (
                <div className="mt-4 p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                  <h4 className="font-bold text-green-400 mb-2">Hunt Complete</h4>
                  <div className="grid grid-cols-3 gap-4 text-center text-sm">
                    <div>
                      <div className="text-xl font-bold">{summary.findings_count}</div>
                      <div className="text-xs text-[var(--text-muted)]">Findings</div>
                    </div>
                    <div>
                      <div className="text-xl font-bold">{summary.chains_count}</div>
                      <div className="text-xs text-[var(--text-muted)]">Chains</div>
                    </div>
                    <div>
                      <div className="text-xl font-bold">{summary.steps_count}</div>
                      <div className="text-xs text-[var(--text-muted)]">Steps</div>
                    </div>
                  </div>
                  {summary.tools_run && (
                    <div className="mt-3 flex flex-wrap gap-1">
                      {summary.tools_run.map((t, i) => (
                        <span key={i} className="px-2 py-0.5 bg-[var(--bg)] rounded text-[10px]">{t}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Right panel: Findings + Chains */}
          <div className="flex flex-col gap-4 min-h-0">
            {/* Findings panel */}
            <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 flex-1 overflow-y-auto">
              <h3 className="font-semibold text-sm mb-3">Findings ({findingsCount})</h3>
              {events
                .filter((e): e is StepEvent => e.event === "step" && !!(e as StepEvent).result)
                .filter((s) => {
                  const r = s.result as Record<string, unknown>;
                  return typeof r.findings_added === "number" && (r.findings_added as number) > 0;
                })
                .map((s, i) => (
                  <div key={i} className="mb-2 p-2 bg-[var(--bg)] rounded text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-medium">{(s.result as Record<string, unknown>).tool as string}</span>
                      <span className="text-green-400">+{String((s.result as Record<string, unknown>).findings_added)}</span>
                    </div>
                  </div>
                ))}
            </div>

            {/* Chain graph */}
            {chains.length > 0 && (
              <div className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4 max-h-64 overflow-y-auto">
                <h3 className="font-semibold text-sm mb-3">Chains ({chains.length})</h3>
                <ChainGraph />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Checkpoint Modal */}
      {checkpoint && (
        <CheckpointModal
          data={checkpoint}
          onResume={handleResume}
          onAbort={handleAbort}
        />
      )}
    </main>
  );
}
