// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useRef, useCallback } from "react";

interface AdbCaptureTerminalProps {
  serial: string;
  iface: string;
  packets: string;
  outFile: string;
  /** API endpoint to POST to (default: /api/android/capture) */
  endpoint?: string;
  /** Title displayed in the header bar */
  title?: string;
  /** Extra body fields to include in the POST request */
  extraBody?: Record<string, unknown>;
  onDone?: () => void;
}

interface StepState {
  label: string;
  cmd?: string;
  root?: boolean;
  status: "pending" | "running" | "ok" | "error" | "skipped" | "warning";
  output?: string;
}

/**
 * Live terminal renderer for ADB WiFi capture workflow.
 * Connects to /api/android/capture via SSE and displays real-time step output.
 */
export default function AdbCaptureTerminal({
  serial,
  iface,
  packets,
  outFile,
  endpoint = "/api/android/capture",
  title = "WiFi Capture",
  extraBody,
  onDone,
}: AdbCaptureTerminalProps) {
  const [steps, setSteps] = useState<StepState[]>([]);
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);
  const [aborted, setAborted] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const startTimeRef = useRef<number>(Date.now());
  const abortRef = useRef<AbortController | null>(null);

  const autoScroll = useCallback(() => {
    setTimeout(() => {
      if (scrollRef.current) {
        scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
      }
    }, 50);
  }, []);

  // Timer
  useEffect(() => {
    if (done) return;
    const id = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);
    return () => clearInterval(id);
  }, [done]);

  // SSE connection
  useEffect(() => {
    const abort = new AbortController();
    abortRef.current = abort;

    const run = async () => {
      try {
        const res = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ serial, iface, packets, outFile, ...extraBody }),
          signal: abort.signal,
        });

        if (!res.ok || !res.body) {
          setDone(true);
          setAborted(true);
          return;
        }

        setConnected(true);
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done: readerDone, value } = await reader.read();
          if (readerDone) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const raw = line.slice(6).trim();
            if (!raw) continue;

            try {
              const msg = JSON.parse(raw);

              if (msg.type === "init") {
                const stepsArr: StepState[] = [];
                for (let i = 0; i < msg.totalSteps; i++) {
                  stepsArr.push({ label: "", status: "pending" });
                }
                setSteps(stepsArr);
              } else if (msg.type === "step-start") {
                setSteps((prev) => {
                  const next = [...prev];
                  next[msg.step] = {
                    label: msg.label,
                    cmd: msg.cmd === "__pull__" ? "adb pull" : msg.cmd,
                    root: msg.root,
                    status: "running",
                  };
                  return next;
                });
                autoScroll();
              } else if (msg.type === "step-end") {
                setSteps((prev) => {
                  const next = [...prev];
                  if (next[msg.step]) {
                    next[msg.step] = {
                      ...next[msg.step],
                      status: msg.warning ? "warning" : msg.ok ? "ok" : "error",
                      output: msg.output,
                    };
                  }
                  return next;
                });
                autoScroll();
              } else if (msg.type === "step-skip") {
                setSteps((prev) => {
                  const next = [...prev];
                  if (next[msg.step]) {
                    next[msg.step] = {
                      ...next[msg.step],
                      label: msg.label,
                      status: "skipped",
                    };
                  }
                  return next;
                });
              } else if (msg.type === "done") {
                setDone(true);
                setAborted(!!msg.aborted);
                setConnected(false);
                onDone?.();
              }
            } catch { /* ignore parse errors */ }
          }
        }
      } catch (err) {
        if (!abort.signal.aborted) {
          setDone(true);
          setAborted(true);
          setConnected(false);
        }
      }
    };

    run();

    return () => {
      abort.abort();
    };
  }, [serial, iface, packets, outFile, endpoint, extraBody, autoScroll, onDone]);

  const cancelCapture = () => {
    abortRef.current?.abort();
    setDone(true);
    setAborted(true);
    setConnected(false);
  };

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  };

  const stepIcon = (status: StepState["status"]) => {
    switch (status) {
      case "running": return "⏳";
      case "ok": return "✅";
      case "error": return "❌";
      case "warning": return "⚠️";
      case "skipped": return "⏭️";
      default: return "⬜";
    }
  };

  const stepColor = (status: StepState["status"]) => {
    switch (status) {
      case "running": return "text-yellow-300";
      case "ok": return "text-green-400";
      case "error": return "text-red-400";
      case "warning": return "text-yellow-400";
      case "skipped": return "text-gray-500";
      default: return "text-[var(--text-dim)]";
    }
  };

  const completed = steps.filter((s) => s.status === "ok" || s.status === "warning").length;
  const total = steps.length;

  return (
    <div className="flex flex-col h-full bg-[#0d1117]">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#161b22] border-b border-[var(--border)]">
        <div className="flex items-center gap-3">
          <span className="text-sm">📡</span>
          <span className="text-xs font-mono text-[var(--text-muted)]">
            {title} — {iface}
          </span>
          <span className={`text-xs font-semibold ${
            done
              ? aborted ? "text-red-400" : "text-green-400"
              : "text-yellow-300 animate-pulse"
          }`}>
            {done
              ? aborted ? "● aborted" : "● completed"
              : connected ? "● capturing" : "● connecting"}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-[var(--text-dim)] font-mono">
            {formatTime(elapsed)} · {completed}/{total} steps
          </span>
          {!done && (
            <button
              onClick={cancelCapture}
              className="px-2 py-0.5 text-xs bg-red-900/30 text-red-400 rounded hover:bg-red-900/50 transition-colors"
            >
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Config summary */}
      <div className="px-4 py-2 bg-[#0d1117] border-b border-[var(--border)] flex gap-4 text-[10px] font-mono text-[var(--text-dim)]">
        <span>device: <span className="text-cyan-400">{serial || "default"}</span></span>
        <span>iface: <span className="text-cyan-400">{iface}</span></span>
        <span>packets: <span className="text-cyan-400">{packets}</span></span>
        <span>output: <span className="text-cyan-400">{outFile}</span></span>
      </div>

      {/* Steps terminal */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 space-y-2 font-mono text-[12px]"
      >
        {steps.map((step, i) => (
          <div
            key={i}
            className={`p-3 rounded border transition-all duration-200 ${
              step.status === "running"
                ? "border-yellow-500/40 bg-yellow-900/10 shadow-[0_0_8px_rgba(234,179,8,0.1)]"
                : step.status === "ok"
                  ? "border-green-500/25 bg-green-900/5"
                  : step.status === "warning"
                    ? "border-yellow-500/25 bg-yellow-900/5"
                    : step.status === "error"
                      ? "border-red-500/25 bg-red-900/5"
                      : step.status === "skipped"
                        ? "border-gray-600/20 opacity-40"
                        : "border-[var(--border)] opacity-50"
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="w-5 text-center text-sm">{stepIcon(step.status)}</span>
              <span className={`font-semibold ${stepColor(step.status)}`}>
                [{String(i + 1).padStart(2, "0")}] {step.label || `Step ${i + 1}`}
              </span>
              {step.root && (
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-800/40 text-red-300 font-bold">
                  root
                </span>
              )}
              {step.status === "running" && (
                <span className="ml-auto text-[10px] text-yellow-400/60 animate-pulse">
                  executing...
                </span>
              )}
            </div>

            {step.cmd && (
              <div className="text-[11px] text-cyan-400/60 mt-1 ml-7 flex items-center gap-1">
                <span className="text-green-500/60">$</span> {step.cmd}
              </div>
            )}

            {step.output && (
              <pre className="text-[11px] text-[var(--text)] mt-2 ml-7 whitespace-pre-wrap break-all max-h-[200px] overflow-y-auto bg-black/30 rounded p-2 border border-[var(--border)]">
                {step.output}
              </pre>
            )}
          </div>
        ))}

        {/* Final status */}
        {done && (
          <div className={`mt-4 p-3 rounded border text-center text-sm font-bold ${
            aborted
              ? "border-red-500/30 bg-red-900/10 text-red-400"
              : "border-green-500/30 bg-green-900/10 text-green-400"
          }`}>
            {aborted
              ? `❌ Workflow aborted — ${completed}/${total} steps completed`
              : `✅ WiFi capture complete — ${total}/${total} steps in ${formatTime(elapsed)}`
            }
          </div>
        )}

        <div style={{ height: 1 }} />
      </div>
    </div>
  );
}
