// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useRef, useCallback } from "react";

interface TerminalPanelProps {
  jobId: string;
  tool: string | null;
  target: string;
  onKill?: () => void;
  isRunning: boolean;
}

export default function TerminalPanel({ jobId, tool, target, onKill, isRunning }: TerminalPanelProps) {
  const [output, setOutput] = useState("");
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);
  const [finalStatus, setFinalStatus] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  const connect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const es = new EventSource(`/api/terminals/${jobId}/stream`);
    eventSourceRef.current = es;
    setConnected(true);

    es.onmessage = (event) => {
      if (event.data === "[DONE]") {
        setDone(true);
        setConnected(false);
        es.close();
        return;
      }

      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "output") {
          setOutput((prev) => prev + msg.text);
        } else if (msg.type === "status") {
          setFinalStatus(msg.status);
        }
      } catch {
        // Non-JSON data
        setOutput((prev) => prev + event.data + "\n");
      }
    };

    es.onerror = () => {
      setConnected(false);
      es.close();
    };
  }, [jobId]);

  useEffect(() => {
    connect();
    return () => {
      eventSourceRef.current?.close();
    };
  }, [connect]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [output]);

  const statusColor = finalStatus === "completed" ? "text-green-400" :
    finalStatus === "failed" ? "text-red-400" :
    finalStatus === "cancelled" ? "text-yellow-400" :
    connected ? "text-blue-400" : "text-[var(--text-muted)]";

  return (
    <div className="bg-[#0d1117] border border-[var(--border)] rounded-lg overflow-hidden">
      {/* Title bar */}
      <div className="flex items-center justify-between px-3 py-2 bg-[#161b22] border-b border-[var(--border)]">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-[var(--text-muted)]">
            {tool || "scan"} — {jobId.slice(0, 8)}
          </span>
          <span className={`text-xs font-medium ${statusColor}`}>
            {connected ? "● live" : done ? (finalStatus || "done") : "disconnected"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isRunning && onKill && (
            <button
              onClick={onKill}
              className="px-2 py-0.5 text-xs bg-red-900/30 text-red-400 rounded hover:bg-red-900/50 transition-colors"
            >
              Kill
            </button>
          )}
        </div>
      </div>

      {/* Terminal output */}
      <div
        ref={scrollRef}
        className="p-3 font-mono text-xs text-[#c9d1d9] overflow-y-auto whitespace-pre-wrap break-all"
        style={{ maxHeight: "300px", minHeight: "120px" }}
      >
        <span className="text-[#8b949e]">$ {tool || "runner.py"} --target {target}</span>
        {"\n"}
        {output || (connected ? "Waiting for output...\n" : "")}
        {done && !output && (
          <span className="text-[#8b949e]">No output captured.\n</span>
        )}
      </div>
    </div>
  );
}
