// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useEffect, useRef, useCallback, useState } from "react";
import "@xterm/xterm/css/xterm.css";

interface InteractiveTerminalProps {
  sessionId: string;
  label: string;
  provider: string;
  isRunning: boolean;
  onKill?: () => void;
}

export default function InteractiveTerminal({
  sessionId,
  label,
  provider,
  isRunning,
  onKill,
}: InteractiveTerminalProps) {
  const termRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<import("@xterm/xterm").Terminal | null>(null);
  const [status, setStatus] = useState<"connecting" | "connected" | "done">(
    "connecting",
  );

  const sendData = useCallback(
    (data: string) => {
      fetch(`/api/terminals/ai-session/${sessionId}/input`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: data }),
      }).catch(() => {});
    },
    [sessionId],
  );

  /** Notify backend of terminal size so the PTY resizes correctly */
  const sendResize = useCallback(
    (cols: number, rows: number) => {
      fetch(`/api/terminals/ai-session/${sessionId}/resize`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cols, rows }),
      }).catch(() => {});
    },
    [sessionId],
  );

  useEffect(() => {
    let disposed = false;
    let es: EventSource | null = null;
    let resizeObserver: ResizeObserver | null = null;
    let fitAddon: import("@xterm/addon-fit").FitAddon | null = null;

    async function init() {
      const { Terminal } = await import("@xterm/xterm");
      const { FitAddon } = await import("@xterm/addon-fit");

      if (disposed || !termRef.current) return;

      const term = new Terminal({
        cursorBlink: true,
        fontSize: 13,
        fontFamily:
          "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Menlo, Monaco, monospace",
        theme: {
          background: "#0d1117",
          foreground: "#c9d1d9",
          cursor: "#58a6ff",
          selectionBackground: "#264f78",
          black: "#484f58",
          red: "#ff7b72",
          green: "#3fb950",
          yellow: "#d29922",
          blue: "#58a6ff",
          magenta: "#bc8cff",
          cyan: "#39d353",
          white: "#c9d1d9",
          brightBlack: "#6e7681",
          brightRed: "#ffa198",
          brightGreen: "#56d364",
          brightYellow: "#e3b341",
          brightBlue: "#79c0ff",
          brightMagenta: "#d2a8ff",
          brightCyan: "#56d364",
          brightWhite: "#f0f6fc",
        },
        scrollback: 5000,
        allowProposedApi: true,
      });

      fitAddon = new FitAddon();
      term.loadAddon(fitAddon);
      term.open(termRef.current);
      xtermRef.current = term;

      // Delay initial fit to ensure the container has layout dimensions
      requestAnimationFrame(() => {
        if (disposed) return;
        try {
          fitAddon!.fit();
          sendResize(term.cols, term.rows);
        } catch { /* */ }
        term.focus();
      });

      // Forward every keystroke to the backend process stdin
      term.onData((data: string) => {
        sendData(data);
      });

      // Notify backend when terminal dimensions change
      term.onResize(({ cols, rows }: { cols: number; rows: number }) => {
        sendResize(cols, rows);
      });

      // Connect SSE stream — raw output goes straight into xterm
      es = new EventSource(`/api/terminals/ai-session/${sessionId}/stream`);
      if (!disposed) setStatus("connected");

      es.onmessage = (event) => {
        if (event.data === "[DONE]") {
          if (!disposed) setStatus("done");
          es?.close();
          return;
        }
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "output" && term) {
            term.write(msg.text);
          } else if (msg.type === "status") {
            if (!disposed) setStatus("done");
          }
        } catch {
          term?.write(event.data);
        }
      };

      es.onerror = () => {
        if (!disposed) setStatus("done");
        es?.close();
      };

      // Re-fit terminal when container resizes
      resizeObserver = new ResizeObserver(() => {
        try { fitAddon!.fit(); } catch { /* */ }
      });
      resizeObserver.observe(termRef.current);
    }

    init();

    return () => {
      disposed = true;
      es?.close();
      resizeObserver?.disconnect();
      xtermRef.current?.dispose();
      xtermRef.current = null;
    };
  }, [sessionId, sendData, sendResize]);

  /** Click on the container → refocus xterm so keystrokes flow again */
  const handleClick = useCallback(() => {
    xtermRef.current?.focus();
  }, []);

  const providerIcon =
    provider === "claude-code"
      ? "🟣"
      : provider === "mistral-vibe"
        ? "🟠"
        : "⚡";
  const statusColor =
    status === "connected"
      ? "text-green-400"
      : status === "done"
        ? "text-[var(--text-muted)]"
        : "text-yellow-400";

  return (
    <div className="interactive-terminal flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 bg-[#161b22] border-b border-[var(--border)] shrink-0">
        <div className="flex items-center gap-2">
          <span>{providerIcon}</span>
          <span className="text-xs font-mono text-[var(--text-muted)]">
            {label}
          </span>
          <span className={`text-xs font-medium ${statusColor}`}>
            {status === "connected"
              ? "● connected"
              : status === "done"
                ? "exited"
                : "connecting..."}
          </span>
        </div>
        {isRunning && onKill && (
          <button
            onClick={onKill}
            className="px-2 py-0.5 text-xs bg-red-900/30 text-red-400 rounded hover:bg-red-900/50 transition-colors"
          >
            Kill
          </button>
        )}
      </div>

      {/* xterm.js terminal canvas */}
      <div
        ref={termRef}
        onClick={handleClick}
        className="flex-1 min-h-0"
        style={{ padding: "4px", background: "#0d1117" }}
      />
    </div>
  );
}
