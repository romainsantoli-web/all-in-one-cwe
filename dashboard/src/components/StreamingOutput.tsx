// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useRef, useEffect } from "react";

interface SSEMessage {
  chunk?: string;
  error?: string;
  done?: boolean;
}

export default function StreamingOutput({ url }: { url: string | null }) {
  const [text, setText] = useState("");
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!url) return;
    setText("");
    setDone(false);

    const source = new EventSource(url);
    source.onopen = () => setConnected(true);

    source.onmessage = (event) => {
      const data = event.data;
      if (data === "[DONE]") {
        setDone(true);
        setConnected(false);
        source.close();
        return;
      }
      try {
        const msg: SSEMessage = JSON.parse(data);
        if (msg.chunk) {
          setText((prev) => prev + msg.chunk);
        } else if (msg.error) {
          setText((prev) => prev + `\n⚠️ Error: ${msg.error}\n`);
        }
        if (msg.done) {
          setDone(true);
          setConnected(false);
          source.close();
        }
      } catch {
        setText((prev) => prev + data);
      }
    };

    source.onerror = () => {
      setConnected(false);
      source.close();
    };

    return () => source.close();
  }, [url]);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [text]);

  if (!url && !text) return null;

  return (
    <div className="mt-4">
      <div className="flex items-center gap-2 mb-2">
        {connected && (
          <span className="flex items-center gap-1.5 text-xs text-green-400">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            Streaming
          </span>
        )}
        {done && (
          <span className="text-xs text-[var(--text-muted)]">✓ Complete</span>
        )}
      </div>
      <div
        ref={containerRef}
        className="bg-[var(--bg)] border border-[var(--border)] rounded-lg p-4 font-mono text-xs max-h-[400px] overflow-y-auto whitespace-pre-wrap"
      >
        {text || <span className="text-[var(--text-dim)]">Waiting for output...</span>}
      </div>
    </div>
  );
}
