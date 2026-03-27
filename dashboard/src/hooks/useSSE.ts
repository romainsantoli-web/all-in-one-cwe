// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback, useRef } from "react";

export interface SSEMessage {
  chunk?: string;
  error?: string;
  done?: boolean;
  stats?: Record<string, unknown>;
  progress?: number;
  tool?: string;
  status?: string;
}

interface UseSSEOptions {
  url: string | null;
  onMessage?: (msg: SSEMessage) => void;
  onDone?: () => void;
  onError?: (err: string) => void;
}

export function useSSE({ url, onMessage, onDone, onError }: UseSSEOptions) {
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<SSEMessage[]>([]);
  const sourceRef = useRef<EventSource | null>(null);

  const close = useCallback(() => {
    if (sourceRef.current) {
      sourceRef.current.close();
      sourceRef.current = null;
    }
    setConnected(false);
  }, []);

  useEffect(() => {
    if (!url) return;

    const source = new EventSource(url);
    sourceRef.current = source;

    source.onopen = () => setConnected(true);

    source.onmessage = (event) => {
      const data = event.data;
      if (data === "[DONE]") {
        onDone?.();
        close();
        return;
      }
      try {
        const msg: SSEMessage = JSON.parse(data);
        setMessages((prev) => [...prev, msg]);
        onMessage?.(msg);
        if (msg.done) {
          onDone?.();
          close();
        }
      } catch {
        // Plain text chunk
        const msg: SSEMessage = { chunk: data };
        setMessages((prev) => [...prev, msg]);
        onMessage?.(msg);
      }
    };

    source.onerror = () => {
      onError?.("SSE connection lost");
      close();
    };

    return () => close();
  }, [url]); // eslint-disable-line react-hooks/exhaustive-deps

  const reset = useCallback(() => {
    setMessages([]);
    setConnected(false);
  }, []);

  return { connected, messages, close, reset };
}
