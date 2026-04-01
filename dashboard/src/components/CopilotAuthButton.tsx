// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useRef, useCallback } from "react";

type FlowState = "idle" | "loading" | "waiting" | "polling" | "success" | "error";

export default function CopilotAuthButton() {
  const [state, setState] = useState<FlowState>("idle");
  const [userCode, setUserCode] = useState("");
  const [verificationUri, setVerificationUri] = useState("");
  const [error, setError] = useState("");
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const cleanup = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startFlow = async () => {
    cleanup();
    setState("loading");
    setError("");
    setUserCode("");

    try {
      const res = await fetch("/api/llm/copilot-auth", { method: "POST" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);

      setUserCode(data.user_code);
      setVerificationUri(data.verification_uri);
      setState("waiting");

      // Auto-open verification URL
      window.open(data.verification_uri, "_blank", "noopener,noreferrer");

      // Start polling
      const interval = (data.interval || 5) * 1000;
      const deviceCode = data.device_code;
      let attempts = 0;
      const maxAttempts = Math.ceil((data.expires_in || 900) / (data.interval || 5));

      pollRef.current = setInterval(async () => {
        attempts++;
        if (attempts > maxAttempts) {
          cleanup();
          setState("error");
          setError("Device flow expired. Please try again.");
          return;
        }

        try {
          setState("polling");
          const pollRes = await fetch("/api/llm/copilot-auth", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ device_code: deviceCode }),
          });
          const pollData = await pollRes.json();

          if (pollData.status === "ok") {
            cleanup();
            setState("success");
          } else if (pollData.status === "expired") {
            cleanup();
            setState("error");
            setError("Code expired. Please try again.");
          } else if (pollData.status === "error") {
            cleanup();
            setState("error");
            setError(pollData.error || "Unknown error");
          }
          // "pending" / "slow_down" → keep polling
        } catch {
          // Network error — keep polling
        }
      }, interval);
    } catch (err) {
      setState("error");
      setError((err as Error).message);
    }
  };

  if (state === "success") {
    return (
      <div className="mt-3 pt-3 border-t border-[var(--border)]">
        <div className="flex items-center gap-2">
          <span className="text-green-400 text-sm font-medium">✓ Copilot Pro connected</span>
          <button
            onClick={() => window.location.reload()}
            className="px-2 py-1 text-xs bg-[var(--accent)] text-white rounded hover:opacity-90"
          >
            Refresh
          </button>
        </div>
      </div>
    );
  }

  if (state === "waiting" || state === "polling") {
    return (
      <div className="mt-3 pt-3 border-t border-[var(--border)]">
        <div className="space-y-2">
          <p className="text-sm text-[var(--muted)]">
            Enter this code on GitHub:
          </p>
          <div className="flex items-center gap-3">
            <code className="px-3 py-2 bg-[var(--card)] border border-[var(--border)] rounded text-lg font-mono font-bold tracking-widest text-[var(--accent)]">
              {userCode}
            </code>
            <button
              onClick={() => navigator.clipboard.writeText(userCode)}
              className="px-2 py-1 text-xs bg-[var(--card)] border border-[var(--border)] rounded hover:bg-[var(--accent)]/10"
              title="Copy code"
            >
              📋
            </button>
          </div>
          <a
            href={verificationUri}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-[var(--accent)] hover:underline"
          >
            {verificationUri} ↗
          </a>
          <div className="flex items-center gap-2 text-xs text-[var(--muted)]">
            <span className="inline-block w-2 h-2 bg-yellow-400 rounded-full animate-pulse" />
            {state === "polling" ? "Checking..." : "Waiting for authorization..."}
          </div>
          <button
            onClick={() => { cleanup(); setState("idle"); }}
            className="px-2 py-1 text-xs text-red-400 hover:underline"
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="mt-3 pt-3 border-t border-[var(--border)]">
      <button
        onClick={startFlow}
        disabled={state === "loading"}
        className="px-3 py-1.5 text-xs bg-purple-600 text-white rounded hover:bg-purple-500 disabled:opacity-50"
      >
        {state === "loading" ? "Starting..." : "🔗 Connect with GitHub"}
      </button>
      {error && (
        <span className="ml-2 text-xs text-red-400">{error}</span>
      )}
    </div>
  );
}
