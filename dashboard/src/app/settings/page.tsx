// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState, useEffect, useCallback } from "react";

interface ProviderInfo {
  name: string;
  model: string;
  envVar: string;
  configured: boolean;
  source: "settings" | "env" | "none";
  maskedKey: string | null;
}

export default function SettingsPage() {
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<string | null>(null);
  const [keyInput, setKeyInput] = useState("");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const fetchProviders = useCallback(async () => {
    try {
      const res = await fetch("/api/settings");
      const data = await res.json();
      setProviders(data.providers || []);
    } catch {
      setMessage({ type: "error", text: "Failed to load settings" });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProviders();
  }, [fetchProviders]);

  const saveKey = async (envVar: string) => {
    if (!keyInput.trim()) return;
    setSaving(true);
    setMessage(null);
    try {
      const res = await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ keys: { [envVar]: keyInput.trim() } }),
      });
      if (!res.ok) {
        const err = await res.json();
        setMessage({ type: "error", text: err.error || "Save failed" });
      } else {
        setMessage({ type: "success", text: `${envVar} saved successfully` });
        setEditing(null);
        setKeyInput("");
        await fetchProviders();
      }
    } catch {
      setMessage({ type: "error", text: "Network error" });
    } finally {
      setSaving(false);
    }
  };

  const deleteKey = async (envVar: string) => {
    setSaving(true);
    setMessage(null);
    try {
      const res = await fetch("/api/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ keys: { [envVar]: null } }),
      });
      if (res.ok) {
        setMessage({ type: "success", text: `${envVar} removed` });
        await fetchProviders();
      }
    } catch {
      setMessage({ type: "error", text: "Network error" });
    } finally {
      setSaving(false);
    }
  };

  return (
    <main className="px-6 py-6 max-w-3xl">
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Configure API keys for LLM providers. Keys are stored server-side in the reports directory.
        </p>
      </div>

      {message && (
        <div className={`mb-4 p-3 rounded text-sm ${
          message.type === "success"
            ? "bg-green-900/20 border border-green-800/30 text-green-400"
            : "bg-red-900/20 border border-red-800/30 text-red-400"
        }`}>
          {message.text}
        </div>
      )}

      {loading ? (
        <div className="text-sm text-[var(--text-muted)]">Loading...</div>
      ) : (
        <div className="space-y-3">
          {providers.map((p) => (
            <div
              key={p.envVar}
              className="bg-[var(--card-bg)] border border-[var(--border)] rounded-lg p-4"
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <div>
                    <span className="font-semibold text-sm">{p.name}</span>
                    <span className="text-xs text-[var(--text-dim)] ml-2">{p.model}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`inline-block w-2 h-2 rounded-full ${p.configured ? "bg-green-400" : "bg-red-400"}`} />
                  <span className={`text-xs ${p.configured ? "text-green-400" : "text-red-400"}`}>
                    {p.configured ? `Active (${p.source})` : "Not configured"}
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2 text-xs text-[var(--text-muted)] mb-3">
                <code className="bg-[var(--bg)] px-2 py-0.5 rounded font-mono">{p.envVar}</code>
                {p.maskedKey && (
                  <code className="bg-[var(--bg)] px-2 py-0.5 rounded font-mono">{p.maskedKey}</code>
                )}
              </div>

              {editing === p.envVar ? (
                <div className="flex gap-2">
                  <input
                    type="password"
                    value={keyInput}
                    onChange={(e) => setKeyInput(e.target.value)}
                    placeholder={`Paste ${p.envVar} here...`}
                    className="flex-1 bg-[var(--bg)] border border-[var(--border)] rounded px-3 py-1.5 text-sm text-[var(--text)] placeholder:text-[var(--text-dim)] focus:outline-none focus:border-[var(--accent)] font-mono"
                    autoFocus
                    onKeyDown={(e) => {
                      if (e.key === "Enter") saveKey(p.envVar);
                      if (e.key === "Escape") { setEditing(null); setKeyInput(""); }
                    }}
                  />
                  <button
                    onClick={() => saveKey(p.envVar)}
                    disabled={saving || !keyInput.trim()}
                    className="px-3 py-1.5 bg-[var(--accent)] text-white rounded text-xs font-medium disabled:opacity-50 hover:opacity-90"
                  >
                    {saving ? "..." : "Save"}
                  </button>
                  <button
                    onClick={() => { setEditing(null); setKeyInput(""); }}
                    className="px-3 py-1.5 bg-[var(--card-bg)] border border-[var(--border)] text-[var(--text-muted)] rounded text-xs hover:border-[var(--border-hover)]"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <div className="flex gap-2">
                  <button
                    onClick={() => { setEditing(p.envVar); setKeyInput(""); }}
                    className="px-3 py-1.5 bg-[var(--accent)]/20 text-[var(--accent)] rounded text-xs font-medium hover:bg-[var(--accent)]/30 transition-colors"
                  >
                    {p.configured ? "Change Key" : "Add Key"}
                  </button>
                  {p.configured && p.source === "settings" && (
                    <button
                      onClick={() => deleteKey(p.envVar)}
                      disabled={saving}
                      className="px-3 py-1.5 bg-red-900/20 text-red-400 rounded text-xs font-medium hover:bg-red-900/30 transition-colors disabled:opacity-50"
                    >
                      Remove
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <div className="mt-8 p-4 bg-[var(--card-bg)] border border-[var(--border)] rounded-lg">
        <h3 className="font-semibold text-sm mb-2">How it works</h3>
        <ul className="text-xs text-[var(--text-muted)] space-y-1">
          <li>• Keys saved here are stored in <code className="font-mono">reports/.settings/providers.json</code></li>
          <li>• They take priority over environment variables (.env.local)</li>
          <li>• Keys are never exposed in full to the browser — only the last 4 chars are shown</li>
          <li>• To use a key from environment instead, set it in <code className="font-mono">.env.local</code> and remove it here</li>
        </ul>
      </div>
    </main>
  );
}
