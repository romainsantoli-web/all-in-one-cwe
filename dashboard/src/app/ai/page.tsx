// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import LLMChat from "@/components/LLMChat";

export default function AIPage() {
  return (
    <main className="h-[calc(100vh-2rem)] flex flex-col px-6 py-6">
      <div className="mb-4">
        <h1 className="text-2xl font-bold">AI Assistant</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Chat with AI about security findings, CVEs, and attack strategies. Supports multi-provider streaming.
        </p>
      </div>
      <div className="flex-1 bg-[var(--card-bg)] border border-[var(--border)] rounded-lg overflow-hidden flex flex-col min-h-0">
        <LLMChat />
      </div>
    </main>
  );
}
