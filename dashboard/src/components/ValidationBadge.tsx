// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { useState } from "react";
import type { Finding } from "@/lib/types";

type Validation = NonNullable<Finding["validation"]>;
type ValidationResult = Validation["results"][number];

const VERDICT_STYLES: Record<
  string,
  { bg: string; text: string; label: string }
> = {
  PASS: { bg: "bg-green-500/20", text: "text-green-400", label: "✓ Validated" },
  WARN: { bg: "bg-yellow-500/20", text: "text-yellow-400", label: "⚠ Warning" },
  FAIL: { bg: "bg-red-500/20", text: "text-red-400", label: "✗ Failed" },
  REJECTED: { bg: "bg-red-700/30", text: "text-red-300", label: "⊘ Rejected" },
};

const GATE_ICON: Record<string, string> = {
  PASS: "✓",
  FAIL: "✗",
  WARN: "⚠",
  SKIP: "—",
};

export default function ValidationBadge({
  validation,
}: {
  validation?: Validation;
}) {
  const [showTooltip, setShowTooltip] = useState(false);

  if (!validation) {
    return (
      <span className="text-xs text-[var(--text-muted)] opacity-50">—</span>
    );
  }

  const style = VERDICT_STYLES[validation.overall_verdict] || VERDICT_STYLES.FAIL;
  const ratio = `${validation.gates_passed}/${validation.total_gates}`;

  return (
    <div
      className="relative inline-block"
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      <span
        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${style.bg} ${style.text}`}
      >
        {style.label} {ratio}
      </span>

      {showTooltip && (
        <div className="absolute z-50 bottom-full left-0 mb-2 w-72 p-3 rounded-lg shadow-xl bg-[var(--card-bg)] border border-[var(--border)] text-xs">
          <div className="font-semibold mb-2 text-[var(--text)]">
            Validation Gates ({ratio})
          </div>
          <div className="space-y-1">
            {validation.results.map((r, i) => {
              const icon = GATE_ICON[r.verdict] || "?";
              const color =
                r.verdict === "PASS"
                  ? "text-green-400"
                  : r.verdict === "FAIL"
                    ? "text-red-400"
                    : r.verdict === "WARN"
                      ? "text-yellow-400"
                      : "text-[var(--text-muted)]";
              return (
                <div key={i} className="flex items-start gap-2">
                  <span className={`${color} font-mono`}>{icon}</span>
                  <div className="flex-1">
                    <span className="font-medium text-[var(--text)]">
                      {r.gate}
                    </span>
                    <span className="text-[var(--text-muted)] ml-1">
                      — {r.reason}
                    </span>
                    {r.suggestion && (
                      <div className="text-yellow-400/80 mt-0.5">
                        💡 {r.suggestion}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
          {validation.rejected_reasons.length > 0 && (
            <div className="mt-2 pt-2 border-t border-[var(--border)] text-red-400">
              {validation.rejected_reasons.map((r, i) => (
                <div key={i}>✗ {r}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
