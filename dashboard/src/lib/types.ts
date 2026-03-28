// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
export interface Finding {
  id: string;
  title: string;
  severity: string;
  cwe?: string;
  cwe_id?: string;
  tool: string;
  url?: string;
  endpoint?: string;
  description?: string;
  evidence?: string;
  remediation?: string;
  cvss_score?: number;
  cvss_vector?: string;
  epss_score?: number;
  ai_analysis?: string;
  composite_score?: number;
  duplicate_of?: string;
  duplicate_count?: number;
  validation?: {
    gates_passed: number;
    gates_failed: number;
    gates_warned: number;
    gates_skipped: number;
    total_gates: number;
    overall_verdict: "PASS" | "WARN" | "FAIL" | "REJECTED";
    rejected_reasons: string[];
    results: Array<{
      gate: string;
      verdict: "PASS" | "FAIL" | "WARN" | "SKIP";
      reason: string;
      confidence: number;
      suggestion?: string;
    }>;
  };
}

export interface ScanReport {
  scan_date?: string;
  target?: string;
  profile?: string;
  tool_count?: number;
  finding_count?: number;
  findings: Finding[];
  severity_summary?: Record<string, number>;
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
  unknown: "#6b7280",
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];
