// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
import { SEVERITY_COLORS } from "@/lib/types";

export default function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity.toLowerCase()] || SEVERITY_COLORS.info;
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase"
      style={{ backgroundColor: `${color}20`, color }}
    >
      {severity}
    </span>
  );
}
