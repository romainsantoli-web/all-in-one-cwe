// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import { SEVERITY_COLORS, SEVERITY_ORDER } from "@/lib/types";

ChartJS.register(ArcElement, Tooltip, Legend);

export default function SeverityChart({
  severityCounts,
}: {
  severityCounts: Record<string, number>;
}) {
  const labels = SEVERITY_ORDER.filter((s) => (severityCounts[s] || 0) > 0);
  const data = labels.map((s) => severityCounts[s] || 0);
  const colors = labels.map((s) => SEVERITY_COLORS[s]);

  if (data.length === 0) {
    return <p className="text-[var(--text-muted)] text-sm">No findings</p>;
  }

  return (
    <Doughnut
      data={{
        labels: labels.map((s) => s.charAt(0).toUpperCase() + s.slice(1)),
        datasets: [
          {
            data,
            backgroundColor: colors,
            borderColor: "transparent",
          },
        ],
      }}
      options={{
        responsive: true,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#888", font: { size: 11 } },
          },
        },
      }}
    />
  );
}
