// ⚠️ Contenu généré par IA — validation humaine requise avant utilisation.
"use client";

import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
} from "chart.js";
import { SEVERITY_COLORS, SEVERITY_ORDER } from "@/lib/types";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip);

export default function CweBarChart({
  cweCounts,
}: {
  cweCounts: Record<string, number>;
}) {
  const entries = Object.entries(cweCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15);

  if (entries.length === 0) {
    return <p className="text-[var(--text-muted)] text-sm">No CWE data</p>;
  }

  return (
    <Bar
      data={{
        labels: entries.map(([cwe]) => cwe),
        datasets: [
          {
            data: entries.map(([, c]) => c),
            backgroundColor: "#f9731680",
            borderColor: "#f97316",
            borderWidth: 1,
            borderRadius: 4,
          },
        ],
      }}
      options={{
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            grid: { color: "#22222280" },
            ticks: { color: "#888", font: { size: 11 } },
          },
          y: {
            grid: { display: false },
            ticks: { color: "#ccc", font: { size: 11 } },
          },
        },
      }}
    />
  );
}
