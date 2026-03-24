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

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip);

export default function ToolBarChart({
  toolCounts,
}: {
  toolCounts: Record<string, number>;
}) {
  const entries = Object.entries(toolCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12);

  if (entries.length === 0) {
    return <p className="text-[var(--text-muted)] text-sm">No tool data</p>;
  }

  return (
    <Bar
      data={{
        labels: entries.map(([t]) => t),
        datasets: [
          {
            data: entries.map(([, c]) => c),
            backgroundColor: "#6366f180",
            borderColor: "#6366f1",
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
