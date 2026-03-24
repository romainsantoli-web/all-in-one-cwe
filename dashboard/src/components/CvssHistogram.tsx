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

function scoreToBucket(score: number): number {
  if (score >= 10) return 9;
  return Math.floor(score);
}

function bucketColor(idx: number): string {
  if (idx >= 9) return "#ef4444"; // critical
  if (idx >= 7) return "#f97316"; // high
  if (idx >= 4) return "#eab308"; // medium
  if (idx >= 1) return "#22c55e"; // low
  return "#3b82f6"; // info
}

export default function CvssHistogram({
  findings,
}: {
  findings: { cvss_score?: number }[];
}) {
  const buckets = Array(10).fill(0);
  let scored = 0;

  for (const f of findings) {
    if (f.cvss_score != null && f.cvss_score > 0) {
      buckets[scoreToBucket(f.cvss_score)]++;
      scored++;
    }
  }

  if (scored === 0) {
    return <p className="text-[var(--text-muted)] text-sm">No CVSS scores</p>;
  }

  const labels = [
    "0–1",
    "1–2",
    "2–3",
    "3–4",
    "4–5",
    "5–6",
    "6–7",
    "7–8",
    "8–9",
    "9–10",
  ];

  return (
    <Bar
      data={{
        labels,
        datasets: [
          {
            data: buckets,
            backgroundColor: buckets.map((_, i) => `${bucketColor(i)}90`),
            borderColor: buckets.map((_, i) => bucketColor(i)),
            borderWidth: 1,
            borderRadius: 4,
          },
        ],
      }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: "#888", font: { size: 11 } },
            title: { display: true, text: "CVSS Score", color: "#888" },
          },
          y: {
            grid: { color: "#22222280" },
            ticks: { color: "#888", font: { size: 11 }, stepSize: 1 },
            title: { display: true, text: "Count", color: "#888" },
          },
        },
      }}
    />
  );
}
