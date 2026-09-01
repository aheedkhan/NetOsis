export const CHART = {
  zeek: "#22d3ee",
  http: "#60a5fa",
  ssh: "#a78bfa",
  shell: "#34d399",
  sinkhole: "#fb7185",
  decision: "#fbbf24",
  other: "#64748b",
  grid: "rgba(148,163,184,0.12)",
  axis: "#64748b",
  tooltipBg: "rgba(10,15,28,0.95)",
  tooltipBorder: "rgba(34,211,238,0.25)",
};

export const PIE_COLORS = [
  "#22d3ee",
  "#60a5fa",
  "#a78bfa",
  "#34d399",
  "#fb7185",
  "#fbbf24",
  "#f472b6",
  "#94a3b8",
];

export function shortDataset(key: string) {
  return key.replace("cybersnare.", "");
}
