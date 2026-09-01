// Restrained iOS/macOS system palette — used only where colour carries
// meaning (a dataset series, a status). No neon, no glow.
export const CHART = {
  zeek: "#64d2ff",
  http: "#0a84ff",
  ssh: "#bf5af2",
  shell: "#30d158",
  sinkhole: "#ff453a",
  decision: "#ff9f0a",
  other: "#8e8e93",
  grid: "rgba(255,255,255,0.08)",
  axis: "rgba(255,255,255,0.4)",
  tooltipBg: "#1c1c1f",
  tooltipBorder: "rgba(255,255,255,0.12)",
};

export const PIE_COLORS = [
  "#0a84ff",
  "#64d2ff",
  "#bf5af2",
  "#30d158",
  "#ff453a",
  "#ff9f0a",
  "#ff2d55",
  "#8e8e93",
];

// Bot-vs-human — the one place a strong colour split is meaningful rather
// than decorative: it is the actual verdict the deception platform acts on.
export const CAPABILITY_COLOR: Record<string, string> = {
  automated: "#ff453a",
  scripted: "#ff9f0a",
  interactive_operator: "#30d158",
};

export function shortDataset(key: string) {
  return key.replace("cybersnare.", "");
}
