import type { Level } from "./api";

export const TACTICS = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

/** Mirrors controller/attack_meta.py — the techniques NetOsis can actually emit. */
export const TECHNIQUE_TACTIC: Record<string, string> = {
  T1078: "Initial Access",
  T1110: "Credential Access",
  "T1059.004": "Execution",
  T1033: "Discovery",
  T1083: "Discovery",
  T1057: "Discovery",
  T1016: "Discovery",
  T1046: "Discovery",
  T1082: "Discovery",
  T1049: "Discovery",
  T1018: "Discovery",
  "T1087.001": "Discovery",
  T1518: "Discovery",
  T1005: "Collection",
  "T1074.001": "Collection",
  T1036: "Defense Evasion",
  "T1070.004": "Defense Evasion",
  "T1070.002": "Defense Evasion",
  "T1222.002": "Defense Evasion",
  T1105: "Command and Control",
  "T1003.008": "Credential Access",
  "T1552.001": "Credential Access",
  "T1552.003": "Credential Access",
  "T1021.004": "Lateral Movement",
  "T1053.003": "Persistence",
  "T1098.004": "Persistence",
  "T1548.001": "Privilege Escalation",
  "T1548.003": "Privilege Escalation",
  T1048: "Exfiltration",
};

export const TACTIC_COLOR: Record<string, string> = {
  "Initial Access": "#06b6d4",
  Execution: "#2563eb",
  Persistence: "#f59e0b",
  "Privilege Escalation": "#f43f5e",
  "Defense Evasion": "#8b5cf6",
  "Credential Access": "#dc2626",
  Discovery: "#0d9488",
  "Lateral Movement": "#6366f1",
  Collection: "#10b981",
  "Command and Control": "#8b5cf6",
  Exfiltration: "#ef4444",
  Impact: "#334155",
};

export const LEVEL: Record<Level, { label: string; fill: string; ink: string; soft: string; rank: number }> = {
  CRITICAL: { label: "Critical", fill: "#f05d68", ink: "#c8323f", soft: "#fdeef0", rank: 3 },
  HIGH: { label: "High", fill: "#f5a524", ink: "#9a5b00", soft: "#fef5e4", rank: 2 },
  MEDIUM: { label: "Medium", fill: "#2563eb", ink: "#2563eb", soft: "#eaf1fe", rank: 1 },
  LOW: { label: "Low", fill: "#10b981", ink: "#047857", soft: "#e8f8f2", rank: 0 },
};

export const SEVERITY: Record<string, { fill: string; ink: string; soft: string; label: string }> = {
  CRITICAL: { fill: "#f05d68", ink: "#c8323f", soft: "#fdeef0", label: "Critical" },
  HIGH: { fill: "#f5a524", ink: "#9a5b00", soft: "#fef5e4", label: "High" },
  MEDIUM: { fill: "#2563eb", ink: "#2563eb", soft: "#eaf1fe", label: "Medium" },
};

export function clock(ts: string): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

export function dateTime(ts: string): string {
  const d = new Date(ts);
  return `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${clock(ts)}`;
}

export function ago(ts: string | number | null | undefined, now = Date.now()): string {
  if (ts === null || ts === undefined || ts === "") return "never";
  const t = typeof ts === "number" ? ts * 1000 : new Date(ts).getTime();
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function duration(sec: number): string {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
}

export function compact(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}

export const EVENT_LABEL: Record<string, string> = {
  auth_failure: "Failed login",
  auth_success: "Login",
  command: "Command",
  lateral_movement: "Lateral movement",
  deception_action: "Deception response",
};

export const DECEPTION_LABEL: Record<string, string> = {
  D01: "Expose decoy host",
  D02: "Expose fake service",
  D03: "Plant credential",
  D04: "Plant document",
  D05: "Deploy canary",
  D06: "Increase telemetry",
  D07: "Reveal network segment",
};
