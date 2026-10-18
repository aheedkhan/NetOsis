import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useRef, useState } from "react";

/* ----------------------------------------------------------------- contracts
   Every type mirrors a controller/soc.py response. Nothing in the UI invents
   a number: if the API does not return it, the UI shows an empty state. */

export type Level = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Mode = "live" | "demo" | "mixed" | "empty";
export type WindowKey = "1h" | "24h" | "7d" | "all";

export interface Persona {
  id: string;
  label: string;
  summary: string;
  tags: string[];
  evidence: Record<string, string[]>;
}

export interface Geo {
  ip: string;
  kind: "public" | "private" | "reserved" | "invalid";
  mapped: boolean;
  source: string | null;
  label?: string;
  country?: string;
  iso?: string;
  city?: string;
  lat?: number;
  lng?: number;
  approximate?: boolean;
  accuracy_km?: number;
}

export interface Actor {
  id: string;
  ip: string;
  demo: boolean;
  geo: Geo;
  first_seen: string;
  last_seen: string;
  persona: Persona;
  risk_score: number;
  level: Level;
  auth_failures: number;
  auth_successes: number;
  usernames: string[];
  sensors: string[];
  hosts: string[];
  sessions: number;
  event_count: number;
  command_count: number;
  high_risk: number;
  techniques: string[];
  deception: string[];
  recent_commands: string[];
  canary_hits: number;
  paths_created: string[];
}

export interface SocEvent {
  seq: number;
  timestamp: string;
  sensor: string;
  session_id: string;
  actor_id: string;
  source_ip: string;
  target_host: string;
  target_ip: string;
  event_type: "auth_failure" | "auth_success" | "command" | "lateral_movement" | "deception_action" | string;
  command: string;
  result: string;
  technique: string | null;
  technique_name: string | null;
  technique_confidence?: number;
  behavior?: string | null;
  demo?: boolean;
  extra?: {
    risk_category?: string;
    username?: string;
    from_host?: string;
    llm_fallback?: boolean;
    action?: string;
    name?: string;
    reason?: string;
    level?: Level;
    [k: string]: unknown;
  };
}

export interface Session {
  id: string;
  ip: string;
  sensor: string;
  host: string;
  start: string;
  last: string;
  commands: number;
  failed_logins: number;
  logged_in: boolean;
  user: string | null;
  techniques: string[];
  high_risk: number;
  pivot_to: string[];
  demo: boolean;
  deception: string[];
  active: boolean;
  duration_s: number;
  outcome: "shell" | "failed login" | "connected";
}

export interface Alert {
  seq: number;
  timestamp: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  kind: string;
  title: string;
  detail: string;
  ip: string;
  host: string;
  session: string;
  technique: string | null;
  demo: boolean;
}

export interface SensorState {
  name: string;
  online: boolean;
  sessions: number;
  last_seen: number | null;
  ctid: number | null;
  demo: boolean;
}

export interface Overview {
  now: number;
  window: number | null;
  mode: Mode;
  kpis: { attacks: number; sessions_live: number; sources: number; commands: number; high_risk: number; deception: number };
  previous: { attacks: number; sources: number; commands: number; high_risk: number; deception: number } | null;
  definitions: Record<string, string>;
  risk: Record<Level, number>;
  series: { all: number[]; high: number[]; step_s: number; start: number };
  sensors: SensorState[];
  sensors_online: number;
  sensors_total: number;
  alerts_total: number;
  critical: number;
}

export interface AttackTech {
  id: string;
  name: string;
  tactic: string;
  count: number;
  actors: number;
  last_seen: string;
  example: string;
  top_commands: string[];
}
export interface Attack {
  tactics: { tactic: string; techniques: AttackTech[]; count: number }[];
  total_techniques: number;
  total_events: number;
  supported: { id: string; name: string; tactic: string }[];
}

export interface GeoPoint {
  ip: string;
  lat: number;
  lng: number;
  country?: string;
  iso?: string;
  city?: string;
  source: string;
  demo: boolean;
  level: Level;
  events: number;
  sessions: number;
  persona: string;
  hosts: string[];
  last_seen: string;
  arc: boolean;
  dest: { label: string; lat: number; lng: number; source: string } | null;
}
export interface GeoData {
  points: GeoPoint[];
  unmapped: { internal: number; public_unmapped: number; reserved: number };
  site: { label: string; lat: number; lng: number; source: string } | null;
  demo_site: { label: string; lat: number; lng: number; source: string } | null;
  countries: { country: string; actors: number }[];
  geodb: { available: boolean; database: string | null };
}

export interface NetHost {
  name: string;
  ip: string;
  kind: "honeypot" | "production" | "decoy" | "soc";
  ctid?: number;
  note?: string;
  online?: boolean;
  sessions?: number;
  last_seen?: number | null;
  events: number;
  agent?: AgentStats;
}
export interface AgentStats {
  online: boolean;
  last_seen: number;
  uptime_s: number;
  cpu_pct: number;
  cpus: number;
  load: number[];
  mem: { total: number; used: number };
  disk: { total: number; used: number };
  net: { rx_bps: number; tx_bps: number };
  services: Record<string, string>;
  listening: number[];
  addresses: string[];
  gateway: string | null;
  version: string;
  demo: boolean;
  connections_in: number;
}
export interface AgentRow extends Omit<AgentStats, "connections_in"> {
  name: string;
  role: string;
  ctid: number | null;
  hostname: string;
  flows: { dir: "in" | "out"; peer: string; port: number; count: number }[];
}
export interface LiveFlow {
  from: string;
  to: string;
  port: number;
  count: number;
  kind: "attack" | "pivot" | "telemetry" | "llm" | "other";
  peer_ip: string | null;
}
export interface Network {
  edge: { name: string; wan: string; note: string };
  outside: { name: string; note: string };
  vlans: { id: number; name: string; cidr: string; gateway: string; hosts: NetHost[] }[];
  paths: { from: string; to: string; count: number }[];
  entry_events: number;
  live_flows: LiveFlow[];
  agents: { online: number; total: number };
}

export interface GraphNode {
  id: string;
  type: "actor" | "honeypot" | "technique";
  label: string;
  weight: number;
  level?: Level;
  persona?: string;
  ip?: string;
  vlan?: number;
  name?: string;
  tactic?: string;
  demo?: boolean;
}
export interface GraphEdge {
  source: string;
  target: string;
  relation: "lateral" | "login" | "guess" | "session" | "observed";
  weight: number;
}
export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Deception {
  ladder: { id: string; min_score: number; name: string; description: string; fired: number; last: string | null }[];
  history: SocEvent[];
  weights: Record<string, number>;
  policy_error: string | null;
}

export interface AiStatus {
  ollama: { url: string; reachable: boolean; models: string[]; error?: string };
  model: string;
  commands: number;
  llm_answered: number;
  deterministic: number;
  recent_llm: { ts: string; command: string; sensor: string }[];
}

export interface Health {
  controller: { uptime_s: number; events_stored: number; events_total: number; max_events: number };
  sensors: SensorState[];
  agents: AgentRow[];
  geodb: { available: boolean; database: string | null };
  site_configured: boolean;
  ingest_token_set: boolean;
  proxmox_configured: boolean;
}

/* ------------------------------------------------------------------ window */

export const WINDOW_LABEL: Record<WindowKey, string> = {
  "1h": "Last hour",
  "24h": "Last 24 hours",
  "7d": "Last 7 days",
  all: "Everything held",
};

export const WindowContext = createContext<{ win: WindowKey; setWin: (w: WindowKey) => void }>({
  win: "24h",
  setWin: () => undefined,
});
export const useWindow = () => useContext(WindowContext);

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status} ${path}`);
  return (await res.json()) as T;
}

function useApi<T>(name: string, extra = "", refetch = 4000) {
  const { win } = useWindow();
  const sep = extra ? "&" : "";
  return useQuery<T>({
    queryKey: [name, win, extra],
    queryFn: () => get<T>(`/api/${name}?window=${win}${sep}${extra}`),
    refetchInterval: refetch,
    placeholderData: (prev) => prev,
  });
}

export const useOverview = () => useApi<Overview>("overview");
export const useActors = () => useApi<Actor[]>("actors");
export const useSessions = () => useApi<Session[]>("sessions");
export const useAlerts = (limit = 40) => useApi<Alert[]>("alerts", `limit=${limit}`);
export const useAttack = () => useApi<Attack>("attack", "", 6000);
export const useGeo = () => useApi<GeoData>("geo", "", 6000);
export const useNetwork = () => useApi<Network>("network");
export const useGraph = () => useApi<Graph>("graph", "", 6000);
export const useDeception = () => useApi<Deception>("deception");
export const useAi = () => useApi<AiStatus>("ai", "", 8000);
export const useHealth = () => useApi<Health>("health", "", 8000);
export const useEvents = (params: Record<string, string | undefined>, refetch = 4000) => {
  const qs = Object.entries(params)
    .filter(([, v]) => v)
    .map(([k, v]) => `${k}=${encodeURIComponent(v!)}`)
    .join("&");
  return useApi<SocEvent[]>("events", qs, refetch);
};

/* ------------------------------------------------------------ live stream */

/** Live tail over SSE. Returns the newest events (deduped, oldest first). */
export function useLiveEvents(max = 120) {
  const [events, setEvents] = useState<SocEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const qc = useQueryClient();
  const lastInvalidate = useRef(0);
  useEffect(() => {
    let es: EventSource | null = null;
    let stop = false;
    get<SocEvent[]>(`/api/events?limit=${max}&window=all`)
      .then((e) => !stop && setEvents(e))
      .catch(() => undefined);
    es = new EventSource("/api/stream");
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.addEventListener("ev", (m) => {
      const ev = JSON.parse((m as MessageEvent).data) as SocEvent;
      setEvents((prev) => (prev.some((p) => p.seq === ev.seq) ? prev : [...prev, ev].slice(-max)));
      const now = Date.now();
      if (now - lastInvalidate.current > 1500) {
        // new telemetry: refresh the summaries promptly instead of waiting for the poll
        lastInvalidate.current = now;
        qc.invalidateQueries({ predicate: (q) => q.queryKey[0] !== "events" });
      }
    });
    return () => {
      stop = true;
      es?.close();
    };
  }, [max, qc]);
  return { events, connected };
}
