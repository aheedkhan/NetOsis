export type TimelineEntry = {
  timestamp?: string;
  dataset?: string;
  action?: string;
  actor_key?: string;
  arm?: string;
  level?: string;
  source_ip?: string;
  technique?: string;
  engage?: string;
};

export type ArmStats = {
  events: number;
  actors: number;
  transitions: number;
  shell_commands: number;
  datasets: Record<string, number>;
};

export type MilestoneReport = {
  generated_at: string;
  total_events: number;
  unique_actors: number;
  time_range: { first: string | null; last: string | null };
  arms: Record<string, ArmStats>;
  manifest_transitions: number;
  top_techniques: Record<string, number>;
  top_engage: Record<string, number>;
  dataset_counts: Record<string, number>;
};

export type VolumePoint = {
  ts: number;
  time: string;
  total: number;
  zeek?: number;
  http?: number;
  ssh?: number;
  shell?: number;
  sinkhole?: number;
  decision?: number;
  other?: number;
};

export type ActorRow = {
  actor_key: string;
  events: number;
  last_seen?: string;
  level: string;
  arm: string;
  top_technique?: string | null;
};

export type SiemAnalytics = {
  volume: VolumePoint[];
  top_actors: ActorRow[];
  levels: Record<string, number>;
  transitions?: TransitionEntry[];
  patterns?: PatternAnalytics;
};

export type KillChainTactic = {
  id: string;
  name: string;
  count: number;
};

export type AttackPatternStep = {
  label: string;
  dataset: string;
  technique?: string | null;
  technique_name?: string | null;
  tactic?: string | null;
  level?: string | null;
};

export type AttackPattern = {
  count: number;
  steps: AttackPatternStep[];
  signature: string;
};

export type EngageMatrix = {
  levels: string[];
  engages: string[];
  cells: { level: string; engage: string; count: number }[];
};

export type TechniqueMatrix = {
  levels: string[];
  techniques: string[];
  cells: { level: string; technique: string; count: number }[];
};

export type DatasetFlowEdge = {
  from: string;
  to: string;
  count: number;
};

export type PatternAnalytics = {
  kill_chain: KillChainTactic[];
  attack_patterns: AttackPattern[];
  engage_matrix: EngageMatrix;
  technique_matrix: TechniqueMatrix;
  dataset_flow: DatasetFlowEdge[];
};

export type LadderStep = {
  id: string;
  name: string;
  engage: string;
  summary: string;
};

export type TransitionEntry = {
  timestamp?: string;
  actor_key?: string;
  from_level?: string;
  to_level?: string;
  rationale?: string;
  trigger?: string;
};

export type SurfaceState = {
  ssh: { exposed: boolean; auth: string };
  https: { exposed: boolean; auth: string };
  shell: { exposed: boolean; runtime?: string };
  sinkhole: boolean;
};

export type DeceptionState = {
  global_level: string;
  policy?: string;
  manifest_id?: string;
  rationale?: string;
  arm?: string;
  ladder: LadderStep[];
  surfaces: SurfaceState;
  transitions: TransitionEntry[];
  actors: unknown[];
  events_seen?: number;
};

export type DashboardData = {
  report: MilestoneReport;
  timeline: TimelineEntry[];
  analytics: SiemAnalytics;
  deception: DeceptionState;
};

export type GraphNode = {
  id: string;
  label?: string;
  type: "core" | "surface" | "machine" | "step";
  ip?: string;
  events?: number;
  level?: string;
  arm?: string;
  top_technique?: string | null;
  surfaces?: Record<string, number>;
  first_seen?: string;
  last_seen?: string;
  technique_name?: string | null;
  tactic?: string | null;
  surface?: string;
  engage?: string | null;
  timestamp?: string;
  repeat?: number;
  index?: number;
};

export type GraphEdge = {
  from: string;
  to: string;
  weight?: number;
  type?: string;
  step?: number;
  label?: string;
};

export type AttackGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  machine_count: number;
  machines?: GraphNode[];
};

export type GraphStepLog = {
  id: string;
  index: number;
  timestamp?: string;
  label: string;
  dataset: string;
  action?: string;
  technique?: string | null;
  technique_name?: string | null;
  tactic?: string | null;
  engage?: string | null;
  level?: string | null;
  surface?: string;
  source_ip?: string;
  repeat?: number;
};

export type ActorAttackGraph = {
  actor_key: string;
  label: string;
  ip: string;
  events: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  steps: GraphStepLog[];
  logs: GraphStepLog[];
  operation?: OperationMap;
};

export type OperationPhase = {
  id: string;
  label: string;
  subtitle: string;
  color: string;
};

export type OperationNode = {
  id: string;
  type: "attacker" | "operation";
  label: string;
  ip?: string;
  zone?: string;
  phase: string;
  lane?: number;
  technique_name?: string | null;
  tactic?: string | null;
  surface?: string;
  level?: string | null;
  engage?: string | null;
  timestamp?: string;
  repeat?: number;
  index?: number;
};

export type OperationEdge = {
  from: string;
  to: string;
  type: "infiltration" | "exfiltration" | "lateral";
  order: number;
  phase: string;
  label?: string;
};

export type OperationMap = {
  phases: OperationPhase[];
  zones: { id: string; label: string; range?: string }[];
  attacker_zone: string;
  nodes: OperationNode[];
  edges: OperationEdge[];
  phase_counts: Record<string, number>;
};
