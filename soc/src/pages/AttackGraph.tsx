import { useMemo, useState } from "react";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import "@xyflow/react/dist/base.css";
import { ArrowRight, Server, Waypoints } from "lucide-react";
import { useActors, useGraph, type GraphEdge, type GraphNode } from "../lib/api";
import { href } from "../lib/router";
import { LEVEL, TACTICS, TACTIC_COLOR } from "../lib/format";
import { Card, CardHead, DemoTag, Empty, ErrorState, LevelPill, PageHead, Skeleton } from "../components/ui";
import { Avatar } from "../components/Avatar";

type NData = { n: GraphNode; dim: boolean; active: boolean };

function ActorNode({ data }: NodeProps<Node<NData>>) {
  const n = data.n;
  const lvl = n.level ?? "LOW";
  return (
    <div
      className={`flex w-[200px] items-center gap-2 rounded-lg border bg-white px-2 py-1.5 transition-opacity ${data.dim ? "opacity-25" : ""} ${data.active ? "ring-2 ring-blue" : ""}`}
      style={{ borderColor: LEVEL[lvl].fill + "88" }}
    >
      <Handle type="source" position={Position.Right} className="!size-1 !border-0 !bg-transparent" />
      <Avatar seed={n.label} persona={personaId(n.persona)} level={lvl} size={28} />
      <span className="min-w-0">
        <span className="mono block truncate text-[11.5px] font-semibold">{n.label}</span>
        <span className="block truncate text-[10.5px] text-ink-3">
          {n.persona} · {n.weight} ev
        </span>
      </span>
    </div>
  );
}
function HostNode({ data }: NodeProps<Node<NData>>) {
  const n = data.n;
  return (
    <div className={`w-[180px] rounded-xl border-2 border-ink bg-white px-3 py-2.5 transition-opacity ${data.dim ? "opacity-25" : ""} ${data.active ? "ring-2 ring-blue" : ""}`}>
      <Handle type="target" position={Position.Left} className="!size-1 !border-0 !bg-transparent" />
      <Handle type="source" position={Position.Right} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="t" type="target" position={Position.Top} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="b" type="source" position={Position.Bottom} className="!size-1 !border-0 !bg-transparent" />
      <span className="flex items-center gap-2">
        <Server className="size-4 text-ink" />
        <span className="text-[12.5px] font-semibold">{n.label}</span>
      </span>
      <span className="mt-0.5 block text-[11px] text-ink-3">
        <span className="mono">{n.ip}</span> · VLAN {n.vlan} · {n.weight} events
      </span>
    </div>
  );
}
function TechNode({ data }: NodeProps<Node<NData>>) {
  const n = data.n;
  const c = TACTIC_COLOR[n.tactic ?? ""] ?? "#64748b";
  return (
    <div
      className={`w-[210px] rounded-lg border bg-white px-2.5 py-1.5 transition-opacity ${data.dim ? "opacity-25" : ""} ${data.active ? "ring-2 ring-blue" : ""}`}
      style={{ borderColor: c + "66", borderLeft: `3px solid ${c}` }}
    >
      <Handle type="target" position={Position.Left} className="!size-1 !border-0 !bg-transparent" />
      <span className="flex items-baseline justify-between gap-2">
        <span className="mono text-[11px] font-semibold">{n.label}</span>
        <span className="num text-[10.5px] text-ink-3">{n.weight}</span>
      </span>
      <span className="block truncate text-[11px] text-ink-2">{n.name}</span>
    </div>
  );
}
const nodeTypes = { actor: ActorNode, honeypot: HostNode, technique: TechNode };

function personaId(label?: string) {
  const m: Record<string, string> = {
    "Lateral mover": "lateral_mover", Dropper: "dropper", Entrenching: "persistence", "Covering tracks": "cleaner",
    "Credential hunter": "credential_hunter", Explorer: "explorer", Scanner: "scanner", "Brute-forcer": "brute_forcer",
  };
  return m[label ?? ""] ?? "opportunist";
}

export default function AttackGraph({ params }: { params?: URLSearchParams }) {
  const { data, isLoading, error } = useGraph();
  const { data: actors } = useActors();
  const [focus, setFocus] = useState<string | null>(params?.get("ip") ? `actor:${params.get("ip")}` : null);
  const [limit, setLimit] = useState(12);

  const { nodes, edges, hidden } = useMemo(() => layout(data?.nodes ?? [], data?.edges ?? [], focus, limit), [data, focus, limit]);
  const focused = data?.nodes.find((n) => n.id === focus) ?? null;
  const actor = focused?.type === "actor" ? actors?.find((a) => `actor:${a.ip}` === focused.id) : null;

  if (error) return <ErrorState error={error} />;
  return (
    <>
      <PageHead
        title="Attack graph"
        sub="Who reached which honeypot, and what they did there. Left: attackers · centre: honeypots · right: ATT&CK techniques by tactic. Click any node to isolate its paths."
        right={
          <>
            <label className="flex items-center gap-2 text-[12px] text-ink-3">
              Attackers shown
              <select value={limit} onChange={(e) => setLimit(+e.target.value)} className="field h-[30px] text-[12.5px]">
                {[8, 12, 25, 50].map((n) => (
                  <option key={n} value={n}>
                    top {n}
                  </option>
                ))}
              </select>
            </label>
            {focus && (
              <button className="btn" onClick={() => setFocus(null)}>
                Clear focus
              </button>
            )}
          </>
        }
      />
      <div className="grid grid-cols-[minmax(0,1fr)_300px] gap-4 max-xl:grid-cols-1">
        <Card className="overflow-hidden">
          {isLoading ? (
            <Skeleton className="m-4 h-[640px]" />
          ) : nodes.length === 0 ? (
            <Empty title="No attacker activity in this window" icon={<Waypoints className="size-6" />} />
          ) : (
            <div className="h-[calc(100vh-190px)] min-h-[560px]">
              <ReactFlow
                nodes={nodes}
                edges={edges}
                nodeTypes={nodeTypes}
                fitView
                fitViewOptions={{ padding: 0.08 }}
                nodesConnectable={false}
                onNodeClick={(_, n) => setFocus((f) => (f === n.id ? null : n.id))}
                onPaneClick={() => setFocus(null)}
                minZoom={0.2}
                proOptions={{ hideAttribution: true }}
              >
                <Background gap={22} size={1} color="#e4e9f1" />
                <Controls showInteractive={false} position="bottom-right" />
              </ReactFlow>
            </div>
          )}
        </Card>
        <div className="flex flex-col gap-4">
          <Card>
            <CardHead title={focused ? focused.label : "Legend"} sub={focused ? focused.type : `${hidden} lower-risk attackers hidden — raise the limit to see them`} />
            <div className="grid gap-2 p-4 pt-3 text-[12px] text-ink-2">
              {!focused && (
                <>
                  <Legend color="#c8323f" dashed label="Lateral movement between honeypots" />
                  <Legend color="#14243a" label="Logged in and ran commands" />
                  <Legend color="#94a3b8" label="Only guessed passwords" />
                  <Legend color="#2563eb" label="Technique observed on that honeypot" />
                </>
              )}
              {actor && (
                <>
                  <div className="flex items-center gap-2">
                    <LevelPill level={actor.level} /> {actor.persona.label} {actor.demo && <DemoTag />}
                  </div>
                  <p className="text-ink-3">{actor.persona.summary}</p>
                  <p>
                    {actor.command_count} commands · {actor.sessions} sessions · {actor.techniques.length} techniques
                  </p>
                  <a className="link" href={href("sessions", { ip: actor.ip })}>
                    Replay their sessions <ArrowRight className="size-3" />
                  </a>
                </>
              )}
              {focused?.type === "technique" && (
                <>
                  <p>{focused.name}</p>
                  <p className="text-ink-3">{focused.tactic} · {focused.weight} events</p>
                  <a className="link" href={href("attack", { technique: focused.label })}>
                    Inspect in ATT&CK <ArrowRight className="size-3" />
                  </a>
                </>
              )}
              {focused?.type === "honeypot" && (
                <a className="link" href={href("telemetry", { q: focused.label })}>
                  Events on {focused.label} <ArrowRight className="size-3" />
                </a>
              )}
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}

function Legend({ color, label, dashed }: { color: string; label: string; dashed?: boolean }) {
  return (
    <span className="flex items-center gap-2">
      <svg width="26" height="6" aria-hidden>
        <line x1="0" y1="3" x2="26" y2="3" stroke={color} strokeWidth="2.2" strokeDasharray={dashed ? "5 3" : undefined} />
      </svg>
      {label}
    </span>
  );
}

function layout(all: GraphNode[], allEdges: GraphEdge[], focus: string | null, limit: number) {
  const actorsAll = all.filter((n) => n.type === "actor").sort((a, b) => LEVEL[b.level ?? "LOW"].rank - LEVEL[a.level ?? "LOW"].rank || b.weight - a.weight);
  const keepActors = new Set(actorsAll.slice(0, limit).map((n) => n.id));
  if (focus?.startsWith("actor:")) keepActors.add(focus);
  const hidden = actorsAll.length - keepActors.size;
  const hosts = all.filter((n) => n.type === "honeypot");
  const techs = all.filter((n) => n.type === "technique").sort((a, b) => TACTICS.indexOf(a.tactic as never) - TACTICS.indexOf(b.tactic as never) || b.weight - a.weight);
  const edges0 = allEdges.filter((e) => (!e.source.startsWith("actor:") || keepActors.has(e.source)));

  // neighbourhood of the focused node (two hops through honeypots)
  let keep: Set<string> | null = null;
  if (focus) {
    keep = new Set([focus]);
    for (const e of edges0) if (e.source === focus || e.target === focus) keep.add(e.source).add(e.target);
    if (focus.startsWith("actor:")) {
      // techniques this attacker used appear on hosts they touched
      for (const e of edges0) if (keep.has(e.source) && e.source.startsWith("host:") && e.relation === "observed") keep.add(e.target);
    }
  }
  const dim = (id: string) => (keep ? !keep.has(id) : false);

  const nodes: Node[] = [];
  const actorList = actorsAll.filter((n) => keepActors.has(n.id));
  const colH = (count: number, step: number) => count * step;
  const H = Math.max(colH(actorList.length, 52), colH(techs.length, 50), 360);
  actorList.forEach((n, i) =>
    nodes.push({ id: n.id, type: "actor", position: { x: 0, y: (H - colH(actorList.length, 52)) / 2 + i * 52 }, data: { n, dim: dim(n.id), active: focus === n.id } }),
  );
  hosts.forEach((n, i) =>
    nodes.push({ id: n.id, type: "honeypot", position: { x: 420, y: H / 2 - (hosts.length * 130) / 2 + i * 130 }, data: { n, dim: dim(n.id), active: focus === n.id } }),
  );
  techs.forEach((n, i) =>
    nodes.push({ id: n.id, type: "technique", position: { x: 820, y: (H - colH(techs.length, 50)) / 2 + i * 50 }, data: { n, dim: dim(n.id), active: focus === n.id } }),
  );

  const maxW = Math.max(1, ...edges0.map((e) => e.weight));
  const edges: Edge[] = edges0.map((e) => {
    const w = 1 + (e.weight / maxW) * 3;
    const off = keep ? !(keep.has(e.source) && keep.has(e.target)) : false;
    const base = { id: `${e.source}>${e.target}>${e.relation}`, source: e.source, target: e.target, zIndex: e.relation === "lateral" ? 5 : 0 };
    if (e.relation === "lateral")
      return {
        ...base,
        sourceHandle: "b",
        targetHandle: "t",
        type: "smoothstep",
        animated: true,
        label: `pivot ×${e.weight}`,
        labelStyle: { fontSize: 10, fill: "#c8323f", fontWeight: 600 },
        style: { stroke: "#c8323f", strokeWidth: 2.4, strokeDasharray: "6 4", opacity: off ? 0.1 : 1 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#c8323f" },
      };
    const color = e.relation === "observed" ? "#2563eb" : e.relation === "guess" ? "#94a3b8" : "#14243a";
    return {
      ...base,
      type: "default",
      style: { stroke: color, strokeWidth: w, opacity: off ? 0.06 : e.relation === "observed" ? 0.35 : 0.5 },
    };
  });
  return { nodes, edges, hidden };
}
