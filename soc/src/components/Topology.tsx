import { useMemo } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/base.css";
import { Globe2, Lock, Radar, Server, ShieldHalf, MonitorCog } from "lucide-react";
import type { NetHost, Network } from "../lib/api";

const VLAN_STYLE: Record<number, { tint: string; ink: string; short: string }> = {
  10: { tint: "#eaf1fe", ink: "#2563eb", short: "FIN" },
  20: { tint: "#e8f8f2", ink: "#047857", short: "OPS" },
  30: { tint: "#fef5e4", ink: "#9a5b00", short: "ENT" },
  40: { tint: "#f0eefe", ink: "#5b4cd6", short: "SOC" },
};
// Reading order follows the attack: ENT (the only WAN-exposed segment) sits next
// to the firewall, so the entry path and the usual ENT -> FIN pivot are short
// and never cross another segment.
const VLAN_ORDER = [30, 10, 20, 40];

type HostData = { host: NetHost; vlan: number; compact: boolean; onSelect?: (h: NetHost) => void; selected: boolean };

function HostNode({ data }: NodeProps<Node<HostData>>) {
  const h = data.host;
  const v = VLAN_STYLE[data.vlan] ?? VLAN_STYLE[30];
  const Icon = h.kind === "production" ? Lock : h.kind === "soc" ? MonitorCog : h.kind === "decoy" ? Radar : Server;
  const on = h.kind === "honeypot" || h.agent ? h.online : undefined;
  const a = h.agent?.online ? h.agent : undefined;
  const memPct = a && a.mem.total ? Math.round((a.mem.used / a.mem.total) * 100) : null;
  return (
    <div
      role="button"
      aria-label={`${h.name}, ${h.kind}`}
      className={`relative flex w-full cursor-pointer items-center gap-2 rounded-lg border bg-white text-left transition-shadow hover:shadow-[var(--shadow-float)] ${
        data.compact ? "h-[46px] px-2" : "h-[58px] px-2.5"
      } ${h.kind === "decoy" ? "border-dashed" : ""} ${data.selected ? "ring-2 ring-blue" : ""}`}
      style={{ borderColor: h.kind === "honeypot" ? v.ink + "55" : "#e4e9f1" }}
      title={`${h.name} · ${h.ip}`}
    >
      <Handle type="target" position={Position.Top} className="!size-1 !border-0 !bg-transparent" />
      <Handle type="source" position={Position.Bottom} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="l" type="target" position={Position.Left} className="!size-1 !border-0 !bg-transparent" />
      <Handle id="r" type="source" position={Position.Right} className="!size-1 !border-0 !bg-transparent" />
      <span className="grid size-7 shrink-0 place-items-center rounded-md" style={{ background: v.tint, color: v.ink }}>
        <Icon className="size-3.5" strokeWidth={2} />
      </span>
      <span className="min-w-0">
        <span className="block truncate text-[11.5px] font-semibold leading-tight">{h.name}</span>
        <span className="mono block truncate text-[10.5px] leading-tight text-ink-3">{h.ip}</span>
        {!data.compact && (
          <span className="block truncate text-[10.5px] leading-tight text-ink-3">
            {a
              ? `${h.kind === "honeypot" ? `${h.sessions ?? 0} sess · ` : ""}cpu ${Math.round(a.cpu_pct)}% · mem ${memPct}%`
              : h.kind === "honeypot"
                ? on
                  ? `on · ${h.sessions ?? 0} sessions`
                  : "powered off"
                : h.kind === "production"
                  ? "real · untouched"
                  : h.kind === "decoy"
                    ? "decoy (answered by theater)"
                    : on === false
                      ? "agent silent"
                      : "SOC"}
          </span>
        )}
      </span>
      {on !== undefined && (
        <span
          className={`absolute right-1.5 top-1.5 size-1.5 rounded-full ${on ? "bg-green" : "bg-[#cbd5e1]"}`}
          title={a ? "Agent reporting live" : on ? "Honeypot heartbeat" : "Not reporting"}
        />
      )}
    </div>
  );
}

function VlanNode({ data }: NodeProps<Node<{ vlan: Network["vlans"][number]; compact: boolean }>>) {
  const v = VLAN_STYLE[data.vlan.id] ?? VLAN_STYLE[10];
  return (
    <div className="h-full w-full rounded-xl border bg-white/60" style={{ borderColor: v.ink + "33", background: v.tint + "66" }}>
      <Handle type="target" position={Position.Top} className="!size-1 !border-0 !bg-transparent" />
      <div className="flex items-baseline justify-between px-2.5 pt-2">
        <span className="whitespace-nowrap text-[11px] font-semibold" style={{ color: v.ink }}>
          {v.short} · VLAN {data.vlan.id}
        </span>
        {!data.compact && <span className="mono text-[10px] text-ink-3">{data.vlan.cidr}</span>}
      </div>
    </div>
  );
}

function EdgeNode({ data }: NodeProps<Node<{ label: string; sub: string; kind: "internet" | "fw" }>>) {
  const Icon = data.kind === "internet" ? Globe2 : ShieldHalf;
  return (
    <div className="flex flex-col items-center gap-1.5">
      <Handle type="target" position={Position.Left} className="!size-1 !border-0 !bg-transparent" />
      <Handle type="source" position={Position.Right} className="!size-1 !border-0 !bg-transparent" />
      <span
        className={`grid size-11 place-items-center rounded-xl border ${data.kind === "fw" ? "border-ink bg-ink text-white" : "border-line bg-white text-ink-2"}`}
      >
        <Icon className="size-5" strokeWidth={1.8} />
      </span>
      <span className="text-center leading-tight">
        <span className="block text-[11.5px] font-semibold">{data.label}</span>
        <span className="mono block text-[10px] text-ink-3">{data.sub}</span>
      </span>
    </div>
  );
}

const nodeTypes = { host: HostNode, vlan: VlanNode, edge: EdgeNode };

export function Topology({
  net,
  height,
  compact = false,
  selected,
  onSelect,
}: {
  net: Network | undefined;
  height: number;
  compact?: boolean;
  selected?: string | null;
  onSelect?: (h: NetHost) => void;
}) {
  const { nodes, edges } = useMemo(() => build(net, compact, selected ?? null, onSelect), [net, compact, selected, onSelect]);
  if (!net) return <div style={{ height }} />;
  return (
    <div style={{ height }} className="w-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: compact ? 0.06 : 0.12 }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        onNodeClick={(_, n) => {
          if (n.type === "host") onSelect?.((n.data as HostData).host);
        }}
        zoomOnScroll={!compact}
        panOnDrag={!compact}
        zoomOnDoubleClick={!compact}
        preventScrolling={!compact}
        minZoom={0.4}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
      >
        {!compact && <Background gap={22} size={1} color="#dfe5ee" />}
        {!compact && <Controls showInteractive={false} position="bottom-right" />}
      </ReactFlow>
    </div>
  );
}

function build(net: Network | undefined, compact: boolean, selected: string | null, onSelect?: (h: NetHost) => void) {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  if (!net) return { nodes, edges };

  const hostW = compact ? 150 : 190;
  const hostH = compact ? 46 : 58;
  const gap = compact ? 8 : 10;
  const pad = 10;
  const vlanTop = compact ? 0 : 0;
  const x0 = compact ? 178 : 260;
  const colGap = compact ? 14 : 22;
  const vlans = (VLAN_ORDER.map((id) => net.vlans.find((v) => v.id === id)).filter(Boolean) as Network["vlans"]).map((v) =>
    compact ? { ...v, hosts: v.hosts.filter((h) => h.kind === "honeypot" || h.kind === "soc") } : v,
  );
  const colW = hostW + pad * 2;
  const tallest = Math.max(...vlans.map((v) => v.hosts.length));
  const vlanH = 30 + tallest * (hostH + gap) + pad;
  const midY = vlanTop + vlanH + (compact ? 7 : 11);

  nodes.push({ id: "internet", type: "edge", position: { x: 0, y: midY - 40 }, data: { label: "Internet", sub: "attackers", kind: "internet" } });
  nodes.push({ id: "fw", type: "edge", position: { x: compact ? 82 : 120, y: midY - 40 }, data: { label: net.edge.name, sub: net.edge.wan, kind: "fw" } });

  const attacked = net.entry_events > 0;
  edges.push({
    id: "internet-fw",
    source: "internet",
    target: "fw",
    animated: attacked,
    style: { stroke: attacked ? "#f05d68" : "#cbd5e1", strokeWidth: attacked ? 2 : 1.4 },
    markerEnd: { type: MarkerType.ArrowClosed, color: attacked ? "#f05d68" : "#cbd5e1", width: 14, height: 14 },
  });

  vlans.forEach((v, i) => {
    // 2 x 2 grid: ENT FIN / OPS SOC keeps text at a readable scale
    const vx = x0 + (i % 2) * (colW + colGap);
    const vy = vlanTop + Math.floor(i / 2) * (vlanH + (compact ? 14 : 22));
    nodes.push({
      id: `vlan-${v.id}`,
      type: "vlan",
      position: { x: vx, y: vy },
      data: { vlan: v, compact },
      style: { width: colW, height: vlanH },
      selectable: false,
    });
    edges.push({
      id: `fw-vlan-${v.id}`,
      source: "fw",
      target: `vlan-${v.id}`,
      type: "smoothstep",
      style: { stroke: "#cbd5e1", strokeWidth: 1.2 },
    });
    v.hosts.forEach((h, j) => {
      nodes.push({
        id: `host-${h.name}`,
        type: "host",
        parentId: `vlan-${v.id}`,
        extent: "parent",
        position: { x: pad, y: 30 + j * (hostH + gap) },
        data: { host: h, vlan: v.id, compact, onSelect, selected: selected === h.name },
        style: { width: hostW },
      });
    });
  });

  // entry point: what the WAN port-forward actually reaches
  if (attacked) {
    edges.push({
      id: "fw-entry",
      source: "fw",
      target: "host-ent-web-01",
      targetHandle: "l",
      type: "smoothstep",
      animated: true,
      style: { stroke: "#f05d68", strokeWidth: 2 },
      label: compact ? undefined : `${net.entry_events} events`,
      labelStyle: { fontSize: 10, fill: "#c8323f", fontWeight: 600 },
      labelBgStyle: { fill: "#fff" },
    });
  }
  // observed lateral movement, from telemetry
  for (const p of net.paths) {
    edges.push({
      id: `pivot-${p.from}-${p.to}`,
      source: `host-${p.from}`,
      target: `host-${p.to}`,
      sourceHandle: "r",
      targetHandle: "l",
      type: "smoothstep",
      animated: true,
      style: { stroke: "#c8323f", strokeWidth: 2.2, strokeDasharray: "6 4" },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#c8323f", width: 14, height: 14 },
      label: compact ? undefined : `pivot ×${p.count}`,
      labelStyle: { fontSize: 10, fill: "#c8323f", fontWeight: 600 },
      labelBgStyle: { fill: "#fff" },
      zIndex: 10,
    });
  }
  // live TCP connections reported by node agents (refreshes every few seconds)
  const hostIds = new Set(nodes.filter((n) => n.type === "host").map((n) => n.id));
  const liveAttack = net.live_flows.filter((f) => f.kind === "attack");
  if (liveAttack.length) {
    edges[0] = { ...edges[0], animated: true, style: { stroke: "#f05d68", strokeWidth: 2.4 } };
  }
  for (const f of net.live_flows) {
    const to = `host-${f.to}`;
    const from = f.from === "outside" ? "fw" : `host-${f.from}`;
    if (!hostIds.has(to) || (from !== "fw" && !hostIds.has(from))) continue;
    if (f.kind === "attack") {
      edges.push({
        id: `live-${f.from}-${f.to}-${f.port}`,
        source: "fw",
        target: to,
        targetHandle: "l",
        type: "smoothstep",
        animated: true,
        style: { stroke: "#e11d48", strokeWidth: 2.6 },
        label: compact ? undefined : `live · ${f.count} conn`,
        labelStyle: { fontSize: 10, fill: "#be123c", fontWeight: 700 },
        labelBgStyle: { fill: "#fff" },
        zIndex: 11,
      });
    } else if (f.kind === "pivot" && !net.paths.some((p) => p.from === f.from && p.to === f.to)) {
      edges.push({
        id: `live-${f.from}-${f.to}-${f.port}`,
        source: from,
        target: to,
        sourceHandle: "r",
        targetHandle: "l",
        type: "smoothstep",
        animated: true,
        style: { stroke: "#c8323f", strokeWidth: 2.2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#c8323f", width: 14, height: 14 },
        label: compact ? undefined : "live pivot",
        labelStyle: { fontSize: 10, fill: "#c8323f", fontWeight: 700 },
        labelBgStyle: { fill: "#fff" },
        zIndex: 10,
      });
    } else if ((f.kind === "telemetry" || f.kind === "llm") && !compact) {
      edges.push({
        id: `live-${f.from}-${f.to}-${f.port}`,
        source: from,
        target: to,
        type: "default",
        animated: true,
        style: { stroke: f.kind === "llm" ? "#8b5cf6" : "#60a5fa", strokeWidth: 1, opacity: 0.55, strokeDasharray: "3 4" },
        zIndex: 1,
      });
    }
  }
  return { nodes, edges };
}
