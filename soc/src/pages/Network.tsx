import { useState } from "react";
import { ArrowRight } from "lucide-react";
import { useNetwork, type AgentStats, type LiveFlow, type NetHost } from "../lib/api";
import { ago, duration } from "../lib/format";
import { href } from "../lib/router";
import { Card, CardHead, DemoTag, ErrorState, PageHead, Skeleton } from "../components/ui";
import { Topology } from "../components/Topology";

const KIND: Record<NetHost["kind"], string> = {
  honeypot: "Honeypot sensor (real container, reports telemetry)",
  production: "Real server — honeypots are firewalled away from it",
  decoy: "Decoy host — answered by the network theater, no machine behind it",
  soc: "SOC controller — LLM, RAG, telemetry and this dashboard",
};

export default function Network() {
  const { data, isLoading, error } = useNetwork();
  const [selName, setSelName] = useState<string | null>(null);
  if (error) return <ErrorState error={error} />;
  // re-read the host from the latest poll so its live stats keep updating
  const sel = data?.vlans.flatMap((v) => v.hosts).find((h) => h.name === selName) ?? null;
  const setSel = (h: NetHost) => setSelName(h.name);
  const vlanOf = (h: NetHost) => data?.vlans.find((v) => v.hosts.some((x) => x.name === h.name));
  return (
    <>
      <PageHead
        title="Network intelligence"
        sub={`The lab as it is right now: ${data?.agents.online ?? 0} of ${data?.agents.total ?? 0} node agents reporting live connections and load. Red = attackers, dashed red = pivots, blue = telemetry to the SOC.`}
      />
      <div className="grid grid-cols-[minmax(0,1fr)_320px] gap-4 max-xl:grid-cols-1">
        <Card className="overflow-hidden">
          {isLoading ? <Skeleton className="m-4 h-[560px]" /> : <Topology net={data} height={640} selected={sel?.name} onSelect={setSel} />}
        </Card>
        <div className="flex flex-col gap-4">
          <Card>
            <CardHead title={sel ? sel.name : "Select a host"} sub={sel ? KIND[sel.kind] : "Click any node on the map to inspect it."} />
            {sel && (
              <dl className="grid grid-cols-[100px_minmax(0,1fr)] gap-x-3 gap-y-2 p-4 pt-3 text-[12.5px]">
                <dt className="text-ink-3">Address</dt>
                <dd className="mono">{sel.ip}</dd>
                <dt className="text-ink-3">Segment</dt>
                <dd>
                  VLAN {vlanOf(sel)?.id} · {vlanOf(sel)?.name} <span className="mono text-ink-3">{vlanOf(sel)?.cidr}</span>
                </dd>
                <dt className="text-ink-3">Gateway</dt>
                <dd className="mono">{vlanOf(sel)?.gateway}</dd>
                {sel.ctid && (
                  <>
                    <dt className="text-ink-3">Proxmox</dt>
                    <dd className="mono">CT {sel.ctid}</dd>
                  </>
                )}
                {sel.kind === "honeypot" && (
                  <>
                    <dt className="text-ink-3">State</dt>
                    <dd>{sel.online ? `On · ${sel.sessions ?? 0} open sessions` : "Powered off or not reporting"}</dd>
                  </>
                )}
                {sel.agent && <AgentRows a={sel.agent} />}
                <dt className="text-ink-3">Events</dt>
                <dd className="num">{sel.events.toLocaleString()} in window</dd>
                {sel.note && (
                  <>
                    <dt className="text-ink-3">Notes</dt>
                    <dd>{sel.note}</dd>
                  </>
                )}
              </dl>
            )}
            {sel?.kind === "honeypot" && (
              <div className="flex gap-3 border-t border-line-2 px-4 py-3">
                <a className="link" href={href("telemetry", { q: sel.name })}>
                  Its events <ArrowRight className="size-3" />
                </a>
                <a className="link" href={href("graph")}>
                  In attack graph <ArrowRight className="size-3" />
                </a>
              </div>
            )}
          </Card>
          <Card>
            <CardHead title="Live connections" sub="TCP sessions open right now, from node agents" />
            <div className="grid gap-1 p-3">
              {data?.live_flows.filter((f) => f.kind !== "other").map((f) => <FlowRow key={`${f.from}-${f.to}-${f.port}`} f={f} />)}
              {data && data.live_flows.filter((f) => f.kind !== "other").length === 0 && (
                <p className="px-2 text-[12px] text-ink-3">
                  {data.agents.online ? "Nothing connected right now." : "No node agent reporting — install with scripts/agent-install.sh."}
                </p>
              )}
            </div>
          </Card>
          <Card>
            <CardHead title="Observed paths" sub="From lateral-movement telemetry" />
            <div className="grid gap-1 p-3">
              <div className="flex items-center justify-between rounded-lg px-2 py-1.5 text-[12.5px]">
                <span>
                  Internet → {data?.edge.name} → <span className="font-medium">ent-web-01</span>
                </span>
                <span className="num text-ink-3">{data?.entry_events ?? 0} events</span>
              </div>
              {data?.paths.map((p) => (
                <div key={p.from + p.to} className="flex items-center justify-between rounded-lg bg-red-soft px-2 py-1.5 text-[12.5px] text-red-ink">
                  <span>
                    {p.from} → <span className="font-semibold">{p.to}</span>
                  </span>
                  <span className="num">×{p.count}</span>
                </div>
              ))}
              {data && data.paths.length === 0 && <p className="px-2 text-[12px] text-ink-3">No lateral movement in this window.</p>}
            </div>
          </Card>
          <Card>
            <CardHead title="Segments" />
            <table className="table mt-2">
              <tbody>
                {data?.vlans.map((v) => (
                  <tr key={v.id}>
                    <td className="whitespace-nowrap font-medium">VLAN {v.id}</td>
                    <td>{v.name}</td>
                    <td className="mono whitespace-nowrap text-ink-3">{v.cidr}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="px-4 py-3 text-[11.5px] text-ink-3">
              WAN {data?.edge.wan} is the lab's public address; only TCP/22 is forwarded, to ent-web-01.
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}

const FLOW_STYLE: Record<LiveFlow["kind"], { label: string; cls: string }> = {
  attack: { label: "attacker", cls: "bg-red-soft text-red-ink" },
  pivot: { label: "pivot", cls: "bg-red-soft text-red-ink" },
  telemetry: { label: "telemetry", cls: "bg-blue-soft text-blue" },
  llm: { label: "LLM", cls: "bg-[#f0eefe] text-[#5b4cd6]" },
  other: { label: "other", cls: "bg-line-2 text-ink-2" },
};

function FlowRow({ f }: { f: LiveFlow }) {
  const st = FLOW_STYLE[f.kind];
  return (
    <div className={`flex items-center justify-between gap-2 rounded-lg px-2 py-1.5 text-[12.5px] ${st.cls}`}>
      <span className="min-w-0 truncate">
        {f.from === "outside" ? <span className="mono">{f.peer_ip}</span> : f.from} → <span className="font-semibold">{f.to}</span>
        <span className="mono text-[11px] opacity-70"> :{f.port}</span>
      </span>
      <span className="shrink-0 text-[11px] font-semibold">
        {st.label}
        {f.count > 1 ? ` ×${f.count}` : ""}
      </span>
    </div>
  );
}

function pct(used: number, total: number) {
  return total ? Math.round((used / total) * 100) : 0;
}

function bytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1 << 20) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1 << 30) return `${(n / (1 << 20)).toFixed(1)} MB`;
  return `${(n / (1 << 30)).toFixed(1)} GB`;
}

function Meter({ value }: { value: number }) {
  const color = value > 85 ? "bg-red" : value > 65 ? "bg-amber" : "bg-green";
  return (
    <span className="flex items-center gap-2">
      <span className="h-1.5 w-20 overflow-hidden rounded-full bg-line-2">
        <span className={`block h-1.5 rounded-full ${color}`} style={{ width: `${Math.min(100, value)}%` }} />
      </span>
      <span className="num">{value}%</span>
    </span>
  );
}

function AgentRows({ a }: { a: AgentStats }) {
  return (
    <>
      <dt className="text-ink-3">Agent</dt>
      <dd className="flex items-center gap-1.5">
        <span className={`size-2 rounded-full ${a.online ? "live-dot bg-green" : "bg-[#cbd5e1]"}`} />
        {a.online ? "reporting" : `silent since ${ago(a.last_seen)}`}
        {a.demo && <DemoTag />}
      </dd>
      {a.online && (
        <>
          <dt className="text-ink-3">CPU</dt>
          <dd><Meter value={Math.round(a.cpu_pct)} /></dd>
          <dt className="text-ink-3">Memory</dt>
          <dd><Meter value={pct(a.mem.used, a.mem.total)} /></dd>
          <dt className="text-ink-3">Disk</dt>
          <dd><Meter value={pct(a.disk.used, a.disk.total)} /></dd>
          <dt className="text-ink-3">Network</dt>
          <dd className="num">↓ {bytes(a.net.rx_bps)}/s · ↑ {bytes(a.net.tx_bps)}/s</dd>
          <dt className="text-ink-3">Inbound</dt>
          <dd className="num">{a.connections_in} open connection{a.connections_in === 1 ? "" : "s"}</dd>
          <dt className="text-ink-3">Listening</dt>
          <dd className="mono text-[12px]">{a.listening.join(", ") || "—"}</dd>
          <dt className="text-ink-3">Services</dt>
          <dd className="flex flex-wrap gap-1">
            {Object.entries(a.services).map(([k, v]) => (
              <span key={k} className={`pill h-[20px] px-1.5 text-[10.5px] ${v === "active" ? "bg-green-soft text-green-ink" : "bg-red-soft text-red-ink"}`}>
                {k}: {v}
              </span>
            ))}
            {Object.keys(a.services).length === 0 && "—"}
          </dd>
          <dt className="text-ink-3">Uptime</dt>
          <dd className="num">{duration(a.uptime_s)}</dd>
        </>
      )}
    </>
  );
}
