import { CircleCheck, CircleDashed, CircleX } from "lucide-react";
import { useHealth } from "../lib/api";
import { ago, duration } from "../lib/format";
import { Card, CardHead, DemoTag, ErrorState, PageHead, Skeleton } from "../components/ui";

export default function System() {
  const { data, isLoading, error } = useHealth();
  if (error) return <ErrorState error={error} />;
  if (isLoading || !data) return <Skeleton className="h-[420px]" />;
  const checks: { ok: boolean | null; label: string; detail: string }[] = [
    { ok: data.ingest_token_set, label: "Ingest token", detail: data.ingest_token_set ? "Honeypots must authenticate to send telemetry" : "Not set — every honeypot is refused" },
    { ok: data.sensors.some((s) => s.online), label: "Honeypots reporting", detail: `${data.sensors.filter((s) => s.online).length} of ${data.sensors.length} sent a heartbeat in the last 70 s` },
    { ok: data.agents.some((a) => a.online) ? true : null, label: "Node agents", detail: data.agents.length ? `${data.agents.filter((a) => a.online).length} of ${data.agents.length} reporting (outbound only, no open port)` : "None installed — run scripts/agent-install.sh on each node" },
    { ok: data.proxmox_configured ? true : null, label: "Honeypot auto-wake", detail: data.proxmox_configured ? "Proxmox token configured" : "Optional — Proxmox token not configured, powered-off honeypots won't wake on pivot" },
    { ok: data.geodb.available ? true : null, label: "GeoIP database", detail: data.geodb.available ? data.geodb.database! : "Optional — public IPs are listed but not placed on the map" },
    { ok: data.site_configured ? true : null, label: "Lab location", detail: data.site_configured ? "Set — live arcs end at the lab" : "Optional — NETOSIS_SITE_LAT/LNG not set, live arcs hidden" },
  ];
  return (
    <>
      <PageHead title="System & policies" sub="Health of the controller and every honeypot, and what is (and isn't) configured." />
      <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-4 max-xl:grid-cols-1">
        <Card>
          <CardHead title="Checks" />
          <ul className="grid gap-1 p-3">
            {checks.map((c) => (
              <li key={c.label} className="flex items-start gap-3 rounded-lg px-2 py-2">
                {c.ok === true ? <CircleCheck className="mt-0.5 size-4 text-green" /> : c.ok === false ? <CircleX className="mt-0.5 size-4 text-red" /> : <CircleDashed className="mt-0.5 size-4 text-ink-3" />}
                <span>
                  <span className="block text-[13px] font-medium">{c.label}</span>
                  <span className="block text-[12px] text-ink-3">{c.detail}</span>
                </span>
              </li>
            ))}
          </ul>
        </Card>
        <Card>
          <CardHead title="Controller" />
          <dl className="grid grid-cols-[150px_minmax(0,1fr)] gap-x-3 gap-y-2 p-4 pt-3 text-[12.5px] max-sm:grid-cols-[110px_minmax(0,1fr)]">
            <dt className="text-ink-3">Uptime</dt>
            <dd className="num">{duration(data.controller.uptime_s)}</dd>
            <dt className="text-ink-3">Events held</dt>
            <dd className="num">
              {data.controller.events_stored.toLocaleString()} of {data.controller.max_events.toLocaleString()} (oldest drop off first)
            </dd>
            <dt className="text-ink-3">Events received</dt>
            <dd className="num">{data.controller.events_total.toLocaleString()} since history began</dd>
            <dt className="text-ink-3">Persistence</dt>
            <dd className="mono break-all text-[12px]">data/soc/events.jsonl · state.json</dd>
          </dl>
        </Card>
      </div>
      <Card className="mt-4">
        <CardHead title="Honeypots" sub="From each sensor's 20-second heartbeat" />
        <div className="overflow-x-auto">
        <table className="table mt-2">
          <thead>
            <tr>
              <th>Honeypot</th>
              <th>Proxmox</th>
              <th>Status</th>
              <th>Open sessions</th>
              <th>Last heartbeat</th>
            </tr>
          </thead>
          <tbody>
            {data.sensors.map((s) => (
              <tr key={s.name}>
                <td className="font-medium">
                  {s.name} {s.demo && <DemoTag />}
                </td>
                <td className="mono">{s.ctid ? `CT ${s.ctid}` : "—"}</td>
                <td>
                  <span className="inline-flex items-center gap-1.5">
                    <span className={`size-2 rounded-full ${s.online ? "live-dot bg-green" : "bg-[#cbd5e1]"}`} />
                    {s.online ? "Reporting" : s.last_seen ? "Silent (powered off?)" : "Never reported"}
                  </span>
                </td>
                <td className="num">{s.sessions}</td>
                <td className="num text-ink-3">{s.last_seen ? ago(s.last_seen) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        <p className="px-4 py-3 text-[11.5px] text-ink-3">
          Secrets (ingest token, Proxmox token) live in controller/.env with mode 600 and are never sent to this page; only whether they are set.
        </p>
      </Card>
      <Card className="mt-4">
        <CardHead title="Node agents" sub="Each node pushes its state every 10 s; agents open no port, so nothing can connect to them" />
        <div className="overflow-x-auto">
          <table className="table mt-2">
            <thead>
              <tr>
                <th>Node</th>
                <th>Role</th>
                <th>Status</th>
                <th>CPU</th>
                <th>Memory</th>
                <th>Connections</th>
                <th>Services</th>
                <th>Last report</th>
              </tr>
            </thead>
            <tbody>
              {data.agents.map((a) => (
                <tr key={a.name}>
                  <td className="font-medium whitespace-nowrap">
                    {a.name} {a.demo && <DemoTag />}
                    <div className="mono text-[11px] text-ink-3">{a.addresses.join(", ")}</div>
                  </td>
                  <td>{a.role}{a.ctid ? <span className="mono text-ink-3"> · CT {a.ctid}</span> : null}</td>
                  <td>
                    <span className="inline-flex items-center gap-1.5">
                      <span className={`size-2 rounded-full ${a.online ? "live-dot bg-green" : "bg-[#cbd5e1]"}`} />
                      {a.online ? "Reporting" : "Silent"}
                    </span>
                  </td>
                  <td className="num">{a.online ? `${Math.round(a.cpu_pct)}%` : "—"}</td>
                  <td className="num">{a.online && a.mem.total ? `${Math.round((a.mem.used / a.mem.total) * 100)}%` : "—"}</td>
                  <td className="num">{a.online ? `${a.flows.filter((f) => f.dir === "in").reduce((n, f) => n + f.count, 0)} in · ${a.flows.filter((f) => f.dir === "out").reduce((n, f) => n + f.count, 0)} out` : "—"}</td>
                  <td className="text-[12px]">
                    {Object.entries(a.services).map(([k, v]) => (
                      <span key={k} className={`mr-1 whitespace-nowrap ${v === "active" ? "text-green-ink" : "text-red-ink"}`}>{k}: {v}</span>
                    ))}
                  </td>
                  <td className="num text-ink-3 whitespace-nowrap">{ago(a.last_seen)}</td>
                </tr>
              ))}
              {data.agents.length === 0 && (
                <tr>
                  <td colSpan={8} className="text-ink-3">No node agent has reported yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
