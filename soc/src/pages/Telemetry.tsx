import { useEffect, useMemo, useState } from "react";
import { Braces, Download, Pause, Play, Search, X } from "lucide-react";
import { useEvents, useWindow, WINDOW_LABEL, type SocEvent } from "../lib/api";
import { href } from "../lib/router";
import { EVENT_LABEL, dateTime } from "../lib/format";
import { Card, DemoTag, Empty, ErrorState, PageHead, Skeleton } from "../components/ui";

const TYPES = ["command", "auth_failure", "auth_success", "lateral_movement", "deception_action"];
const SENSORS = ["ent-web-01", "finance-db-01", "ops-app-01"];

export default function Telemetry({ params }: { params?: URLSearchParams }) {
  const { win } = useWindow();
  const [q, setQ] = useState(params?.get("q") ?? "");
  const [query, setQuery] = useState(params?.get("q") ?? "");
  const [types, setTypes] = useState<string[]>(params?.get("type")?.split(",").filter(Boolean) ?? []);
  const [sensor, setSensor] = useState("");
  const [live, setLive] = useState(true);
  const [picked, setPicked] = useState<SocEvent | null>(null);

  useEffect(() => {
    const p = params?.get("q");
    if (p !== null && p !== undefined) {
      setQ(p);
      setQuery(p);
    }
    const t = params?.get("type");
    if (t) setTypes(t.split(","));
  }, [params]);

  const { data, isLoading, error, isFetching } = useEvents(
    { q: query || undefined, type: types.length ? types.join(",") : undefined, sensor: sensor || undefined, limit: "2000" },
    live ? 4000 : 0,
  );
  const rows = useMemo(() => [...(data ?? [])].reverse(), [data]);

  function exportAs(kind: "json" | "csv") {
    const name = `netosis-telemetry-${win}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.${kind}`;
    let body: string;
    if (kind === "json") body = JSON.stringify(rows, null, 2);
    else {
      const cols = ["seq", "timestamp", "event_type", "source_ip", "sensor", "target_host", "session_id", "command", "technique", "technique_name", "demo"];
      const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
      body = [cols.join(","), ...rows.map((r) => cols.map((c) => esc((r as unknown as Record<string, unknown>)[c])).join(","))].join("\n");
    }
    const url = URL.createObjectURL(new Blob([body], { type: kind === "json" ? "application/json" : "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <PageHead
        title="Telemetry explorer"
        sub={`Every event the honeypots shipped · ${WINDOW_LABEL[win].toLowerCase()} · newest first`}
        right={
          <>
            <button className="btn" onClick={() => setLive((v) => !v)} aria-pressed={!live}>
              {live ? <Pause className="size-3.5" /> : <Play className="size-3.5" />}
              {live ? "Pause updates" : "Resume updates"}
            </button>
            <button className="btn" onClick={() => exportAs("csv")} disabled={!rows.length}>
              <Download className="size-3.5" /> CSV
            </button>
            <button className="btn" onClick={() => exportAs("json")} disabled={!rows.length}>
              <Download className="size-3.5" /> JSON
            </button>
          </>
        }
      />
      <Card className="flex max-h-[calc(100vh-170px)] min-h-[540px] flex-col">
        <div className="flex flex-wrap items-center gap-2 border-b border-line-2 px-4 py-3">
          <form
            className="relative"
            onSubmit={(e) => {
              e.preventDefault();
              setQuery(q.trim());
            }}
          >
            <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-ink-3" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="IP, command, technique, host…" className="field w-72 pl-8" aria-label="Search events" />
          </form>
          {query && (
            <button className="btn" onClick={() => { setQ(""); setQuery(""); }}>
              “{query}” <X className="size-3" />
            </button>
          )}
          <span className="mx-1 h-5 w-px bg-line" />
          {TYPES.map((t) => (
            <button
              key={t}
              className="btn"
              aria-pressed={types.includes(t)}
              onClick={() => setTypes((cur) => (cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t]))}
            >
              {EVENT_LABEL[t]}
            </button>
          ))}
          <select value={sensor} onChange={(e) => setSensor(e.target.value)} className="field h-[30px] text-[12.5px]" aria-label="Honeypot">
            <option value="">All honeypots</option>
            {SENSORS.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <span className="num ml-auto text-[12px] text-ink-3">
            {isFetching && live ? "updating · " : ""}
            {rows.length.toLocaleString()} events{rows.length >= 2000 ? " (newest 2,000)" : ""}
          </span>
        </div>
        <div className="grid min-h-0 flex-1 grid-cols-[minmax(0,1fr)_auto]">
          <div className="min-h-0 overflow-auto">
            {error ? (
              <ErrorState error={error} />
            ) : isLoading ? (
              <div className="grid gap-2 p-4">{Array.from({ length: 10 }).map((_, i) => <Skeleton key={i} className="h-7" />)}</div>
            ) : rows.length === 0 ? (
              <Empty title="No events match" icon={<Braces className="size-6" />}>
                Widen the time window or clear filters.
              </Empty>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Honeypot</th>
                    <th>Command / detail</th>
                    <th>Technique</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.slice(0, 600).map((e) => (
                    <tr key={e.seq} data-selected={picked?.seq === e.seq} onClick={() => setPicked(e)} className="cursor-pointer">
                      <td className="num whitespace-nowrap text-ink-3">{dateTime(e.timestamp)}</td>
                      <td className="whitespace-nowrap">{EVENT_LABEL[e.event_type] ?? e.event_type}</td>
                      <td className="mono whitespace-nowrap">
                        {e.source_ip} {e.demo && <DemoTag />}
                      </td>
                      <td className="whitespace-nowrap">{e.target_host}</td>
                      <td className="mono max-w-[420px] truncate">
                        {e.event_type === "deception_action" ? `${e.extra?.action} · ${e.extra?.reason ?? ""}` : e.command || (e.extra?.username ? `user ${e.extra.username}` : "")}
                      </td>
                      <td className="mono whitespace-nowrap text-ink-2">{e.technique ?? ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          {picked && (
            <aside className="flex w-[420px] min-w-0 flex-col border-l border-line max-lg:w-[320px]">
              <div className="flex items-center justify-between border-b border-line-2 px-4 py-2.5">
                <span className="text-[13px] font-semibold">Event #{picked.seq}</span>
                <span className="flex items-center gap-2">
                  <a className="link" href={href("sessions", { id: picked.session_id })}>
                    Session
                  </a>
                  <button className="btn h-7 px-2" onClick={() => setPicked(null)} aria-label="Close inspector">
                    <X className="size-3.5" />
                  </button>
                </span>
              </div>
              <pre className="mono min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all bg-[#fbfcfe] p-4 text-[11.5px] leading-relaxed text-ink-2">
                <JsonView value={picked} />
              </pre>
            </aside>
          )}
        </div>
      </Card>
    </>
  );
}

function JsonView({ value }: { value: unknown }) {
  const text = JSON.stringify(value, null, 2);
  // light syntax colouring: keys, strings, numbers/booleans
  const parts = text.split(/("(?:\\.|[^"\\])*"(?:\s*:)?|\b-?\d+(?:\.\d+)?\b|\btrue\b|\bfalse\b|\bnull\b)/g);
  return (
    <>
      {parts.map((p, i) => {
        if (/^".*":$/.test(p.trim())) return <span key={i} className="text-ink">{p}</span>;
        if (p.startsWith('"')) return <span key={i} className="text-cyan-ink">{p}</span>;
        if (/^(-?\d|true|false|null)/.test(p)) return <span key={i} className="text-blue">{p}</span>;
        return <span key={i}>{p}</span>;
      })}
    </>
  );
}
