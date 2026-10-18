import { useMemo, useState } from "react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDownUp, ArrowRight, MapPin, SquareTerminal } from "lucide-react";
import { useActors, useEvents, useSessions, type Session } from "../lib/api";
import { go, href } from "../lib/router";
import { ago, duration, DECEPTION_LABEL, LEVEL } from "../lib/format";
import { Card, CardHead, DemoTag, Empty, ErrorState, LevelPill, PageHead, Skeleton } from "../components/ui";
import { Replay } from "../components/Replay";
import { Avatar } from "../components/Avatar";

const col = createColumnHelper<Session & { level: keyof typeof LEVEL }>();

export default function Sessions({ params }: { params?: URLSearchParams }) {
  const { data: sessions, isLoading, error } = useSessions();
  const { data: actors } = useActors();
  const [onlyActive, setOnlyActive] = useState(params?.get("active") === "1");
  const [onlyShell, setOnlyShell] = useState(false);
  const [ipFilter, setIpFilter] = useState(params?.get("ip") ?? "");
  const [sorting, setSorting] = useState<SortingState>([{ id: "last", desc: true }]);
  const selectedId = params?.get("id") ?? null;

  const actorBy = useMemo(() => new Map(actors?.map((a) => [a.ip, a])), [actors]);
  const rows = useMemo(
    () =>
      (sessions ?? [])
        .filter((s) => (!onlyActive || s.active) && (!onlyShell || s.logged_in) && (!ipFilter || s.ip.includes(ipFilter)))
        .map((s) => ({ ...s, level: actorBy.get(s.ip)?.level ?? "LOW" })),
    [sessions, onlyActive, onlyShell, ipFilter, actorBy],
  );

  const columns = useMemo(
    () => [
      col.accessor("ip", {
        header: "Source",
        cell: (c) => (
          <span className="block min-w-0">
            <span className="flex items-center gap-2">
              <span className={`size-1.5 shrink-0 rounded-full ${c.row.original.active ? "live-dot bg-green" : "bg-[#cbd5e1]"}`} title={c.row.original.active ? "Activity in the last 5 minutes" : "Ended"} />
              <span className="mono">{c.getValue()}</span>
              {c.row.original.demo && <DemoTag />}
            </span>
            <span className="num block pl-3.5 text-[11px] text-ink-3">{ago(c.row.original.last)}</span>
          </span>
        ),
      }),
      col.accessor("host", {
        header: "Honeypot · outcome",
        cell: (c) => {
          const s = c.row.original;
          return (
            <span className="block min-w-0" title={[s.host, ...s.pivot_to].join(" → ")}>
              <span className="block truncate">
                {s.host}
                {s.pivot_to.length > 0 && <span className="ml-1 font-medium text-red-ink">+{s.pivot_to.length} pivot</span>}
              </span>
              <span className={`block truncate text-[11px] ${s.outcome === "shell" ? "text-ink-2" : "text-ink-3"}`}>
                {s.outcome === "shell" ? `shell · ${s.user ?? "?"} · ${s.commands} cmds` : s.outcome}
              </span>
            </span>
          );
        },
      }),
      col.accessor("level", { header: "Risk", cell: (c) => <LevelPill level={c.getValue()} />, sortingFn: (a, b) => LEVEL[a.original.level].rank - LEVEL[b.original.level].rank }),
    ],
    [],
  );

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: (r) => r.id,
  });

  const selected = (sessions ?? []).find((s) => s.id === selectedId) ?? null;

  return (
    <>
      <PageHead title="Live sessions" sub="Every SSH connection to a honeypot. Select one to replay exactly what the attacker did." />
      <div className="grid grid-cols-[minmax(0,0.95fr)_minmax(0,1.2fr)] gap-4 max-xl:grid-cols-1">
        <Card className="flex max-h-[calc(100vh-170px)] min-h-[520px] flex-col">
          <div className="flex flex-wrap items-center gap-2 border-b border-line-2 px-4 py-3">
            <input value={ipFilter} onChange={(e) => setIpFilter(e.target.value)} placeholder="Filter by source IP" className="field w-48" aria-label="Filter by source IP" />
            <button className="btn" aria-pressed={onlyActive} onClick={() => setOnlyActive((v) => !v)}>
              Active now
            </button>
            <button className="btn" aria-pressed={onlyShell} onClick={() => setOnlyShell((v) => !v)}>
              Got a shell
            </button>
            <span className="num ml-auto text-[12px] text-ink-3">{rows.length} sessions</span>
          </div>
          <div className="min-h-0 flex-1 overflow-auto">
            {error ? (
              <ErrorState error={error} />
            ) : isLoading ? (
              <div className="grid gap-2 p-4">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-8" />)}</div>
            ) : rows.length === 0 ? (
              <Empty title="No sessions match" icon={<SquareTerminal className="size-6" />}>
                Try a wider time window or clear the filters.
              </Empty>
            ) : (
              <table className="table w-full table-fixed">
                <thead>
                  {table.getHeaderGroups().map((hg) => (
                    <tr key={hg.id}>
                      {hg.headers.map((h) => (
                        <th key={h.id} className="first:w-[42%] last:w-[104px]" aria-sort={h.column.getIsSorted() === "asc" ? "ascending" : h.column.getIsSorted() === "desc" ? "descending" : "none"}>
                          <button className="inline-flex items-center gap-1 hover:text-ink" onClick={h.column.getToggleSortingHandler()}>
                            {flexRender(h.column.columnDef.header, h.getContext())}
                            <ArrowDownUp className={`size-3 ${h.column.getIsSorted() ? "text-blue" : "opacity-40"}`} />
                          </button>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {table.getRowModel().rows.map((r) => (
                    <tr
                      key={r.id}
                      data-selected={r.id === selectedId}
                      onClick={() => go("sessions", { id: r.id, ...(ipFilter ? { ip: ipFilter } : {}) })}
                      className="cursor-pointer"
                    >
                      {r.getVisibleCells().map((c) => (
                        <td key={c.id} className="max-w-0 whitespace-nowrap">{flexRender(c.column.columnDef.cell, c.getContext())}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </Card>

        {selected ? (
          <SessionDetail s={selected} />
        ) : (
          <Card className="grid min-h-[520px] place-items-center">
            <Empty title="Select a session to replay it" icon={<SquareTerminal className="size-6" />}>
              The replay steps through the attacker's commands in order, shows what the honeypot answered, and lights up each ATT&CK tactic as
              it is reached.
            </Empty>
          </Card>
        )}
      </div>
    </>
  );
}

function SessionDetail({ s }: { s: Session }) {
  const { data: events, isLoading } = useEvents({ session: s.id, limit: "2000", window: undefined }, s.active ? 3000 : 0);
  const { data: actors } = useActors();
  const actor = actors?.find((a) => a.ip === s.ip);
  return (
    <Card className="flex max-h-[calc(100vh-170px)] min-h-[520px] flex-col">
      <div className="flex items-start gap-4 border-b border-line-2 p-4">
        {actor && <Avatar seed={actor.ip} persona={actor.persona.id} level={actor.level} size={56} />}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-[15px] font-semibold">{s.ip}</span>
            {actor && <LevelPill level={actor.level} />}
            {s.demo && <DemoTag />}
            {s.active && (
              <span className="pill" style={{ background: "#e8f8f2", color: "#047857" }}>
                <span className="live-dot size-1.5 rounded-full bg-green" /> Active
              </span>
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-ink-3">
            {actor && <span className="text-ink-2">{actor.persona.label} — {actor.persona.summary}</span>}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-ink-3">
            {actor?.geo.mapped ? (
              <span className="inline-flex items-center gap-1">
                <MapPin className="size-3" />
                {actor.geo.city ? `${actor.geo.city}, ` : ""}
                {actor.geo.country} {actor.geo.source === "demo" ? "(illustrative)" : "(approximate)"}
              </span>
            ) : (
              actor && <span>{actor.geo.label}</span>
            )}
            <span>{[s.host, ...s.pivot_to].join(" → ")}</span>
            <span className="num">{duration(s.duration_s)}</span>
            <span className="num">{s.commands} commands</span>
            {s.deception.length > 0 && <span>deception: {s.deception.map((d) => `${d} ${DECEPTION_LABEL[d] ?? ""}`).join(", ")}</span>}
          </div>
        </div>
        <a className="link shrink-0" href={href("graph", { ip: s.ip })}>
          In graph <ArrowRight className="size-3" />
        </a>
      </div>
      <div className="flex min-h-0 flex-1 flex-col p-4">
        {isLoading || !events ? <Skeleton className="h-full min-h-[360px]" /> : <Replay events={events} />}
      </div>
    </Card>
  );
}
