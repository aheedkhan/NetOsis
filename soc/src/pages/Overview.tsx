import { useMemo, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import {
  ArrowRight,
  Shield,
  LayoutGrid,
  Users,
  Terminal,
  AlertTriangle,
  Activity,
  Maximize2,
  SlidersHorizontal,
  Calendar,
  Lock,
  Network,
  Download,
  Radio,
  FileCode,
  Clock,
  Star,
  ChevronDown,
} from "lucide-react";
import {
  useAttack,
  useGeo,
  useLiveEvents,
  useNetwork,
  useOverview,
  useSessions,
  useWindow,
  WINDOW_LABEL,
  type GeoData,
  type GeoPoint,
  type Overview as OverviewT,
  type SocEvent,
  type WindowKey,
} from "../lib/api";
import { go, href } from "../lib/router";
import { Counter, Definition, DemoTag, Empty, ModeBadge, Skeleton } from "../components/ui";
import { LEVEL, TACTIC_COLOR, TECHNIQUE_TACTIC } from "../lib/format";
import { Globe, REGIONS, getCountryFlag, inRegion } from "../components/Globe";
import { Topology } from "../components/Topology";
import { TacticDonut } from "../components/Charts";

export default function Overview() {
  const { data: ov, isLoading } = useOverview();

  return (
    <div className="flex flex-col gap-4 select-none">
      {/* Top row of 5 KPI stat cards */}
      <KpiRow ov={ov} loading={isLoading} />

      {/* Middle row: Global Attack Map + Live Intelligence Feed */}
      <div className="grid grid-cols-[minmax(0,1.95fr)_minmax(0,1.05fr)] gap-4 max-2xl:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)] max-xl:grid-cols-1">
        <MapCard />
        <FeedCard />
      </div>

      {/* Bottom row: Network Topology + MITRE ATT&CK + Recent Attack Paths */}
      <div className="grid grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)_minmax(0,1fr)] gap-4 max-xl:grid-cols-1">
        <TopologyCard />
        <MitreCard />
        <PathsCard />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------- KPIs */

function KpiRow({ ov, loading }: { ov: OverviewT | undefined; loading: boolean }) {
  const reduce = useReducedMotion();

  const { win } = useWindow();
  const prevLabel = win === "all" ? "" : `vs. previous ${win}`;
  // Real change against the same-length window before this one; null when there is no
  // earlier history to compare against (never invented).
  const trend = (key: "attacks" | "sources" | "commands" | "high_risk") => {
    const cur = ov?.kpis[key];
    const prev = ov?.previous?.[key];
    if (cur == null || prev == null) return null;
    if (prev === 0) return cur === 0 ? { text: "0%", up: false } : { text: "new", up: true };
    const pct = Math.round(((cur - prev) / prev) * 100);
    return { text: `${pct >= 0 ? "↑" : "↓"} ${Math.abs(pct)}%`, up: pct > 0 };
  };

  const cards = [
    {
      key: "attacks",
      label: "Total Attacks",
      value: ov?.kpis.attacks ?? 0,
      trend: trend("attacks"),
      icon: Shield,
      tint: "bg-red-50 text-red-500 border border-red-100",
      route: "sessions" as const,
      params: undefined,
      def: ov?.definitions?.attacks ?? "",
    },
    {
      key: "sessions_live",
      label: "Active Sessions",
      value: ov?.kpis.sessions_live ?? 0,
      trend: null,
      note: "open right now",
      icon: LayoutGrid,
      tint: "bg-blue-50 text-blue-500 border border-blue-100",
      route: "sessions" as const,
      params: { active: "1" },
      def: ov?.definitions?.sessions_live ?? "",
    },
    {
      key: "sources",
      label: "Unique Sources",
      value: ov?.kpis.sources ?? 0,
      trend: trend("sources"),
      icon: Users,
      tint: "bg-purple-50 text-purple-500 border border-purple-100",
      route: "map" as const,
      params: undefined,
      def: ov?.definitions?.sources ?? "",
    },
    {
      key: "commands",
      label: "Captured Commands",
      value: ov?.kpis.commands ?? 0,
      trend: trend("commands"),
      icon: Terminal,
      tint: "bg-amber-50 text-amber-500 border border-amber-100",
      route: "telemetry" as const,
      params: { type: "command" },
      def: ov?.definitions?.commands ?? "",
    },
    {
      key: "high_risk",
      label: "High Risk Events",
      value: ov?.kpis.high_risk ?? 0,
      trend: trend("high_risk"),
      icon: AlertTriangle,
      tint: "bg-emerald-50 text-emerald-600 border border-emerald-100",
      route: "attack" as const,
      params: undefined,
      def: ov?.definitions?.high_risk ?? "",
      viewAll: true,
    },
  ];

  return (
    <div className="grid grid-cols-5 gap-4 max-2xl:grid-cols-3 max-lg:grid-cols-2 max-sm:grid-cols-1">
      {cards.map((k, i) => {
        const Icon = k.icon;
        return (
          <motion.a
            key={k.key}
            href={href(k.route, k.params as Record<string, string> | undefined)}
            initial={reduce ? false : { opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: reduce ? 0 : i * 0.05, ease: [0.22, 1, 0.36, 1] }}
            className="group relative flex flex-col justify-between rounded-2xl border border-slate-100 bg-white p-3.5 shadow-xs transition-all hover:border-slate-200 hover:shadow-md"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className={`grid size-9 place-items-center rounded-xl ${k.tint}`}>
                  <Icon className="size-4.5" strokeWidth={2} />
                </span>
                <span className="text-[13px] font-semibold text-slate-700">{k.label}</span>
              </div>
              <span className="flex items-center gap-2">
                {k.viewAll && (
                  <span className="flex items-center gap-1 text-[12px] font-semibold text-blue-600 group-hover:underline">
                    View All <ArrowRight className="size-3" />
                  </span>
                )}
                {k.def && (
                  <span onClick={(e) => e.preventDefault()}>
                    <Definition text={k.def} />
                  </span>
                )}
              </span>
            </div>

            {loading ? (
              <Skeleton className="my-2 h-9 w-24 rounded-lg" />
            ) : (
              <div className="mt-2.5">
                <Counter value={k.value} className="block text-[28px] font-bold tracking-tight text-slate-900 leading-none" />
                <div className="mt-2 flex items-center gap-1.5 text-[11.5px]">
                  {k.trend ? (
                    <>
                      <span className={`font-bold ${k.trend.up ? "text-red-500" : "text-emerald-600"}`}>{k.trend.text}</span>
                      <span className="text-slate-400 font-medium">{prevLabel}</span>
                    </>
                  ) : (
                    <span className="text-slate-400 font-medium">
                      {"note" in k && k.note ? k.note : win === "all" ? "all recorded history" : `no earlier ${win} to compare`}
                    </span>
                  )}
                </div>
              </div>
            )}
          </motion.a>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------- Globe */

function MapCard() {
  const { data, isLoading } = useGeo();
  const { data: ov } = useOverview();
  const { win, setWin } = useWindow();
  const [region, setRegion] = useState("world");
  const [sel, setSel] = useState<string | null>(null);
  const [openWinSelect, setOpenWinSelect] = useState(false);

  return (
    <div className="relative flex flex-col rounded-2xl border border-slate-100 bg-white shadow-xs overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-100/80 px-6 py-4">
        <div>
          <h2 className="text-[15px] font-bold text-slate-900 tracking-tight leading-none">Global Attack Map</h2>
          <p className="mt-1 text-[12px] font-medium text-slate-400 leading-none">
            Real-time visualization of attack sources and destinations
          </p>
        </div>

        {/* Right header controls */}
        <div className="flex items-center gap-3">
          {/* Time Filter Pill */}
          <div className="relative">
            <button
              onClick={() => setOpenWinSelect((p) => !p)}
              className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-xs hover:bg-slate-50 transition-colors"
            >
              <Calendar className="size-3.5 text-slate-400" />
              <span>{WINDOW_LABEL[win]}</span>
              <ChevronDown className="size-3 text-slate-400" />
            </button>

            {openWinSelect && (
              <div className="absolute right-0 top-full mt-1.5 z-40 w-36 overflow-hidden rounded-xl border border-slate-200 bg-white p-1 shadow-lg">
                {(Object.keys(WINDOW_LABEL) as WindowKey[]).map((k) => (
                  <button
                    key={k}
                    onClick={() => {
                      setWin(k);
                      setOpenWinSelect(false);
                    }}
                    className={`w-full rounded-lg px-2.5 py-1.5 text-left text-xs font-medium transition-colors ${
                      win === k ? "bg-blue-50 text-blue-600 font-semibold" : "text-slate-700 hover:bg-slate-50"
                    }`}
                  >
                    {WINDOW_LABEL[k]}
                  </button>
                ))}
              </div>
            )}
          </div>

          <ModeBadge mode={ov?.mode} />

          {/* Fullscreen / Map route */}
          <a
            href={href("map")}
            className="grid size-8 place-items-center rounded-xl border border-slate-200 text-slate-500 hover:bg-slate-50 hover:text-slate-800 transition-colors shadow-xs"
            title="Open full map view"
          >
            <Maximize2 className="size-3.5" />
          </a>

          {/* Sliders / Filter icon */}
          <a
            href={href("map")}
            className="grid size-8 place-items-center rounded-xl border border-slate-200 text-slate-500 hover:bg-slate-50 hover:text-slate-800 transition-colors shadow-xs"
            title="Filter by severity and region on the full map"
          >
            <SlidersHorizontal className="size-3.5" />
          </a>
        </div>
      </div>

      {/* Map Canvas and Overlays */}
      <div className="relative min-h-[460px] w-full flex-1">
        {/* Left Region Navigation Overlay */}
        <div data-globe-obstacle className="absolute left-5 top-5 z-20 flex flex-col gap-1 rounded-2xl border border-white/60 bg-white/80 p-1.5 shadow-md backdrop-blur-md max-md:hidden">
          {REGIONS.map((r) => {
            const Icon = r.icon;
            const active = region === r.id;
            return (
              <button
                key={r.id}
                onClick={() => setRegion(r.id)}
                aria-pressed={active}
                className={`flex items-center gap-2.5 rounded-xl px-3 py-1.5 text-left text-[12px] font-medium transition-all ${
                  active
                    ? "bg-[#eaf1fe] text-[#2563eb] font-semibold shadow-xs"
                    : "text-slate-600 hover:bg-slate-100/70 hover:text-slate-900"
                }`}
              >
                <Icon className="size-3.5 shrink-0" />
                <span>{r.label}</span>
              </button>
            );
          })}
        </div>

        {/* 3D Globe Component */}
        {isLoading ? (
          <div className="grid h-[470px] place-items-center">
            <Skeleton className="h-[440px] w-full rounded-2xl" />
          </div>
        ) : (
          <Globe
            data={data}
            height={470}
            inset={190}
            insetRight={200}
            region={region}
            selected={sel}
            onSelect={(p) => setSel(p?.ip ?? null)}
          />
        )}

        <TopSources data={data} region={region} selected={sel} onSelect={setSel} />

        {/* Bottom-left Trajectory Legend */}
        <div data-globe-obstacle className="absolute bottom-4 left-5 z-20 flex items-center gap-4 rounded-full border border-white/70 bg-white/85 px-4 py-1.5 text-[11.5px] font-semibold text-slate-700 shadow-md backdrop-blur-md">
          <span className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-red-500 shadow-xs" />
            High
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-amber-500 shadow-xs" />
            Medium
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-blue-500 shadow-xs" />
            Low
          </span>
          <span className="flex items-center gap-2 pl-1 border-l border-slate-200">
            <span className="h-0.5 w-6 rounded-full bg-gradient-to-r from-blue-500 to-red-500" />
            Attack Trajectory
          </span>
        </div>
      </div>
    </div>
  );
}

/** Countries attacking in this region, busiest first; a row selects that country's top source. */
function TopSources({
  data,
  region,
  selected,
  onSelect,
}: {
  data: GeoData | undefined;
  region: string;
  selected: string | null;
  onSelect: (ip: string | null) => void;
}) {
  const rows = useMemo(() => {
    const by = new Map<string, { country: string; iso?: string; events: number; sources: number; level: GeoPoint["level"]; top: GeoPoint }>();
    for (const p of (data?.points ?? []).filter((x) => inRegion(x, region))) {
      const k = p.country || p.city || "Unknown";
      const r = by.get(k);
      if (!r) {
        by.set(k, { country: k, iso: p.iso, events: p.events, sources: 1, level: p.level, top: p });
        continue;
      }
      r.events += p.events;
      r.sources += 1;
      if (LEVEL[p.level].rank > LEVEL[r.level].rank) r.level = p.level;
      if (p.events > r.top.events) r.top = p;
    }
    return [...by.values()].sort((a, b) => b.events - a.events);
  }, [data, region]);
  const max = Math.max(1, ...rows.map((r) => r.events));

  return (
    <div
      data-globe-obstacle
      className="absolute right-5 top-16 z-20 flex max-h-[250px] w-[180px] flex-col rounded-2xl border border-white/60 bg-white/80 p-1.5 shadow-md backdrop-blur-md max-md:hidden"
    >
      <div className="flex items-baseline justify-between px-2 pb-1 pt-1">
        <span className="text-[11.5px] font-semibold text-slate-700">Top sources</span>
        <span className="text-[10.5px] text-slate-400">attacks</span>
      </div>
      <div className="min-h-0 overflow-y-auto">
        {rows.length === 0 && <p className="px-2 py-2 text-[11px] text-slate-400">No mapped sources here.</p>}
        {rows.map((r) => {
          const active = r.top.ip === selected;
          return (
            <button
              key={r.country}
              onClick={() => onSelect(active ? null : r.top.ip)}
              aria-pressed={active}
              title={`${r.sources} source${r.sources > 1 ? "s" : ""} · busiest ${r.top.ip}`}
              className={`block w-full rounded-lg px-2 py-1 text-left transition-colors ${active ? "bg-[#eaf1fe]" : "hover:bg-slate-100/70"}`}
            >
              <span className="flex items-center gap-1.5 text-[11.5px]">
                <span className="size-1.5 shrink-0 rounded-full" style={{ background: LEVEL[r.level].fill }} />
                <span className="truncate font-medium text-slate-700">
                  {getCountryFlag(r.iso)} {r.country}
                </span>
                <span className="num ml-auto text-slate-500">{r.events}</span>
              </span>
              <span className="mt-0.5 block h-[3px] rounded-full bg-slate-100">
                <span className="block h-[3px] rounded-full" style={{ width: `${(r.events / max) * 100}%`, background: LEVEL[r.level].fill }} />
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------- Feed */

function FeedCard() {
  const { events, connected } = useLiveEvents(80);

  const renderedRows = useMemo(() => {
    if (!events || events.length === 0) return [];

    // Deduplicate consecutive bursts from same IP and event type
    const deduped: SocEvent[] = [];
    for (const e of events) {
      const prev = deduped[deduped.length - 1];
      if (
        prev &&
        prev.source_ip === e.source_ip &&
        prev.event_type === e.event_type &&
        (prev.command === e.command || prev.event_type === "auth_failure")
      ) {
        continue;
      }
      deduped.push(e);
    }

    const mapped = deduped.slice(-6).reverse().map((e: SocEvent) => {
      const isHigh =
        e.extra?.risk_category &&
        ["Credential_attack", "Payload_transfer", "Persistence", "Execution", "Canary_interaction"].includes(
          e.extra.risk_category,
        );
      const isCritical = e.event_type === "lateral_movement";
      const lvl = isCritical || isHigh ? ("High" as const) : e.event_type === "deception_action" ? ("Medium" as const) : ("Low" as const);

      const iconType =
        e.extra?.risk_category === "Payload_transfer"
          ? ("download" as const)
          : e.event_type === "command"
          ? ("terminal" as const)
          : e.event_type === "lateral_movement"
            ? ("network" as const)
            : e.event_type === "deception_action"
              ? ("resource" as const)
              : e.event_type === "auth_failure"
                ? ("lock" as const)
                : ("beacon" as const);

      const timeStr = new Date(e.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });

      let title = e.technique_name ?? e.command ?? "Command executed";
      let snippet = e.command || e.result || "Command executed";
      if (e.event_type === "auth_failure") {
        title = "Failed SSH authentication";
        snippet = `ssh ${e.extra?.username ?? "admin"}@${e.target_host} (invalid credentials)`;
      } else if (e.event_type === "auth_success") {
        title = "Compromised SSH session";
        snippet = `Logged in as ${e.extra?.username ?? "root"} on ${e.target_host}`;
      } else if (e.event_type === "deception_action") {
        title = "Deception trigger activated";
        snippet = `${e.extra?.action ?? "D01"} · ${e.extra?.reason ?? "Deceptive response emitted"}`;
      }

      return {
        seq: e.seq,
        time: timeStr,
        ip: e.source_ip,
        host: e.target_host,
        demo: !!e.demo,
        title,
        snippet,
        level: lvl,
        iconType,
        sessionId: e.session_id,
      };
    });

    return mapped;
  }, [events]);

  return (
    <div className="flex flex-col rounded-2xl border border-slate-100 bg-white shadow-xs overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-100/80 px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="grid size-8 place-items-center rounded-xl bg-blue-50 text-blue-600 shadow-xs">
            <Activity className="size-4.5" strokeWidth={2.2} />
          </div>
          <div>
            <h2 className="text-[15px] font-bold text-slate-900 tracking-tight leading-none">Live Intelligence Feed</h2>
            <p className="mt-1 text-[12px] font-medium text-slate-400 leading-none">
              Real-time attack events and captured data
            </p>
          </div>
        </div>

        <span
          className={`size-2.5 rounded-full ${connected ? "bg-emerald-500 live-dot" : "bg-slate-300"}`}
          title={connected ? "Streaming live events" : "Connecting"}
        />
      </div>

      {/* Events List */}
      <div className="flex flex-col gap-2.5 p-4 flex-1 overflow-y-auto max-h-[500px]">
        {renderedRows.length === 0 && (
          <Empty title={connected ? "Waiting for the next attacker event" : "Connecting to the live stream…"}>
            Every row here is a real event shipped by a honeypot.
          </Empty>
        )}
        {renderedRows.map((item) => {
          const iconConfig =
            item.iconType === "terminal"
              ? { bg: "bg-slate-900 text-white", Icon: Terminal }
              : item.iconType === "lock"
                ? { bg: "bg-red-500 text-white", Icon: Lock }
                : item.iconType === "network"
                  ? { bg: "bg-blue-600 text-white", Icon: Network }
                  : item.iconType === "download"
                    ? { bg: "bg-emerald-500 text-white", Icon: Download }
                    : item.iconType === "beacon"
                      ? { bg: "bg-sky-500 text-white", Icon: Radio }
                      : { bg: "bg-purple-600 text-white", Icon: FileCode };

          const IconComponent = iconConfig.Icon;

          const badgeConfig =
            item.level === "High"
              ? { bg: "bg-red-50 text-red-600 border border-red-100", label: "High", star: true }
              : item.level === "Medium"
                ? { bg: "bg-amber-50 text-amber-600 border border-amber-100", label: "Medium", star: true }
                : { bg: "bg-blue-50 text-blue-600 border border-blue-100", label: "Low", star: false };

          return (
            <a
              key={item.seq}
              href={href("sessions", { id: item.sessionId })}
              className="flex items-start gap-3 rounded-xl border border-slate-100/90 bg-[#fbfcfd] p-3 shadow-xs hover:border-slate-200 hover:bg-white hover:shadow-sm transition-all"
            >
              <div className={`grid size-9 shrink-0 place-items-center rounded-full shadow-xs ${iconConfig.bg}`}>
                <IconComponent className="size-4" strokeWidth={2} />
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 text-[11px] text-slate-400">
                  <Clock className="size-3" />
                  <span className="mono">{item.time}</span>
                  <span className="mono font-semibold text-slate-600">{item.ip}</span>
                  <span className="truncate font-semibold text-slate-500">({item.host})</span>
                  {item.demo && <DemoTag />}
                </div>

                <div className="text-[12.5px] font-bold text-slate-900 truncate mt-0.5">
                  {item.title}
                </div>

                <div className="mono text-[11px] text-slate-500 truncate mt-1 bg-white px-2 py-0.5 rounded-md border border-slate-100">
                  {item.snippet}
                </div>
              </div>

              <div className="shrink-0 self-start">
                <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-bold ${badgeConfig.bg}`}>
                  {badgeConfig.star ? <Star className="size-2.5 fill-current" /> : <span>+</span>}
                  {badgeConfig.label}
                </span>
              </div>
            </a>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------- bottom row */

function TopologyCard() {
  const { data } = useNetwork();
  return (
    <div className="flex flex-col rounded-2xl border border-slate-100 bg-white shadow-xs overflow-hidden">
      <div className="flex items-center justify-between border-b border-slate-100/80 px-6 py-4">
        <div>
          <h2 className="text-[15px] font-bold text-slate-900 tracking-tight leading-none">Network Topology</h2>
          <p className="mt-1 text-[12px] font-medium text-slate-400 leading-none">
            Live network view with honeypots and attack flows
          </p>
        </div>
        <a
          href={href("network")}
          className="flex items-center gap-1 text-[12px] font-semibold text-blue-600 hover:underline"
        >
          View All <ArrowRight className="size-3" />
        </a>
      </div>
      <div className="px-3 py-2 flex-1">
        <Topology net={data} height={250} compact onSelect={() => go("network")} />
      </div>
    </div>
  );
}

function MitreCard() {
  const { data } = useAttack();
  const { win } = useWindow();
  const tactics = (data?.tactics ?? []).filter((t) => t.count > 0);
  const total = tactics.reduce((n, t) => n + t.count, 0);
  const rows = tactics.map((t) => ({
    tactic: t.tactic,
    count: t.count,
    pct: total ? Math.round((t.count / total) * 100) : 0,
    color: TACTIC_COLOR[t.tactic] ?? "#64748b",
  }));

  return (
    <div className="flex flex-col rounded-2xl border border-slate-100 bg-white shadow-xs overflow-hidden">
      <div className="flex items-center justify-between border-b border-slate-100/80 px-6 py-4">
        <div>
          <h2 className="text-[15px] font-bold text-slate-900 tracking-tight leading-none">MITRE ATT&CK</h2>
          <p className="mt-1 text-[12px] font-medium text-slate-400 leading-none">
            Tactic distribution ({WINDOW_LABEL[win].toLowerCase()})
          </p>
        </div>
        <a
          href={href("attack")}
          className="flex items-center gap-1 text-[12px] font-semibold text-blue-600 hover:underline"
        >
          View All <ArrowRight className="size-3" />
        </a>
      </div>

      {rows.length === 0 ? (
        <Empty title="No ATT&CK techniques mapped in this window" />
      ) : (
        <div className="grid grid-cols-[160px_minmax(0,1fr)] items-center gap-3 p-4 flex-1 max-sm:grid-cols-1">
          <TacticDonut tactics={rows} total={total} height={210} onSelect={(t) => go("attack", { tactic: t })} />
          <div className="grid grid-cols-1 gap-1">
            {rows.map((t) => (
              <a
                key={t.tactic}
                href={href("attack", { tactic: t.tactic })}
                className="flex items-center justify-between rounded-lg px-2 py-1 text-[11.5px] font-medium text-slate-600 hover:bg-slate-50 transition-colors"
                title={`${t.count} events`}
              >
                <div className="flex items-center gap-2 truncate">
                  <span className="size-2 shrink-0 rounded-full" style={{ background: t.color }} />
                  <span className="truncate">{t.tactic}</span>
                </div>
                <span className="mono font-bold text-slate-800 ml-2">{t.pct}%</span>
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function PathsCard() {
  const { data: sessions } = useSessions();
  const { win } = useWindow();

  // The most recent sessions that reached a shell and did something mappable.
  const paths = (sessions ?? [])
    .filter((x) => x.techniques.length > 0 || x.pivot_to.length > 0)
    .sort((a, b) => b.last.localeCompare(a.last))
    .slice(0, 4)
    .map((x) => {
      const level = x.pivot_to.length ? "High" : x.high_risk > 0 ? "Medium" : "Low";
      const first = x.techniques[0];
      const last = x.techniques[x.techniques.length - 1];
      return {
        id: x.id,
        source: x.ip,
        target: x.pivot_to.length ? `${x.host} → ${x.pivot_to.join(", ")}` : x.host,
        tech: !first ? "lateral movement" : first === last ? first : `${first} → ${last}`,
        tactic: first ? TECHNIQUE_TACTIC[first] : undefined,
        badge: level,
        demo: x.demo,
      };
    });

  return (
    <div className="flex flex-col rounded-2xl border border-slate-100 bg-white shadow-xs overflow-hidden">
      <div className="flex items-center justify-between border-b border-slate-100/80 px-6 py-4">
        <div>
          <h2 className="text-[15px] font-bold text-slate-900 tracking-tight leading-none">Recent Attack Paths</h2>
          <p className="mt-1 text-[12px] font-medium text-slate-400 leading-none">{WINDOW_LABEL[win]}</p>
        </div>
        <a
          href={href("sessions")}
          className="flex items-center gap-1 text-[12px] font-semibold text-blue-600 hover:underline"
        >
          View All <ArrowRight className="size-3" />
        </a>
      </div>

      <div className="flex flex-col gap-2 p-4 flex-1 justify-center">
        {paths.length === 0 && <Empty title="No attacker has run mapped commands in this window" />}
        {paths.map((p, i) => {
          const badgeStyle =
            p.badge === "High"
              ? "bg-red-50 text-red-600 border border-red-100"
              : p.badge === "Medium"
                ? "bg-amber-50 text-amber-600 border border-amber-100"
                : "bg-blue-50 text-blue-600 border border-blue-100";

          return (
            <a
              key={p.id}
              href={href("sessions", { id: p.id })}
              className="flex items-center gap-3.5 rounded-xl border border-slate-100 bg-[#fbfcfd] p-3 shadow-xs hover:border-slate-200 hover:bg-white hover:shadow-sm transition-all"
            >
              <span className="grid size-6 shrink-0 place-items-center rounded-full bg-slate-100 text-[11px] font-bold text-slate-700">
                {i + 1}
              </span>

              <div className="flex-1 min-w-0">
                <div className="flex min-w-0 items-center gap-2 text-[12.5px] font-bold text-slate-800">
                  <span className="mono shrink-0">{p.source}</span>
                  <ArrowRight className="size-3 shrink-0 text-slate-400" />
                  <span className="truncate">{p.target}</span>
                </div>
                <div className="mono text-[11px] text-slate-400 font-medium mt-0.5 truncate">
                  {p.tech}
                  {p.tactic ? ` · ${p.tactic}` : ""}
                </div>
              </div>

              <div className="flex shrink-0 items-center gap-1.5">
                {p.demo && <DemoTag />}
                <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[10px] font-bold ${badgeStyle}`}>
                  {p.badge !== "Low" ? <Star className="size-2.5 fill-current" /> : <span>+</span>}
                  {p.badge}
                </span>
              </div>
            </a>
          );
        })}
      </div>
    </div>
  );
}
