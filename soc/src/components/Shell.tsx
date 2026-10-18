import { useEffect, useRef, useState, type ReactNode } from "react";
import { motion } from "motion/react";
import {
  Activity,
  BrainCircuit,
  ChevronDown,
  Globe2,
  LayoutDashboard,
  Network as NetworkIcon,
  Search,
  ServerCog,
  SquareTerminal,
  Waypoints,
  Workflow,
  Grid3x3,
  Bell,
} from "lucide-react";
import { useAlerts, useOverview, useWindow, WINDOW_LABEL, type WindowKey } from "../lib/api";
import { go, href, type Route } from "../lib/router";

const NAV: { id: Route; label: string; icon: typeof Activity }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "map", label: "Global Attack Map", icon: Globe2 },
  { id: "sessions", label: "Live Sessions", icon: SquareTerminal },
  { id: "graph", label: "Attack Graph", icon: Waypoints },
  { id: "attack", label: "MITRE ATT&CK", icon: Grid3x3 },
  { id: "deception", label: "Deception Engine", icon: Workflow },
  { id: "telemetry", label: "Telemetry", icon: Activity },
  { id: "network", label: "Network Intelligence", icon: NetworkIcon },
  { id: "ai", label: "AI Intelligence", icon: BrainCircuit },
  { id: "system", label: "System & Policies", icon: ServerCog },
];

export function Shell({ route, children }: { route: Route; children: ReactNode }) {
  return (
    <div className="grid min-h-full grid-cols-[240px_minmax(0,1fr)] max-lg:grid-cols-[64px_minmax(0,1fr)]">
      <Sidebar route={route} />
      <div className="flex min-w-0 flex-col bg-[#f4f6fa]">
        <Topbar />
        <main className="min-w-0 flex-1 px-6 pb-8 pt-5 max-md:px-4">{children}</main>
      </div>
    </div>
  );
}

function Sidebar({ route }: { route: Route }) {
  const { data: ov } = useOverview();
  return (
    <aside className="sticky top-0 flex h-screen flex-col border-r border-line bg-white px-3.5 py-4 z-20">
      <a href={href("overview")} className="mb-6 flex items-center gap-3 px-2">
        <Logo />
        <div className="max-lg:hidden">
          <div className="text-[16px] font-bold tracking-tight text-slate-900 leading-none">NetOsis</div>
          <div className="text-[11px] font-medium text-slate-400 mt-0.5">Cyber Deception Platform</div>
        </div>
      </a>
      <nav className="flex flex-col gap-1" aria-label="Modules">
        {NAV.map((n) => {
          const active = n.id === route;
          const Icon = n.icon;
          return (
            <a
              key={n.id}
              href={href(n.id)}
              aria-current={active ? "page" : undefined}
              title={n.label}
              className={`relative flex h-9.5 items-center gap-3 rounded-xl px-3 text-[13px] font-medium transition-all ${
                active
                  ? "bg-[#eaf1fe] text-[#2563eb] font-semibold shadow-xs"
                  : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
              }`}
            >
              {active && (
                <motion.span
                  layoutId="nav-active"
                  className="absolute inset-0 rounded-xl bg-[#eaf1fe]"
                  transition={{ type: "spring", stiffness: 500, damping: 40 }}
                />
              )}
              <Icon className="relative size-[18px] shrink-0" strokeWidth={active ? 2.2 : 1.8} />
              <span className="relative truncate max-lg:hidden">{n.label}</span>
            </a>
          );
        })}
      </nav>

      <div className="mt-auto max-lg:hidden">
        <a
          href={href("deception")}
          className="block rounded-2xl border border-slate-100 bg-[#fbfcfd] p-3.5 shadow-xs transition-all hover:bg-slate-50 hover:border-slate-200"
        >
          <div className="flex items-center gap-2 text-[12.5px] font-bold text-slate-800">
            <span className={`size-2 rounded-full shrink-0 ${ov?.sensors_online ? "bg-emerald-500 live-dot" : "bg-slate-400"}`} />
            <span>Deception {ov?.sensors_online ? "Active" : "Idle"}</span>
          </div>
          <div className="mt-1 text-[11px] font-medium text-slate-400">
            {ov ? `${ov.kpis.deception} triggers • ${ov.sensors_online}/${ov.sensors_total} honeypots on` : "Connecting…"}
          </div>
          {ov && (
            <div className="mt-2 text-[11px] text-slate-500">
              <Spark values={ov.series.all} />
            </div>
          )}
        </a>
        <div className="mt-2.5 px-1 text-[11px] font-medium text-slate-400">NetOsis v1.0.0</div>
      </div>
    </aside>
  );
}

function Spark({ values }: { values: number[] }) {
  const max = Math.max(1, ...values);
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * 100},${24 - (v / max) * 18}`).join(" ");
  return (
    <svg viewBox="0 0 100 28" className="h-6 w-full" preserveAspectRatio="none" aria-hidden>
      <polyline points={pts} fill="none" stroke="#2563eb" strokeWidth="1.8" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
    </svg>
  );
}

function Logo() {
  return (
    <svg viewBox="0 0 32 32" className="size-8 shrink-0" aria-hidden>
      <path d="M16 2.5 27.5 7v8.6c0 7.1-4.8 12.6-11.5 14.4C9.3 28.2 4.5 22.7 4.5 15.6V7L16 2.5Z" fill="#2563eb" />
      <path d="M16 8.2 22.8 11v4.7c0 4.2-2.8 7.4-6.8 8.6-4-1.2-6.8-4.4-6.8-8.6V11L16 8.2Z" fill="#fff" />
      <circle cx="16" cy="15.6" r="2.6" fill="#2563eb" />
    </svg>
  );
}

function Topbar() {
  const { data: alerts } = useAlerts(50);
  const { data: ov } = useOverview();
  const healthy = ov ? ov.sensors_online > 0 : false;
  const [q, setQ] = useState("");
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const on = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        input.current?.focus();
      }
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, []);

  const critical = alerts?.filter((a) => a.severity === "CRITICAL").length ?? 0;

  return (
    <header className="sticky top-0 z-30 flex h-16 min-w-0 items-center gap-4 border-b border-line bg-white/95 px-6 backdrop-blur-md max-md:gap-2 max-md:px-3">
      {/* Search Input */}
      <form
        className="relative min-w-0 flex-1 md:max-w-[440px]"
        onSubmit={(e) => {
          e.preventDefault();
          go("telemetry", q ? { q } : undefined);
        }}
        role="search"
      >
        <Search className="pointer-events-none absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
        <input
          ref={input}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search attacks, IPs, hosts, commands..."
          className="h-9.5 w-full rounded-xl border border-slate-200/90 bg-white pl-10 pr-12 text-[13px] text-slate-800 placeholder:text-slate-400 shadow-xs focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-100 transition-all"
          aria-label="Search attacks"
        />
        <kbd className="mono pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-semibold text-slate-500 max-md:hidden">
          ⌘ K
        </kbd>
      </form>

      {/* Right side controls */}
      <div className="ml-auto flex shrink-0 items-center gap-4 max-md:gap-2">
        {/* System Healthy Pill */}
        <a
          href={href("system")}
          className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold shadow-xs transition-colors max-md:hidden ${
            healthy
              ? "border-emerald-200 bg-emerald-50/80 text-emerald-700 hover:bg-emerald-100/60"
              : "border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100"
          }`}
          title="Honeypot heartbeats and controller status"
        >
          <span className={`size-2 rounded-full ${healthy ? "bg-emerald-500 live-dot" : "bg-slate-400"}`} />
          <span>{ov ? (healthy ? `${ov.sensors_online}/${ov.sensors_total} honeypots reporting` : "No honeypot reporting") : "Connecting…"}</span>
        </a>

        {/* Notification Bell */}
        <a
          href={href("telemetry", { type: "lateral_movement,deception_action" })}
          className="relative grid size-9 place-items-center rounded-xl text-slate-500 hover:bg-slate-100 hover:text-slate-800 transition-colors"
          aria-label={`${critical} alerts`}
          title={`${critical} unread security notifications`}
        >
          <Bell className="size-[19px]" strokeWidth={1.8} />
          {critical > 0 && (
            <span className="mono absolute right-1.5 top-1.5 grid size-4 place-items-center rounded-full bg-red-500 text-[10px] font-bold text-white shadow-xs">
              {critical > 9 ? "9+" : critical}
            </span>
          )}
        </a>

        {/* User Profile */}
        <div className="flex items-center gap-2.5 pl-1 select-none">
          <div className="grid size-8 shrink-0 place-items-center rounded-full bg-slate-900 text-xs font-bold text-white shadow-xs">
            A
          </div>
          <div className="flex flex-col text-left max-sm:hidden">
            <span className="text-[13px] font-bold text-slate-800 leading-tight">aheed</span>
            <span className="text-[10.5px] font-medium text-slate-400 leading-tight">Administrator</span>
          </div>
          <ChevronDown className="size-3.5 text-slate-400 max-sm:hidden" />
        </div>
      </div>
    </header>
  );
}
