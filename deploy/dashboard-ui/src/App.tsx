import { motion } from "framer-motion";
import { useState, type ReactNode } from "react";
import { Activity, LayoutDashboard, Map, Radio, RefreshCw, Shield } from "lucide-react";
import { ActorTable } from "./components/ActorTable";
import { ArmComparisonChart } from "./components/ArmComparisonChart";
import { DatasetPieChart } from "./components/DatasetPieChart";
import { EventVolumeChart } from "./components/EventVolumeChart";
import { JsonPanel } from "./components/JsonPanel";
import { LevelDonut } from "./components/LevelDonut";
import { LiveLogStream } from "./components/LiveLogStream";
import { NetworkMap } from "./components/NetworkMap";
import { SiemBarChart } from "./components/SiemBarChart";
import { StatsGrid } from "./components/StatsGrid";
import { SystemUsagePanel } from "./components/SystemUsagePanel";
import { Timeline } from "./components/Timeline";
import { VisualsSection } from "./sections/VisualsSection";
import { useDashboard } from "./useDashboard";
import { useSystemMetrics } from "./useSystemMetrics";
import { useTopology } from "./useTopology";
import { CHART } from "./charts/theme";
import "./App.css";

export type AppSection = "overview" | "events" | "visuals" | "actors";

function Header({
  lastRefresh,
  loading,
  onRefresh,
  generatedAt,
  eventRate,
  section,
  onSection,
}: {
  lastRefresh: Date | null;
  loading: boolean;
  onRefresh: () => void;
  generatedAt?: string;
  eventRate?: number;
  section: AppSection;
  onSection: (s: AppSection) => void;
}) {
  const nav: { id: AppSection; label: string; icon: typeof LayoutDashboard }[] = [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
    { id: "visuals", label: "Attack map", icon: Map },
    { id: "events", label: "Events", icon: Activity },
    { id: "actors", label: "Actors", icon: Radio },
  ];

  return (
    <motion.header className="header siem-header" initial={{ opacity: 0, y: -16 }} animate={{ opacity: 1, y: 0 }}>
      <div className="header-brand">
        <div className="logo-mark">
          <Shield size={20} strokeWidth={2.2} />
        </div>
        <div>
          <h1>CyberSnare SOC</h1>
          <p className="header-sub">Intelligence Plane · SIEM analytics · dynamic deception</p>
        </div>
      </div>

      <nav className="header-nav" aria-label="Main">
        {nav.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            className={`nav-item nav-btn ${section === id ? "active" : ""}`}
            onClick={() => onSection(id)}
            aria-current={section === id ? "page" : undefined}
          >
            <Icon size={14} /> {label}
          </button>
        ))}
      </nav>

      <div className="header-actions">
        {eventRate !== undefined && eventRate > 0 && (
          <span className="eps-pill mono">{eventRate.toFixed(1)} evt/min</span>
        )}
        <div className="live-pill">
          <motion.span className="live-dot" animate={{ scale: [1, 1.3, 1], opacity: [1, 0.6, 1] }} transition={{ duration: 1.5, repeat: Infinity }} />
          <span className="mono">LIVE</span>
        </div>
        {generatedAt && <span className="header-ts mono">Report {new Date(generatedAt).toLocaleTimeString()}</span>}
        {lastRefresh && <span className="header-ts mono">Sync {lastRefresh.toLocaleTimeString()}</span>}
        <motion.button className="refresh-btn" onClick={onRefresh} disabled={loading} whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.96 }} type="button">
          <motion.span animate={loading ? { rotate: 360 } : { rotate: 0 }} transition={loading ? { duration: 1, repeat: Infinity, ease: "linear" } : {}} style={{ display: "flex" }}>
            <RefreshCw size={16} />
          </motion.span>
          Refresh
        </motion.button>
      </div>
    </motion.header>
  );
}

function Panel({ title, subtitle, badge, children, className = "" }: { title: string; subtitle?: string; badge?: string; children: ReactNode; className?: string }) {
  return (
    <section className={`glass-card panel chart-panel ${className}`}>
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {badge && <span className="badge badge-cyan">{badge}</span>}
      </div>
      {children}
    </section>
  );
}

function eventRate(volume: { total: number; ts: number }[]) {
  if (volume.length < 2) return 0;
  const span = (volume[volume.length - 1].ts - volume[0].ts) / 60;
  if (span <= 0) return 0;
  const total = volume.reduce((s, r) => s + r.total, 0);
  return total / span;
}

export default function App() {
  const [section, setSection] = useState<AppSection>("overview");
  const { data, loading, error, lastRefresh, refresh } = useDashboard();
  const topology = useTopology(true);
  const systemMetrics = useSystemMetrics(true);
  const [pendingActor, setPendingActor] = useState<string | undefined>();

  // Clicking an actor anywhere in the SOC view (the map, a table row) jumps
  // to the attack-map tab with that actor pre-selected — one entity, one
  // click, straight to its own log and diagram rather than a separate search.
  function selectActor(actorKey: string) {
    setPendingActor(actorKey);
    setSection("visuals");
  }

  return (
    <>
      <div className="app-bg" />
      <div className="app-grid" />
      <div className="shell siem-shell">
        <Header
          lastRefresh={lastRefresh}
          loading={loading && !data}
          onRefresh={refresh}
          generatedAt={data?.report.generated_at}
          eventRate={data ? eventRate(data.analytics.volume) : undefined}
          section={section}
          onSection={setSection}
        />

        {error && (
          <motion.div className="error-banner" initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
            Cannot reach intelligence API: {error}. Start lab with <code>./cs up</code>
          </motion.div>
        )}

        {!data && loading && (
          <div className="loading-grid">
            {[0, 1, 2, 3, 4].map((i) => (
              <motion.div key={i} className="glass-card skeleton" animate={{ opacity: [0.4, 0.8, 0.4] }} transition={{ duration: 1.2, repeat: Infinity, delay: i * 0.12 }} />
            ))}
          </div>
        )}

        {data && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.35 }}>
            {section === "overview" && (
              <>
                <StatsGrid report={data.report} />

                <SystemUsagePanel metrics={systemMetrics.data} error={systemMetrics.error} />

                <div className="siem-row siem-row-hero">
                  <Panel title="Event throughput" subtitle="Stacked volume by telemetry family (5-min buckets)" badge="time series" className="span-2">
                    <EventVolumeChart data={data.analytics.volume} />
                  </Panel>
                  <Panel title="Telemetry mix" subtitle="Dataset distribution" badge="donut">
                    <DatasetPieChart data={data.report.dataset_counts} />
                  </Panel>
                </div>

                <div className="siem-row">
                  <Panel title="MITRE ATT&CK" subtitle="Technique frequency" className="span-1">
                    <SiemBarChart data={data.report.top_techniques} color={CHART.sinkhole} layout="vertical" />
                  </Panel>
                  <Panel title="MITRE Engage" subtitle="Deception activity codes" className="span-1">
                    <SiemBarChart data={data.report.top_engage} color={CHART.shell} layout="vertical" />
                  </Panel>
                  <Panel title="Deception levels" subtitle="Events by engagement level" className="span-1">
                    <LevelDonut levels={data.analytics.levels} />
                  </Panel>
                </div>

                <NetworkMap topology={topology} onSelectActor={selectActor} />

                <div className="siem-row">
                  <Panel title="Experimental arms" subtitle="Milestone 1 A/B/C comparison" className="span-2">
                    <ArmComparisonChart arms={data.report.arms} />
                  </Panel>
                  <ActorTable actors={data.analytics.top_actors} onSelect={selectActor} />
                </div>

                <JsonPanel report={data.report} />
              </>
            )}

            {section === "visuals" && data && (
              <VisualsSection
                deception={data.deception}
                enabled
                refreshKey={lastRefresh?.toISOString()}
                initialActor={pendingActor}
              />
            )}

            {section === "events" && (
              <div className="siem-row siem-row-logs">
                <Timeline entries={data.timeline} />
                <LiveLogStream entries={data.timeline} />
              </div>
            )}

            {section === "actors" && (
              <div className="siem-row">
                <Panel title="Top actors" subtitle="By event volume — milestone study — click a row for its attack story" className="span-2">
                  <ActorTable actors={data.analytics.top_actors} onSelect={selectActor} />
                </Panel>
              </div>
            )}
          </motion.div>
        )}

        <footer className="footer mono">CyberSnare SIEM · JSONL system of record · auto-refresh 5s</footer>
      </div>
    </>
  );
}
