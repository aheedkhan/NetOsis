import { motion } from "framer-motion";
import { Cpu, HardDrive, MemoryStick, MonitorCog, Thermometer } from "lucide-react";
import type { SystemMetrics } from "../types";

type Props = {
  metrics: SystemMetrics | null;
  error: string | null;
};

const MAX_TEMP_C = 100;

function tempColor(c: number): string {
  if (c >= 85) return "var(--rose)";
  if (c >= 65) return "var(--amber)";
  return "var(--emerald)";
}

function loadColor(pct: number): string {
  if (pct >= 90) return "var(--rose)";
  if (pct >= 70) return "var(--amber)";
  return "var(--cyan)";
}

function Meter({
  icon: Icon,
  label,
  value,
  displayValue,
  color,
  delay = 0,
}: {
  icon: typeof Cpu;
  label: string;
  value: number;
  displayValue: string;
  color: string;
  delay?: number;
}) {
  return (
    <div className="bar-row sys-meter-row">
      <div className="bar-meta">
        <span className="bar-key mono sys-meter-key">
          <Icon size={12} /> {label}
        </span>
        <span className="bar-val mono">{displayValue}</span>
      </div>
      <div className="bar-track">
        <motion.div
          className="bar-fill"
          style={{ background: color }}
          initial={{ width: 0 }}
          animate={{ width: `${Math.min(Math.max(value, 0), 100)}%` }}
          transition={{ duration: 0.6, delay, ease: [0.22, 1, 0.36, 1] }}
        />
      </div>
    </div>
  );
}

export function SystemUsagePanel({ metrics, error }: Props) {
  return (
    <section className="glass-card panel chart-panel sys-panel">
      <div className="panel-head compact">
        <div>
          <h2>Host system</h2>
          <p>{metrics ? metrics.hostname : "Lab machine"} · CPU, RAM, disk, GPU, temperatures</p>
        </div>
        <span className={`badge ${metrics ? "badge-cyan" : "badge-burn"}`}>
          {metrics ? "LIVE · 2s" : error ? "unavailable" : "connecting"}
        </span>
      </div>

      {!metrics && (
        <div className="empty-state">
          {error ? "Host metrics collector not reachable." : "Waiting for host metrics…"}
        </div>
      )}

      {metrics && (
        <div className="sys-grid">
          <div className="bar-list">
            <Meter
              icon={Cpu}
              label={`CPU · ${metrics.cpu.cores} cores`}
              value={metrics.cpu.percent ?? 0}
              displayValue={metrics.cpu.percent !== null ? `${metrics.cpu.percent.toFixed(1)}%` : "—"}
              color={loadColor(metrics.cpu.percent ?? 0)}
              delay={0}
            />
            <Meter
              icon={MemoryStick}
              label="RAM"
              value={metrics.memory.percent ?? 0}
              displayValue={`${(metrics.memory.used_mb / 1024).toFixed(1)} / ${(metrics.memory.total_mb / 1024).toFixed(1)} GB`}
              color={loadColor(metrics.memory.percent ?? 0)}
              delay={0.05}
            />
            <Meter
              icon={HardDrive}
              label={`Disk · ${metrics.disk.path}`}
              value={metrics.disk.percent ?? 0}
              displayValue={`${metrics.disk.used_gb.toFixed(0)} / ${metrics.disk.total_gb.toFixed(0)} GB`}
              color={loadColor(metrics.disk.percent ?? 0)}
              delay={0.1}
            />
            {metrics.gpu?.map((g, i) => (
              <Meter
                key={g.name + i}
                icon={MonitorCog}
                label={g.name}
                value={g.util_percent}
                displayValue={`${g.util_percent.toFixed(0)}% · ${(g.mem_used_mb / 1024).toFixed(1)}/${(g.mem_total_mb / 1024).toFixed(1)} GB · ${g.temp_c.toFixed(0)}°C`}
                color={loadColor(g.util_percent)}
                delay={0.15 + i * 0.05}
              />
            ))}
          </div>

          {metrics.temperatures && metrics.temperatures.length > 0 && (
            <div className="sys-temps">
              <div className="sys-temps-head mono">
                <Thermometer size={12} /> Temperatures
              </div>
              <div className="sys-temps-grid">
                {metrics.temperatures.map((t) => (
                  <div key={t.chip + t.label} className="sys-temp-chip" title={t.chip}>
                    <div className="sys-temp-meta">
                      <span className="sys-temp-label">{t.label}</span>
                      <span className="sys-temp-val mono" style={{ color: tempColor(t.temp_c) }}>
                        {t.temp_c.toFixed(0)}°C
                      </span>
                    </div>
                    <div className="bar-track sys-temp-track">
                      <div
                        className="bar-fill"
                        style={{
                          width: `${Math.min((t.temp_c / MAX_TEMP_C) * 100, 100)}%`,
                          background: tempColor(t.temp_c),
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
