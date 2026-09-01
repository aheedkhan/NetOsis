import { motion } from "framer-motion";
import type { MilestoneReport } from "../types";

const ARM_LABELS: Record<string, string> = {
  A: "Arm A · P0 static",
  B: "Arm B · P1 adaptive",
  C: "Arm C · P2 intent",
  "?": "Unknown",
};

const ARM_COLORS: Record<string, string> = {
  A: "var(--blue)",
  B: "var(--cyan)",
  C: "var(--emerald)",
  "?": "var(--muted)",
};

type Props = { report: MilestoneReport };

export function ArmsPanel({ report }: Props) {
  const arms = Object.entries(report.arms ?? {});
  const maxEvents = Math.max(...arms.map(([, s]) => s.events), 1);

  return (
    <motion.section
      className="glass-card panel"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.35 }}
    >
      <div className="panel-head">
        <div>
          <h2>Experimental arms</h2>
          <p>Three-arm milestone comparison</p>
        </div>
      </div>
      <div className="arms-grid">
        {arms.length === 0 && (
          <div className="empty-state">No arm data — events not tagged yet</div>
        )}
        {arms.map(([arm, stats], i) => (
          <motion.div
            key={arm}
            className="arm-card"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.4 + i * 0.08 }}
            whileHover={{ scale: 1.02 }}
          >
            <div className="arm-head">
              <span className="arm-id mono" style={{ color: ARM_COLORS[arm] ?? ARM_COLORS["?"] }}>
                {arm}
              </span>
              <span className="arm-label">{ARM_LABELS[arm] ?? `Arm ${arm}`}</span>
            </div>
            <div className="arm-bar-track">
              <motion.div
                className="arm-bar-fill"
                style={{ background: ARM_COLORS[arm] ?? ARM_COLORS["?"] }}
                initial={{ width: 0 }}
                animate={{ width: `${(stats.events / maxEvents) * 100}%` }}
                transition={{ duration: 0.8, delay: 0.5 + i * 0.1, ease: [0.22, 1, 0.36, 1] }}
              />
            </div>
            <div className="arm-metrics">
              <div>
                <span className="metric-val mono">{stats.events.toLocaleString()}</span>
                <span className="metric-lbl">events</span>
              </div>
              <div>
                <span className="metric-val mono">{stats.actors}</span>
                <span className="metric-lbl">actors</span>
              </div>
              <div>
                <span className="metric-val mono">{stats.transitions}</span>
                <span className="metric-lbl">transitions</span>
              </div>
              <div>
                <span className="metric-val mono">{stats.shell_commands}</span>
                <span className="metric-lbl">shell cmds</span>
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </motion.section>
  );
}
