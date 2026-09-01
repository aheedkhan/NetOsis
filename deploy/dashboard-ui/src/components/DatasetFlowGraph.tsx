import { motion } from "framer-motion";
import { ArrowRight } from "lucide-react";
import type { DatasetFlowEdge } from "../types";
import { CHART } from "../charts/theme";

const FAM_COLORS: Record<string, string> = {
  zeek: CHART.zeek,
  http: CHART.http,
  ssh: CHART.ssh,
  shell: CHART.shell,
  sinkhole: CHART.sinkhole,
  decision: CHART.decision,
  other: CHART.other,
};

type Props = { edges: DatasetFlowEdge[] };

export function DatasetFlowGraph({ edges }: Props) {
  const max = Math.max(...edges.map((e) => e.count), 1);

  return (
    <section className="glass-card panel flow-graph-panel">
      <div className="panel-head">
        <div>
          <h2>Telemetry flow</h2>
          <p>How attackers move between surfaces — recon → auth → shell → sinkhole</p>
        </div>
        <span className="badge badge-amber">transitions</span>
      </div>

      {edges.length === 0 ? (
        <div className="empty-state">No cross-surface flows recorded yet</div>
      ) : (
        <div className="flow-edge-list">
          {edges.map((e, i) => {
            const w = 24 + (e.count / max) * 76;
            const fromColor = FAM_COLORS[e.from] ?? CHART.other;
            const toColor = FAM_COLORS[e.to] ?? CHART.other;
            return (
              <motion.div
                key={`${e.from}-${e.to}`}
                className="flow-edge"
                initial={{ opacity: 0, x: -12 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.04 }}
              >
                <span className="flow-node" style={{ borderColor: fromColor, color: fromColor }}>
                  {e.from}
                </span>
                <div className="flow-connector" style={{ width: `${w}%` }}>
                  <motion.div
                    className="flow-pulse"
                    style={{ background: `linear-gradient(90deg, ${fromColor}, ${toColor})` }}
                    animate={{ x: ["-100%", "200%"] }}
                    transition={{ duration: 2 + i * 0.2, repeat: Infinity, ease: "linear" }}
                  />
                  <ArrowRight size={14} className="flow-arrow-icon" />
                  <span className="flow-count mono">×{e.count}</span>
                </div>
                <span className="flow-node" style={{ borderColor: toColor, color: toColor }}>
                  {e.to}
                </span>
              </motion.div>
            );
          })}
        </div>
      )}
    </section>
  );
}
