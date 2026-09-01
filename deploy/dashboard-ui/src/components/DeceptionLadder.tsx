import { motion } from "framer-motion";
import { Flame, Lock, Shield, Terminal, Eye } from "lucide-react";
import type { LadderStep } from "../types";

const ICONS: Record<string, typeof Eye> = {
  L0: Eye,
  L1: Shield,
  L2: Terminal,
  L3: Lock,
  BURN: Flame,
};

const LEVEL_COLORS: Record<string, string> = {
  L0: "ladder-l0",
  L1: "ladder-l1",
  L2: "ladder-l2",
  L3: "ladder-l3",
  BURN: "ladder-burn",
};

type Props = {
  ladder: LadderStep[];
  activeLevel: string;
  policy?: string;
  manifestId?: string;
};

export function DeceptionLadder({ ladder, activeLevel, policy, manifestId }: Props) {
  const activeIdx = ladder.findIndex((s) => s.id === activeLevel);

  return (
    <section className="glass-card panel deception-ladder-panel">
      <div className="panel-head">
        <div>
          <h2>Deception ladder</h2>
          <p>MITRE Engage levels — active posture highlighted</p>
        </div>
        <div className="ladder-meta">
          <span className={`badge badge-active-level ${LEVEL_COLORS[activeLevel] ?? ""}`}>
            {activeLevel} active
          </span>
          {policy && <span className="badge badge-violet mono">{policy}</span>}
          {manifestId && <span className="mono dim manifest-id">{manifestId}</span>}
        </div>
      </div>

      <div className="ladder-track">
        {ladder.map((step, i) => {
          const Icon = ICONS[step.id] ?? Shield;
          const isActive = step.id === activeLevel;
          const isPast = activeIdx >= 0 && i < activeIdx;
          const colorClass = LEVEL_COLORS[step.id] ?? "ladder-l1";

          return (
            <div key={step.id} className="ladder-step-wrap">
              {i > 0 && (
                <motion.div
                  className={`ladder-connector ${isPast || isActive ? "lit" : ""}`}
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ delay: i * 0.08 }}
                />
              )}
              <motion.div
                className={`ladder-step ${colorClass} ${isActive ? "active" : ""} ${isPast ? "past" : ""}`}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.06 }}
                whileHover={{ scale: 1.02 }}
              >
                {isActive && (
                  <motion.span
                    className="ladder-pulse"
                    animate={{ opacity: [0.4, 1, 0.4], scale: [1, 1.15, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />
                )}
                <div className="ladder-icon">
                  <Icon size={22} strokeWidth={2} />
                </div>
                <div className="ladder-label">
                  <strong>{step.id}</strong>
                  <span>{step.name}</span>
                </div>
                <span className="ladder-engage mono">{step.engage}</span>
                <p className="ladder-summary">{step.summary}</p>
              </motion.div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
