import { motion } from "framer-motion";
import { ArrowRight, GitBranch } from "lucide-react";
import type { AttackPattern } from "../types";

const STEP_COLORS: Record<string, string> = {
  T1595: "#22d3ee",
  T1078: "#60a5fa",
  T1059: "#34d399",
  T1497: "#f472b6",
  T1007: "#a78bfa",
  T1071: "#fb7185",
  T1105: "#fb7185",
  T1021: "#fbbf24",
  T1598: "#94a3b8",
};

function stepColor(label: string) {
  return STEP_COLORS[label] ?? "#64748b";
}

type Props = { patterns: AttackPattern[] };

export function AttackPatternChains({ patterns }: Props) {
  if (!patterns.length) {
    return (
      <section className="glass-card panel pattern-chains-panel">
        <div className="panel-head">
          <div>
            <h2>Attack patterns</h2>
            <p>Repeated technique sequences per actor</p>
          </div>
        </div>
        <div className="empty-state">No patterns yet — run <code>./cs attacker</code> or <code>./cs redteam</code></div>
      </section>
    );
  }

  return (
    <section className="glass-card panel pattern-chains-panel">
      <div className="panel-head">
        <div>
          <h2>Attack patterns</h2>
          <p>Repeated technique sequences — recon → access → execution → C2</p>
        </div>
        <span className="badge badge-cyan">{patterns.length} chains</span>
      </div>

      <div className="pattern-chain-list">
        {patterns.map((p, pi) => (
          <motion.div
            key={p.signature}
            className="pattern-chain-card"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: pi * 0.06 }}
          >
            <div className="pattern-chain-meta">
              <GitBranch size={14} />
              <span className="mono">×{p.count}</span>
              {p.steps[0]?.level && (
                <span className={`badge badge-${p.steps[0].level.toLowerCase()}`}>{p.steps[0].level}</span>
              )}
            </div>
            <div className="pattern-chain-flow">
              {p.steps.map((s, si) => (
                <div key={`${s.label}-${si}`} className="pattern-step-wrap">
                  {si > 0 && <ArrowRight size={14} className="pattern-step-arrow" />}
                  <motion.div
                    className="pattern-step"
                    style={{ borderColor: stepColor(s.label), background: `${stepColor(s.label)}15` }}
                    whileHover={{ scale: 1.04 }}
                  >
                    <strong className="mono">{s.label}</strong>
                    {s.technique_name && <span className="pattern-step-name">{s.technique_name}</span>}
                    {s.tactic && <span className="pattern-step-tactic">{s.tactic}</span>}
                    {s.level && <span className="pattern-step-level mono">{s.level}</span>}
                  </motion.div>
                </div>
              ))}
            </div>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
