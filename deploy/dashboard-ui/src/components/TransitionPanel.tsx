import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, Zap } from "lucide-react";
import type { TransitionEntry } from "../types";

type Props = { transitions: TransitionEntry[] };

function formatTime(ts?: string) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString("en-GB", { hour12: false });
  } catch {
    return ts.slice(0, 19);
  }
}

export function TransitionPanel({ transitions }: Props) {
  const rows = [...transitions].reverse().slice(0, 12);

  return (
    <section className="glass-card panel transition-panel">
      <div className="panel-head">
        <div>
          <h2>Level transitions</h2>
          <p>L1 → L2 → BURN escalation log</p>
        </div>
        <span className="badge badge-emerald">{transitions.length} recorded</span>
      </div>

      <div className="transition-list">
        <AnimatePresence initial={false}>
          {rows.length === 0 && (
            <div className="empty-state">
              No transitions yet — run <code>./cs attacker</code> or <code>./cs set-level L2</code>
            </div>
          )}
          {rows.map((t, i) => (
            <motion.div
              key={`${t.timestamp}-${t.from_level}-${t.to_level}-${i}`}
              className="transition-row"
              initial={{ opacity: 0, x: -16 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0 }}
              transition={{ delay: i * 0.04 }}
            >
              <span className="mono transition-time">{formatTime(t.timestamp)}</span>
              <div className="transition-flow">
                <span className="level-chip from">{t.from_level ?? "?"}</span>
                <ArrowRight size={16} className="transition-arrow" />
                <span className="level-chip to">{t.to_level ?? "?"}</span>
              </div>
              <span className="transition-rationale">{t.rationale ?? t.trigger ?? "—"}</span>
              {t.actor_key && <span className="mono transition-actor">{t.actor_key.slice(0, 20)}</span>}
              <Zap size={14} className="transition-zap" />
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </section>
  );
}
