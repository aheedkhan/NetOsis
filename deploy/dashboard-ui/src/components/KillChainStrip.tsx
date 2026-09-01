import { motion } from "framer-motion";
import { ArrowRight } from "lucide-react";
import type { KillChainTactic } from "../types";

const TACTIC_COLORS: Record<string, string> = {
  TA0043: "#22d3ee",
  TA0001: "#60a5fa",
  TA0002: "#34d399",
  TA0007: "#a78bfa",
  TA0005: "#f472b6",
  TA0011: "#fb7185",
  TA0008: "#fbbf24",
  TA0006: "#94a3b8",
};

type Props = { tactics: KillChainTactic[] };

export function KillChainStrip({ tactics }: Props) {
  const max = Math.max(...tactics.map((t) => t.count), 1);

  return (
    <section className="glass-card panel kill-chain-panel">
      <div className="panel-head">
        <div>
          <h2>MITRE kill chain</h2>
          <p>Attack tactic progression — node size = event volume</p>
        </div>
        <span className="badge badge-violet">ATT&CK</span>
      </div>

      <div className="kill-chain-strip">
        {tactics.map((t, i) => {
          const scale = 0.55 + (t.count / max) * 0.45;
          const color = TACTIC_COLORS[t.id] ?? "#94a3b8";
          const active = t.count > 0;

          return (
            <div key={t.id} className="kill-chain-node-wrap">
              {i > 0 && (
                <motion.div
                  className={`kill-chain-arrow ${active ? "lit" : ""}`}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.05 }}
                >
                  <ArrowRight size={18} />
                </motion.div>
              )}
              <motion.div
                className={`kill-chain-node ${active ? "active" : "idle"}`}
                style={{
                  borderColor: active ? color : undefined,
                  boxShadow: active ? `0 0 20px ${color}33` : undefined,
                }}
                initial={{ scale: 0, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: i * 0.06, type: "spring", stiffness: 260 }}
              >
                <motion.div
                  className="kill-chain-bubble"
                  style={{
                    background: active ? `${color}22` : undefined,
                    borderColor: active ? color : undefined,
                    transform: `scale(${scale})`,
                  }}
                  animate={active ? { scale: [scale, scale * 1.06, scale] } : {}}
                  transition={{ duration: 2.5, repeat: Infinity, delay: i * 0.2 }}
                >
                  <span className="kill-chain-count mono">{t.count}</span>
                </motion.div>
                <span className="kill-chain-id mono">{t.id.replace("TA", "T")}</span>
                <span className="kill-chain-name">{t.name}</span>
              </motion.div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
