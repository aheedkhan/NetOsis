import { motion } from "framer-motion";

type Props = {
  title: string;
  subtitle: string;
  data: Record<string, number>;
  color: string;
  delay?: number;
};

export function BarChart({ title, subtitle, data, color, delay = 0 }: Props) {
  const entries = Object.entries(data).slice(0, 8);
  const max = Math.max(...entries.map(([, v]) => v), 1);

  return (
    <motion.section
      className="glass-card panel chart-panel"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay }}
    >
      <div className="panel-head compact">
        <div>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
      </div>
      <div className="bar-list">
        {entries.map(([key, value], i) => (
          <div key={key} className="bar-row">
            <div className="bar-meta">
              <span className="bar-key mono">{key.replace("cybersnare.", "")}</span>
              <span className="bar-val mono">{value.toLocaleString()}</span>
            </div>
            <div className="bar-track">
              <motion.div
                className="bar-fill"
                style={{ background: color }}
                initial={{ width: 0 }}
                animate={{ width: `${(value / max) * 100}%` }}
                transition={{
                  duration: 0.7,
                  delay: delay + 0.1 + i * 0.05,
                  ease: [0.22, 1, 0.36, 1],
                }}
              />
            </div>
          </div>
        ))}
        {entries.length === 0 && <div className="empty-state">No data</div>}
      </div>
    </motion.section>
  );
}
