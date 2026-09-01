import { motion } from "framer-motion";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { PIE_COLORS } from "../charts/theme";

const LEVEL_COLORS: Record<string, string> = {
  L0: "#64748b",
  L1: "#60a5fa",
  L2: "#34d399",
  L3: "#a78bfa",
  BURN: "#fb7185",
  BLOCK: "#f87171",
};

export function LevelDonut({ levels }: { levels: Record<string, number> }) {
  const rows = Object.entries(levels).map(([name, value]) => ({ name, value }));
  if (!rows.length) return <div className="chart-empty">No level data</div>;

  return (
    <motion.div className="chart-box chart-box-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <ResponsiveContainer width="100%" height={180}>
        <PieChart>
          <Pie data={rows} cx="50%" cy="50%" innerRadius={48} outerRadius={72} dataKey="value" stroke="none" paddingAngle={2}>
            {rows.map((r) => (
              <Cell key={r.name} fill={LEVEL_COLORS[r.name] ?? PIE_COLORS[0]} />
            ))}
          </Pie>
          <Tooltip
            content={({ active, payload }) =>
              active && payload?.[0] ? (
                <div className="chart-tooltip">
                  <div className="chart-tooltip-title">{payload[0].name}</div>
                  <div className="chart-tooltip-row mono">{String(payload[0].value)} events</div>
                </div>
              ) : null
            }
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="level-chips">
        {rows.map((r) => (
          <span key={r.name} className="level-chip mono" style={{ borderColor: LEVEL_COLORS[r.name] ?? "#64748b" }}>
            {r.name} <strong>{r.value}</strong>
          </span>
        ))}
      </div>
    </motion.div>
  );
}
