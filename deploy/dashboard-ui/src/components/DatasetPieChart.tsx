import { motion } from "framer-motion";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { PIE_COLORS, shortDataset } from "../charts/theme";

type Props = { data: Record<string, number> };

function Tip({ active, payload }: { active?: boolean; payload?: { name: string; value: number }[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-title">{p.name}</div>
      <div className="chart-tooltip-row mono">{p.value?.toLocaleString()} events</div>
    </div>
  );
}

export function DatasetPieChart({ data }: Props) {
  const rows = Object.entries(data)
    .slice(0, 8)
    .map(([name, value]) => ({ name: shortDataset(name), value }));

  if (!rows.length) return <div className="chart-empty">No datasets</div>;

  return (
    <motion.div className="chart-box chart-box-pie" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.25 }}>
      <ResponsiveContainer width="100%" height={280}>
        <PieChart>
          <Pie
            data={rows}
            cx="50%"
            cy="50%"
            innerRadius={62}
            outerRadius={96}
            paddingAngle={2}
            dataKey="value"
            stroke="none"
          >
            {rows.map((_, i) => (
              <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
            ))}
          </Pie>
          <Tooltip content={<Tip />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="pie-legend">
        {rows.map((r, i) => (
          <div key={r.name} className="pie-legend-row">
            <span className="pie-legend-dot" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} />
            <span className="pie-legend-name">{r.name}</span>
            <span className="pie-legend-val mono">{r.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
