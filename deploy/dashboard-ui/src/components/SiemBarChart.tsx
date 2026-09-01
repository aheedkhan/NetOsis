import { motion } from "framer-motion";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { CHART } from "../charts/theme";

type Props = {
  data: Record<string, number>;
  color?: string;
  layout?: "vertical" | "horizontal";
};

function Tip({ active, payload, label }: { active?: boolean; payload?: { value: number }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-title">{label}</div>
      <div className="chart-tooltip-row mono">{payload[0].value?.toLocaleString()}</div>
    </div>
  );
}

export function SiemBarChart({ data, color = CHART.zeek, layout = "vertical" }: Props) {
  const rows = Object.entries(data)
    .slice(0, 10)
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  if (!rows.length) return <div className="chart-empty">No data</div>;

  const vertical = layout === "vertical";

  return (
    <motion.div className="chart-box" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <ResponsiveContainer width="100%" height={vertical ? 260 : 220}>
        <BarChart
          data={rows}
          layout={vertical ? "vertical" : "horizontal"}
          margin={{ top: 4, right: 12, left: vertical ? 4 : 0, bottom: 4 }}
        >
          <CartesianGrid stroke={CHART.grid} strokeDasharray="3 3" horizontal={!vertical} vertical={vertical} />
          {vertical ? (
            <>
              <XAxis type="number" tick={{ fill: CHART.axis, fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={52} tick={{ fill: CHART.axis, fontSize: 10 }} axisLine={false} tickLine={false} />
            </>
          ) : (
            <>
              <XAxis dataKey="name" tick={{ fill: CHART.axis, fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: CHART.axis, fontSize: 10 }} axisLine={false} tickLine={false} width={36} />
            </>
          )}
          <Tooltip content={<Tip />} cursor={{ fill: "rgba(34,211,238,0.06)" }} />
          <Bar dataKey="value" fill={color} radius={vertical ? [0, 4, 4, 0] : [4, 4, 0, 0]} maxBarSize={28} />
        </BarChart>
      </ResponsiveContainer>
    </motion.div>
  );
}
