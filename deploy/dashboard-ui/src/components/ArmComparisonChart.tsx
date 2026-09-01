import { motion } from "framer-motion";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { CHART } from "../charts/theme";
import type { ArmStats } from "../types";

const ARM_LABELS: Record<string, string> = {
  A: "Arm A",
  B: "Arm B",
  C: "Arm C",
  "?": "Unknown",
};

function Tip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip-title">{label}</div>
      {payload.map((p) => (
        <div key={p.name} className="chart-tooltip-row">
          <span className="chart-tooltip-dot" style={{ background: p.color }} />
          <span>{p.name}</span>
          <span className="mono">{p.value?.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

export function ArmComparisonChart({ arms }: { arms: Record<string, ArmStats> }) {
  const rows = Object.entries(arms).map(([arm, s]) => ({
    arm: ARM_LABELS[arm] ?? arm,
    events: s.events,
    actors: s.actors,
    transitions: s.transitions,
    shell: s.shell_commands,
  }));

  if (!rows.length) return <div className="chart-empty">No arm data</div>;

  return (
    <motion.div className="chart-box" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <ResponsiveContainer width="100%" height={240}>
        <BarChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid stroke={CHART.grid} strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="arm" tick={{ fill: CHART.axis, fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: CHART.axis, fontSize: 11 }} axisLine={false} tickLine={false} width={42} />
          <Tooltip content={<Tip />} />
          <Legend wrapperStyle={{ fontSize: 11 }} formatter={(v) => <span style={{ color: "#94a3b8" }}>{v}</span>} />
          <Bar dataKey="events" name="Events" fill={CHART.zeek} radius={[4, 4, 0, 0]} />
          <Bar dataKey="actors" name="Actors" fill={CHART.ssh} radius={[4, 4, 0, 0]} />
          <Bar dataKey="transitions" name="Transitions" fill={CHART.decision} radius={[4, 4, 0, 0]} />
          <Bar dataKey="shell" name="Shell cmds" fill={CHART.shell} radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </motion.div>
  );
}
