import { motion } from "framer-motion";
import type { EngageMatrix, TechniqueMatrix } from "../types";

const LEVEL_COLORS: Record<string, string> = {
  L0: "#64748b",
  L1: "#60a5fa",
  L2: "#34d399",
  L3: "#a78bfa",
  BURN: "#fb7185",
};

const ENGAGE_LABELS: Record<string, string> = {
  EAC0001: "Observe",
  EAC0003: "Attract",
  EAC0004: "Reveal",
  EAC0005: "Engage",
  EAC0009: "Burn",
};

type Props = {
  engage: EngageMatrix;
  technique: TechniqueMatrix;
};

function HeatmapGrid({
  title,
  subtitle,
  levels,
  columns,
  cells,
  colKey,
  colLabel,
}: {
  title: string;
  subtitle: string;
  levels: string[];
  columns: string[];
  cells: { level: string; count: number; [key: string]: string | number }[];
  colKey: string;
  colLabel: (v: string) => string;
}) {
  const max = Math.max(...cells.map((c) => c.count), 1);
  const cellMap = new Map(cells.map((c) => [`${c.level}:${c[colKey]}`, c.count]));

  return (
    <div className="heatmap-block">
      <div className="heatmap-head">
        <h3>{title}</h3>
        <p>{subtitle}</p>
      </div>
      {levels.length === 0 || columns.length === 0 ? (
        <div className="empty-state small">No mapped events yet</div>
      ) : (
        <div className="heatmap-scroll">
          <table className="heatmap-table">
            <thead>
              <tr>
                <th>Level</th>
                {columns.map((col) => (
                  <th key={col} className="mono">
                    {colLabel(col)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {levels.map((lvl) => (
                <tr key={lvl}>
                  <td>
                    <span className="heatmap-level" style={{ color: LEVEL_COLORS[lvl] ?? "#94a3b8" }}>
                      {lvl}
                    </span>
                  </td>
                  {columns.map((col) => {
                    const count = cellMap.get(`${lvl}:${col}`) ?? 0;
                    const intensity = count / max;
                    return (
                      <td key={col}>
                        <motion.div
                          className="heatmap-cell"
                          style={{
                            background: count
                              ? `rgba(34, 211, 238, ${0.08 + intensity * 0.72})`
                              : "rgba(15,23,42,0.4)",
                            borderColor: count ? `rgba(34,211,238,${0.2 + intensity * 0.5})` : undefined,
                          }}
                          initial={{ scale: 0.8, opacity: 0 }}
                          animate={{ scale: 1, opacity: 1 }}
                          whileHover={{ scale: 1.08 }}
                          title={`${lvl} × ${col}: ${count}`}
                        >
                          {count > 0 && <span className="mono">{count}</span>}
                        </motion.div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function EngageLevelHeatmap({ engage, technique }: Props) {
  return (
    <section className="glass-card panel heatmap-panel">
      <div className="panel-head">
        <div>
          <h2>L1 / L2 pattern map</h2>
          <p>Engage codes &amp; techniques by deception level — darker = more events</p>
        </div>
        <span className="badge badge-emerald">heatmap</span>
      </div>

      <div className="heatmap-duo">
        <HeatmapGrid
          title="MITRE Engage × Level"
          subtitle="EAC0003 Attract (L1) vs EAC0005 Engage (L2)"
          levels={engage.levels}
          columns={engage.engages}
          cells={engage.cells}
          colKey="engage"
          colLabel={(v) => ENGAGE_LABELS[v] ?? v}
        />
        <HeatmapGrid
          title="ATT&CK × Level"
          subtitle="Which techniques fire at each ladder step"
          levels={technique.levels}
          columns={technique.techniques}
          cells={technique.cells}
          colKey="technique"
          colLabel={(v) => v}
        />
      </div>
    </section>
  );
}
