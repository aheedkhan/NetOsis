import { motion } from "framer-motion";
import type { ActorRow } from "../types";

function fmtTime(ts?: string) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return ts.slice(11, 19);
  }
}

function shortActor(key: string) {
  return key.length > 24 ? `${key.slice(0, 22)}…` : key;
}

export function ActorTable({ actors }: { actors: ActorRow[] }) {
  return (
    <motion.section
      className="glass-card panel actor-panel"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.35 }}
    >
      <div className="panel-head">
        <div>
          <h2>Top actors</h2>
          <p>SIEM entity view — ranked by event volume</p>
        </div>
        <span className="badge badge-violet">{actors.length} tracked</span>
      </div>
      <div className="actor-table-wrap">
        <table className="actor-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Actor</th>
              <th>Events</th>
              <th>Level</th>
              <th>Arm</th>
              <th>ATT&CK</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {actors.map((a, i) => (
              <motion.tr
                key={a.actor_key}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.04 * i }}
              >
                <td className="mono rank-cell">{i + 1}</td>
                <td className="mono actor-cell" title={a.actor_key}>{shortActor(a.actor_key)}</td>
                <td className="mono events-cell">{a.events.toLocaleString()}</td>
                <td><span className="badge badge-amber">{a.level}</span></td>
                <td className="mono">{a.arm}</td>
                <td className="mono tech-cell">{a.top_technique ?? "—"}</td>
                <td className="mono time-cell">{fmtTime(a.last_seen)}</td>
              </motion.tr>
            ))}
          </tbody>
        </table>
        {!actors.length && <div className="empty-state">No actors yet</div>}
      </div>
    </motion.section>
  );
}
