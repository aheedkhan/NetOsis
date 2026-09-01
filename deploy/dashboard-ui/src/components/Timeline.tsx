import { AnimatePresence, motion } from "framer-motion";
import type { TimelineEntry } from "../types";

type Props = { entries: TimelineEntry[] };

const DATASET_COLORS: Record<string, string> = {
  "cybersnare.zeek.conn": "badge-cyan",
  "cybersnare.zeek.http": "badge-cyan",
  "cybersnare.zeek.ssh": "badge-violet",
  "cybersnare.zeek.ssl": "badge-violet",
  "cybersnare.http.request": "badge-amber",
  "cybersnare.ssh.auth": "badge-amber",
  "cybersnare.shell.command": "badge-emerald",
  "cybersnare.sinkhole.dns": "badge-rose",
  "cybersnare.sinkhole.http": "badge-rose",
  "cybersnare.decision.transition": "badge-emerald",
};

function shortDataset(ds?: string) {
  return (ds ?? "unknown").replace("cybersnare.", "");
}

function shortActor(key?: string) {
  if (!key) return "—";
  return key.length > 28 ? `${key.slice(0, 26)}…` : key;
}

function formatTime(ts?: string) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return ts.slice(11, 19);
  }
}

export function Timeline({ entries }: Props) {
  const rows = [...entries].reverse().slice(0, 30);

  return (
    <motion.section
      className="glass-card panel timeline-panel"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.3 }}
    >
      <div className="panel-head">
        <div>
          <h2>Live timeline</h2>
          <p>ATT&CK / Engage enrichment per event</p>
        </div>
        <span className="badge badge-cyan">streaming</span>
      </div>

      <div className="timeline-table-wrap">
        <table className="timeline-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Dataset</th>
              <th>Actor</th>
              <th>Level</th>
              <th>ATT&CK</th>
              <th>Engage</th>
            </tr>
          </thead>
          <tbody>
            <AnimatePresence initial={false} mode="popLayout">
              {rows.map((e, i) => (
                <motion.tr
                  key={`${e.timestamp}-${e.dataset}-${e.actor_key}-${i}`}
                  layout
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.25, delay: i * 0.015 }}
                >
                  <td className="mono time-cell">{formatTime(e.timestamp)}</td>
                  <td>
                    <span
                      className={`badge ${DATASET_COLORS[e.dataset ?? ""] ?? "badge-violet"}`}
                    >
                      {shortDataset(e.dataset)}
                    </span>
                  </td>
                  <td className="mono actor-cell">{shortActor(e.actor_key)}</td>
                  <td>
                    {e.level ? (
                      <span className="badge badge-amber">{e.level}</span>
                    ) : (
                      <span className="dim">—</span>
                    )}
                  </td>
                  <td className="mono tech-cell">{e.technique ?? "—"}</td>
                  <td className="mono">{e.engage ?? "—"}</td>
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>
        {rows.length === 0 && (
          <div className="empty-state">No events yet — run ./cs redteam to generate traffic</div>
        )}
      </div>
    </motion.section>
  );
}
