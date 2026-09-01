import { AnimatePresence, motion } from "framer-motion";
import { Terminal } from "lucide-react";
import type { TimelineEntry } from "../types";

type Props = { entries: TimelineEntry[] };

const LEVEL_STYLE: Record<string, string> = {
  L0: "log-l0",
  L1: "log-l1",
  L2: "log-l2",
  L3: "log-l3",
  BURN: "log-burn",
};

const DATASET_STYLE: Record<string, string> = {
  "cybersnare.decision.transition": "log-transition",
  "cybersnare.shell.command": "log-shell",
  "cybersnare.ssh.auth": "log-ssh",
  "cybersnare.http.request": "log-http",
  "cybersnare.sinkhole.dns": "log-sinkhole",
  "cybersnare.sinkhole.http": "log-sinkhole",
};

function shortDataset(ds?: string) {
  return (ds ?? "unknown").replace("cybersnare.", "");
}

function formatTime(ts?: string) {
  if (!ts) return "??:??:??";
  try {
    return new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
  } catch {
    return ts.slice(11, 19);
  }
}

function logLine(e: TimelineEntry): string {
  const parts = [
    shortDataset(e.dataset),
    e.action,
    e.technique,
    e.engage,
    e.source_ip,
    e.actor_key?.slice(0, 24),
  ].filter(Boolean);
  return parts.join(" · ");
}

export function LiveLogStream({ entries }: Props) {
  const rows = [...entries].reverse().slice(0, 40);

  return (
    <section className="glass-card panel live-log-panel">
      <div className="panel-head">
        <div>
          <h2>
            <Terminal size={18} style={{ display: "inline", marginRight: 8, verticalAlign: -3 }} />
            Live event log
          </h2>
          <p>Terminal-style JSONL tail — color by level & dataset</p>
        </div>
        <span className="badge badge-cyan mono">tail -40</span>
      </div>

      <div className="log-terminal">
        <div className="log-chrome">
          <span className="log-dot red" />
          <span className="log-dot amber" />
          <span className="log-dot green" />
          <span className="log-title mono">events.jsonl</span>
        </div>
        <div className="log-body">
          <AnimatePresence initial={false}>
            {rows.length === 0 && (
              <div className="log-line log-dim">waiting for telemetry…</div>
            )}
            {rows.map((e, i) => {
              const levelClass = LEVEL_STYLE[e.level ?? ""] ?? "";
              const dsClass = DATASET_STYLE[e.dataset ?? ""] ?? "log-default";
              return (
                <motion.div
                  key={`${e.timestamp}-${e.dataset}-${i}`}
                  className={`log-line ${levelClass} ${dsClass}`}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.2, delay: i * 0.01 }}
                >
                  <span className="log-ts">{formatTime(e.timestamp)}</span>
                  {e.level && <span className="log-level">[{e.level}]</span>}
                  <span className="log-msg">{logLine(e)}</span>
                </motion.div>
              );
            })}
          </AnimatePresence>
        </div>
      </div>
    </section>
  );
}
