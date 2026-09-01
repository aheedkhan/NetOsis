import { motion, AnimatePresence } from "framer-motion";
import { useMemo } from "react";
import type { TopologyMap, Capability } from "../types";
import { CAPABILITY_COLOR } from "../charts/theme";

type Props = {
  topology: TopologyMap | null;
  onSelectActor?: (actorKey: string) => void;
};

const TRUST_TONE: Record<string, string> = {
  hostile: "hostile",
  low: "low",
  medium: "medium",
  high: "high",
  "adversary-facing": "hostile",
  contained: "contained",
  control: "control",
  infrastructure: "control",
};

function capabilityLabel(c?: Capability | null) {
  if (c === "automated") return "Bot — blocked";
  if (c === "interactive_operator") return "Human — engaged";
  if (c === "scripted") return "Unclear — observed";
  return "Unclassified";
}

export function NetworkMap({ topology, onSelectActor }: Props) {
  const rows = useMemo(() => {
    if (!topology) return [];
    const byRow = new Map<number, typeof topology.zones>();
    for (const z of topology.zones) {
      const r = z.row ?? 9;
      if (!byRow.has(r)) byRow.set(r, []);
      byRow.get(r)!.push(z);
    }
    return [...byRow.entries()].sort((a, b) => a[0] - b[0]);
  }, [topology]);

  if (!topology) {
    return (
      <section className="glass-card panel netmap-panel">
        <div className="empty-state">Loading topology…</div>
      </section>
    );
  }

  const hostsByZone = new Map<string, typeof topology.hosts>();
  for (const h of topology.hosts) {
    if (!hostsByZone.has(h.zone)) hostsByZone.set(h.zone, []);
    hostsByZone.get(h.zone)!.push(h);
  }

  const actorsByZone = new Map<string, typeof topology.actors>();
  for (const a of topology.actors) {
    if (!actorsByZone.has(a.zone)) actorsByZone.set(a.zone, []);
    actorsByZone.get(a.zone)!.push(a);
  }

  return (
    <motion.section
      className="glass-card panel netmap-panel"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div className="panel-head">
        <div>
          <h2>{topology.org.name}</h2>
          <p>Live network map — where every tracked address actually sits, not a fictional geography</p>
        </div>
        <span className="badge badge-cyan">{topology.actors.length} placed</span>
      </div>

      <div className="netmap-legend">
        <span><i className="netmap-dot" style={{ background: CAPABILITY_COLOR.interactive_operator }} /> Human — engaged</span>
        <span><i className="netmap-dot" style={{ background: CAPABILITY_COLOR.automated }} /> Bot — blocked</span>
        <span><i className="netmap-dot" style={{ background: CAPABILITY_COLOR.scripted }} /> Unclear</span>
      </div>

      <div className="netmap-rows">
        {rows.map(([rowIdx, zones], ri) => (
          <div key={rowIdx} className="netmap-row">
            {ri > 0 && <div className="netmap-row-connector" aria-hidden />}
            <div className="netmap-row-zones">
              {zones.map((zone) => {
                const hosts = hostsByZone.get(zone.id) ?? [];
                const actors = actorsByZone.get(zone.id) ?? [];
                const tone = TRUST_TONE[zone.trust ?? ""] ?? "medium";
                return (
                  <div key={zone.id} className={`netmap-zone tone-${tone}`}>
                    <div className="netmap-zone-head">
                      <strong>{zone.label}</strong>
                      {zone.cidr && <span className="mono netmap-cidr">{zone.cidr}</span>}
                    </div>
                    {zone.note && <p className="netmap-note">{zone.note}</p>}
                    {hosts.length > 0 && (
                      <ul className="netmap-hosts">
                        {hosts.map((h) => (
                          <li key={h.id} className={`netmap-host kind-${h.kind}`}>
                            <span>{h.label}</span>
                            <span className="mono netmap-host-ip">{h.ip}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                    <AnimatePresence>
                      {actors.length > 0 && (
                        <div className="netmap-actors">
                          {actors.map((a) => (
                            <motion.button
                              key={a.actor_key}
                              type="button"
                              className="netmap-actor-pin"
                              title={`${a.actor_key} — ${capabilityLabel(a.capability)}`}
                              onClick={() => onSelectActor?.(a.actor_key)}
                              initial={{ scale: 0, opacity: 0 }}
                              animate={{ scale: 1, opacity: 1 }}
                              exit={{ scale: 0, opacity: 0 }}
                              whileHover={{ scale: 1.15 }}
                              style={{
                                borderColor: CAPABILITY_COLOR[a.capability ?? "scripted"],
                              }}
                            >
                              <span
                                className="netmap-actor-dot"
                                style={{ background: CAPABILITY_COLOR[a.capability ?? "scripted"] }}
                              />
                              <span className="mono netmap-actor-ip">{a.ip}</span>
                              <span className="netmap-actor-events">{a.events}</span>
                            </motion.button>
                          ))}
                        </div>
                      )}
                    </AnimatePresence>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </motion.section>
  );
}
