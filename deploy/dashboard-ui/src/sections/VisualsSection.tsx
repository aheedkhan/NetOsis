/**
 * Attack map — human-readable story timeline (left → right) + network path strip.
 */
import { motion } from "framer-motion";
import { ArrowRight, ChevronRight, Download, Info, Search, Server } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { DeceptionState, GraphNode, OperationMap, OperationNode } from "../types";
import { useAttackGraph } from "../useAttackGraph";
import "./visuals-section.css";

const ATTACK_MAP_PDF = "/CyberSnare-Attack-Map-Guide.pdf";

const LEVEL_COPY: Record<string, string> = {
  L1: "Attract — recon only, login blocked",
  L2: "Engage — attacker can log in",
  BURN: "Burn — honeypot surfaces hidden",
};

const PHASE_HUMAN: Record<string, { title: string; explain: string }> = {
  infiltration: {
    title: "1 · Infiltration",
    explain: "Attacker finds and probes your exposed services (scan, SSH, web login).",
  },
  execution: {
    title: "2 · Execution",
    explain: "Attacker runs commands inside the restricted shell.",
  },
  discovery: {
    title: "3 · Discovery",
    explain: "Attacker checks if the machine is real or a VM / honeypot.",
  },
  exfiltration: {
    title: "4 · Exfiltration / C2",
    explain: "Attacker tries to reach malware domains — caught by the sinkhole.",
  },
};

const SURFACE_HUMAN: Record<string, string> = {
  zeek: "Network sensor saw traffic",
  ssh: "SSH honeypot",
  https: "Web portal",
  shell: "Restricted shell",
  sinkhole: "Sinkhole (trapped callback)",
  decision: "Deception policy",
  other: "Other telemetry",
};

const TECH_HUMAN: Record<string, string> = {
  T1595: "Active scan",
  T1078: "Login attempt",
  T1059: "Command run",
  T1497: "VM / sandbox check",
  T1007: "System discovery",
  T1071: "C2 callback (DNS)",
  T1105: "Payload download",
  T1021: "Remote service",
  T1598: "Info gathering",
};

function humanLabel(node: OperationNode) {
  if (node.technique_name) return node.technique_name;
  const tech = node.label?.startsWith("T") ? TECH_HUMAN[node.label] : undefined;
  if (tech) return tech;
  return node.label ?? "Activity";
}

function stepsByPhase(op: OperationMap) {
  const order = ["infiltration", "execution", "discovery", "exfiltration"];
  const groups: Record<string, OperationNode[]> = {};
  for (const n of op.nodes) {
    if (n.type === "attacker") continue;
    const p = n.phase ?? "infiltration";
    (groups[p] ??= []).push(n);
  }
  return order
    .filter((p) => (groups[p]?.length ?? 0) > 0)
    .map((p) => ({ phase: p, steps: groups[p] }));
}

function NetworkPathBar({ attackerLabel, attackerIp, zone }: { attackerLabel: string; attackerIp: string; zone: string }) {
  const hops = [
    { id: "attacker", label: attackerLabel, sub: attackerIp, active: true },
    { id: "egress", label: "Egress network", sub: "10.200.3.0/24", active: zone === "egress" || zone === "attacker" },
    { id: "deception", label: "Deception VLAN", sub: "10.200.2.0/24", active: zone === "deception" },
    { id: "honeypot", label: "Honeypot target", sub: "10.200.2.10", active: zone === "honeypot" },
  ];

  return (
    <div className="story-network" aria-label="Network path">
      <span className="story-network-title">Where the attacker moves on the network</span>
      <div className="story-network-track">
        {hops.map((h, i) => (
          <div key={h.id} className="story-network-hop-wrap">
            {i > 0 && <ArrowRight size={18} className="story-network-arrow" aria-hidden />}
            <div className={`story-network-hop ${h.active ? "active" : ""}`}>
              <strong>{h.label}</strong>
              <span className="mono">{h.sub}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AttackStory({ op, selectedId, onSelect }: { op: OperationMap; selectedId: string | null; onSelect: (id: string) => void }) {
  const groups = useMemo(() => stepsByPhase(op), [op]);
  const attacker = op.nodes.find((n) => n.type === "attacker");

  return (
    <div className="attack-story">
      {attacker && (
        <div className="story-origin">
          <span className="story-origin-badge">Starts here</span>
          <button
            type="button"
            className={`story-origin-card ${selectedId === attacker.id ? "selected" : ""}`}
            onClick={() => onSelect(attacker.id)}
          >
            <Server size={20} />
            <div>
              <strong>{attacker.label}</strong>
              <span className="mono">{attacker.ip}</span>
            </div>
          </button>
          <ArrowRight size={20} className="story-origin-arrow" aria-hidden />
        </div>
      )}

      {groups.map(({ phase, steps }) => {
        const meta = PHASE_HUMAN[phase] ?? { title: phase, explain: "" };
        const phaseInfo = op.phases.find((p) => p.id === phase);
        const color = phaseInfo?.color ?? "#0a84ff";

        return (
          <section key={phase} className="story-phase" style={{ borderColor: color }}>
            <header className="story-phase-head" style={{ background: `${color}18` }}>
              <h4 style={{ color }}>{meta.title}</h4>
              <p>{meta.explain}</p>
            </header>
            <div className="story-phase-steps">
              {steps.map((step, si) => (
                <div key={step.id} className="story-step-wrap">
                  {si > 0 && <ArrowRight size={16} className="story-step-arrow" aria-hidden />}
                  <motion.button
                    type="button"
                    className={`story-step-card ${selectedId === step.id ? "selected" : ""}`}
                    style={{ borderColor: selectedId === step.id ? color : undefined }}
                    onClick={() => onSelect(step.id)}
                    whileHover={{ y: -2 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <span className="story-step-num" style={{ background: `${color}30`, color }}>
                      Step {step.index}
                    </span>
                    <strong>{humanLabel(step)}</strong>
                    <span className="story-step-meta">
                      {SURFACE_HUMAN[step.surface ?? ""] ?? step.surface}
                      {step.level ? ` · ${step.level}` : ""}
                    </span>
                    {step.timestamp && (
                      <time className="mono">{step.timestamp.slice(11, 19)}</time>
                    )}
                  </motion.button>
                </div>
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}

type Props = {
  deception: DeceptionState;
  enabled: boolean;
  refreshKey?: string;
  /** Jump straight to this actor's story — set when a user clicks an actor
   *  elsewhere in the dashboard (the network map, the actors table). */
  initialActor?: string;
};

export function VisualsSection({ deception, enabled, refreshKey, initialActor }: Props) {
  const graph = useAttackGraph(enabled, refreshKey);
  const [query, setQuery] = useState("");
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  useEffect(() => {
    if (initialActor) graph.setSelected(initialActor);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- fire once per incoming selection, not on every graph identity change
  }, [initialActor]);

  const machines = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return graph.machines;
    return graph.machines.filter(
      (m) =>
        m.label?.toLowerCase().includes(q) ||
        m.ip?.toLowerCase().includes(q) ||
        m.id.toLowerCase().includes(q)
    );
  }, [graph.machines, query]);

  const op = graph.actorGraph?.operation;

  useEffect(() => {
    if (op?.nodes.length) setSelectedNode(op.nodes[0].id);
  }, [graph.selected, op?.nodes.length]);

  const selectedOpNode = op?.nodes.find((n) => n.id === selectedNode) ?? op?.nodes[0];

  function pickMachine(m: GraphNode) {
    graph.setSelected(m.id);
    setSelectedNode("attacker");
  }

  const open = [
    deception.surfaces.ssh.exposed && "SSH",
    deception.surfaces.https.exposed && "HTTPS",
    deception.surfaces.shell.exposed && "Shell",
    deception.surfaces.sinkhole && "Sinkhole",
  ].filter(Boolean);

  return (
    <motion.section className="visuals-section" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
      <header className="visuals-hero">
        <div>
          <h2>Attack map</h2>
          <p>Follow one host left to right — what it did, in plain order.</p>
          <a className="visuals-pdf-btn" href={ATTACK_MAP_PDF} download="CyberSnare-Attack-Map-Guide.pdf">
            <Download size={16} aria-hidden />
            Download flow guide (PDF)
          </a>
        </div>
        <div className="visuals-posture" role="status">
          <span className={`visuals-level visuals-level-${deception.global_level.toLowerCase()}`}>
            {deception.global_level}
          </span>
          <div className="visuals-posture-copy">
            <strong>{LEVEL_COPY[deception.global_level] ?? deception.rationale}</strong>
            <span>{open.length ? `Open: ${open.join(" · ")}` : "Burn mode"}</span>
          </div>
        </div>
      </header>

      <aside className="story-howto" aria-label="How to read this map">
        <Info size={16} />
        <ol>
          <li><strong>Pick a host</strong> on the left (e.g. Kali attacker).</li>
          <li><strong>Read top to bottom</strong> — each coloured block is an attack phase.</li>
          <li><strong>Follow arrows left → right</strong> inside each phase for the exact steps.</li>
          <li><strong>Click a step</strong> for technique, surface, and time below.</li>
        </ol>
      </aside>

      <div className="visuals-workspace">
        <aside className="visuals-sidebar" aria-label="Hosts">
          <div className="visuals-sidebar-head">
            <h3>Hosts</h3>
            <span className="visuals-count">{machines.length}</span>
          </div>
          <label className="visuals-search">
            <Search size={16} aria-hidden />
            <input type="search" placeholder="Filter hosts" value={query} onChange={(e) => setQuery(e.target.value)} />
          </label>
          <ul className="visuals-machine-list">
            {machines.map((m) => (
              <li key={m.id}>
                <button
                  type="button"
                  className={`visuals-machine-row ${graph.selected === m.id ? "selected" : ""}`}
                  onClick={() => pickMachine(m)}
                >
                  <span className="visuals-machine-icon"><Server size={18} /></span>
                  <span className="visuals-machine-body">
                    <span className="visuals-machine-name">{m.label}</span>
                    <span className="visuals-machine-meta">{m.ip} · {m.events?.toLocaleString()} events</span>
                  </span>
                  <ChevronRight size={16} className="visuals-chevron" />
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <main className="visuals-main">
          {!graph.selected && (
            <div className="visuals-placeholder">
              <h3>Select a host on the left</h3>
              <p>The attack story will appear here as numbered steps you can read like a comic panel — infiltration first, exfiltration last.</p>
            </div>
          )}

          {graph.selected && graph.loadingActor && (
            <div className="visuals-placeholder"><div className="visuals-spinner" /><p>Loading attack story…</p></div>
          )}

          {graph.selected && !graph.loadingActor && op && op.nodes.length > 1 && (
            <>
              <h3 className="story-host-title">{graph.actorGraph?.label}</h3>

              <NetworkPathBar
                attackerLabel={graph.actorGraph?.label ?? "Attacker"}
                attackerIp={graph.actorGraph?.ip ?? ""}
                zone={op.attacker_zone}
              />

              <AttackStory op={op} selectedId={selectedNode} onSelect={setSelectedNode} />

              {selectedOpNode && (
                <article className="visuals-step-card story-detail">
                  <h4>
                    {selectedOpNode.type === "attacker"
                      ? "Attacker machine"
                      : `Step ${selectedOpNode.index} — ${humanLabel(selectedOpNode)}`}
                  </h4>
                  <p className="story-detail-summary">
                    {selectedOpNode.type === "attacker"
                      ? "This is where the attack originated. Everything below is what this host did next."
                      : `${SURFACE_HUMAN[selectedOpNode.surface ?? ""] ?? "Activity"} during ${PHASE_HUMAN[selectedOpNode.phase]?.title ?? selectedOpNode.phase}.`}
                  </p>
                  <dl className="visuals-step-dl">
                    {selectedOpNode.technique_name && (
                      <div><dt>MITRE technique</dt><dd>{selectedOpNode.label} — {selectedOpNode.technique_name}</dd></div>
                    )}
                    {selectedOpNode.surface && (
                      <div><dt>What they touched</dt><dd>{SURFACE_HUMAN[selectedOpNode.surface] ?? selectedOpNode.surface}</dd></div>
                    )}
                    {selectedOpNode.level && (
                      <div><dt>Honeypot level</dt><dd>{selectedOpNode.level}</dd></div>
                    )}
                    {selectedOpNode.timestamp && (
                      <div><dt>When</dt><dd>{new Date(selectedOpNode.timestamp).toLocaleString("en-GB", { hour12: false })}</dd></div>
                    )}
                  </dl>
                </article>
              )}
            </>
          )}

          {graph.selected && !graph.loadingActor && (!op || op.nodes.length <= 1) && (
            <div className="visuals-placeholder"><p>No recent attack steps for this host. Run <code>./cs attacker</code>.</p></div>
          )}
        </main>
      </div>
    </motion.section>
  );
}
