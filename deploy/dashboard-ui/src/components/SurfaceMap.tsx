import { motion } from "framer-motion";
import { Globe, Network, Server, Skull, Terminal } from "lucide-react";
import type { SurfaceState } from "../types";

type Props = { surfaces: SurfaceState };

function SurfaceTile({
  label,
  icon: Icon,
  exposed,
  detail,
  tone,
}: {
  label: string;
  icon: typeof Server;
  exposed: boolean;
  detail: string;
  tone: string;
}) {
  return (
    <motion.div
      className={`surface-tile ${exposed ? "on" : "off"} ${tone}`}
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      whileHover={{ y: -2 }}
    >
      <div className="surface-icon">
        <Icon size={28} strokeWidth={1.8} />
        <span className={`surface-led ${exposed ? "led-on" : "led-off"}`} />
      </div>
      <div className="surface-info">
        <strong>{label}</strong>
        <span className="mono">{detail}</span>
      </div>
      <span className={`surface-status ${exposed ? "status-on" : "status-off"}`}>
        {exposed ? "EXPOSED" : "HIDDEN"}
      </span>
    </motion.div>
  );
}

export function SurfaceMap({ surfaces }: Props) {
  return (
    <section className="glass-card panel surface-map-panel">
      <div className="panel-head">
        <div>
          <h2>Attack surface map</h2>
          <p>What the attacker sees right now</p>
        </div>
      </div>
      <div className="surface-grid">
        <SurfaceTile
          label="SSH"
          icon={Server}
          exposed={surfaces.ssh.exposed}
          detail={`auth: ${surfaces.ssh.auth}`}
          tone="tone-ssh"
        />
        <SurfaceTile
          label="HTTPS"
          icon={Globe}
          exposed={surfaces.https.exposed}
          detail={`auth: ${surfaces.https.auth}`}
          tone="tone-https"
        />
        <SurfaceTile
          label="Shell"
          icon={Terminal}
          exposed={surfaces.shell.exposed}
          detail={surfaces.shell.runtime ? `runtime: ${surfaces.shell.runtime}` : "no shell"}
          tone="tone-shell"
        />
        <SurfaceTile
          label="Sinkhole"
          icon={Network}
          exposed={surfaces.sinkhole}
          detail={surfaces.sinkhole ? "DNS + HTTP egress trap" : "inactive"}
          tone="tone-sinkhole"
        />
      </div>
      {surfaces.shell.exposed && (
        <div className="surface-hint">
          <Skull size={14} />
          <span>L2 engage — restricted shell + command logging active</span>
        </div>
      )}
    </section>
  );
}
