import { Activity, Crosshair, GitBranch, Users, Zap } from "lucide-react";
import type { MilestoneReport } from "../types";
import { StatCard } from "./StatCard";

type Props = { report: MilestoneReport };

export function StatsGrid({ report }: Props) {
  const armCount = Object.keys(report.arms ?? {}).length;

  return (
    <div className="stats-grid">
      <StatCard
        label="Events"
        value={report.total_events}
        icon={Activity}
        accent="var(--cyan)"
        glow="radial-gradient(circle, rgba(34,211,238,0.2), transparent 70%)"
        delay={0.05}
      />
      <StatCard
        label="Actors"
        value={report.unique_actors}
        icon={Users}
        accent="var(--violet)"
        glow="radial-gradient(circle, rgba(167,139,250,0.2), transparent 70%)"
        delay={0.1}
      />
      <StatCard
        label="Transitions"
        value={report.manifest_transitions}
        icon={GitBranch}
        accent="var(--amber)"
        glow="radial-gradient(circle, rgba(251,191,36,0.2), transparent 70%)"
        delay={0.15}
      />
      <StatCard
        label="Arms"
        value={armCount}
        icon={Crosshair}
        accent="var(--emerald)"
        glow="radial-gradient(circle, rgba(52,211,153,0.2), transparent 70%)"
        delay={0.2}
        suffix={armCount === 1 ? " active" : ""}
      />
      <StatCard
        label="Techniques"
        value={Object.keys(report.top_techniques ?? {}).length}
        icon={Zap}
        accent="var(--rose)"
        glow="radial-gradient(circle, rgba(251,113,133,0.2), transparent 70%)"
        delay={0.25}
      />
    </div>
  );
}
