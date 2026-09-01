import { motion } from "framer-motion";
import { useEffect, useState } from "react";
import type { LucideIcon } from "lucide-react";

type Props = {
  label: string;
  value: number;
  icon: LucideIcon;
  accent: string;
  glow: string;
  delay?: number;
  suffix?: string;
};

function AnimatedNumber({ value }: { value: number }) {
  const [shown, setShown] = useState(value);

  useEffect(() => {
    const start = shown;
    const delta = value - start;
    if (delta === 0) return;
    const steps = 24;
    let frame = 0;
    const id = window.setInterval(() => {
      frame += 1;
      const t = frame / steps;
      const eased = 1 - (1 - t) ** 3;
      setShown(Math.round(start + delta * eased));
      if (frame >= steps) window.clearInterval(id);
    }, 16);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- animate from last rendered value
  }, [value]);

  return <span>{shown.toLocaleString()}</span>;
}

export function StatCard({
  label,
  value,
  icon: Icon,
  accent,
  glow,
  delay = 0,
  suffix,
}: Props) {
  return (
    <motion.div
      className="glass-card stat-card"
      initial={{ opacity: 0, y: 24, scale: 0.96 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.5, delay, ease: [0.22, 1, 0.36, 1] }}
      whileHover={{ y: -4, transition: { duration: 0.2 } }}
    >
      <div className="stat-glow" style={{ background: glow }} />
      <div className="stat-top">
        <div className="stat-icon" style={{ color: accent, borderColor: `${accent}33` }}>
          <Icon size={18} strokeWidth={2.2} />
        </div>
        <span className="stat-label">{label}</span>
      </div>
      <div className="stat-value mono" style={{ color: accent }}>
        <AnimatedNumber value={value} />
        {suffix && <span className="stat-suffix">{suffix}</span>}
      </div>
    </motion.div>
  );
}
