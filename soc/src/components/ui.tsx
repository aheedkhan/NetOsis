import { animate, useReducedMotion } from "motion/react";
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Info } from "lucide-react";
import type { Level, Mode } from "../lib/api";
import { LEVEL, SEVERITY } from "../lib/format";

export function Card({ children, className = "", ...rest }: { children: ReactNode; className?: string } & React.HTMLAttributes<HTMLElement>) {
  return (
    <section className={`card min-w-0 ${className}`} {...rest}>
      {children}
    </section>
  );
}

export function CardHead({ title, sub, right }: { title: ReactNode; sub?: ReactNode; right?: ReactNode }) {
  return (
    <div className="card-head">
      <div className="min-w-0">
        <h2 className="card-title">{title}</h2>
        {sub && <p className="card-sub">{sub}</p>}
      </div>
      {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
    </div>
  );
}

/** Number that eases to its new value — makes live changes legible. */
export function Counter({ value, className = "" }: { value: number; className?: string }) {
  const reduce = useReducedMotion();
  const [shown, setShown] = useState(value);
  const from = useRef(value);
  useEffect(() => {
    if (reduce) {
      setShown(value);
      from.current = value;
      return;
    }
    const c = animate(from.current, value, {
      duration: 0.6,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (v) => setShown(Math.round(v)),
    });
    from.current = value;
    return () => c.stop();
  }, [value, reduce]);
  return <span className={`num ${className}`}>{shown.toLocaleString()}</span>;
}

export function LevelPill({ level }: { level: Level }) {
  const l = LEVEL[level];
  return (
    <span className="pill" style={{ background: l.soft, color: l.ink }}>
      <span className="size-1.5 rounded-full" style={{ background: l.fill }} />
      {l.label}
    </span>
  );
}

export function SeverityPill({ severity }: { severity: string }) {
  const s = SEVERITY[severity] ?? SEVERITY.MEDIUM;
  return (
    <span className="pill" style={{ background: s.soft, color: s.ink }}>
      {s.label}
    </span>
  );
}

const MODE: Record<Mode, { label: string; dot: string; bg: string; ink: string; tip: string }> = {
  live: { label: "Live telemetry", dot: "#10b981", bg: "#e8f8f2", ink: "#047857", tip: "Every figure comes from events the honeypots shipped." },
  demo: { label: "Demo data", dot: "#f5a524", bg: "#fef5e4", ink: "#9a5b00", tip: "Synthetic sessions from scripts/soc_demo.py, replayed through the real pipeline. Addresses are documentation ranges; map locations are illustrative." },
  mixed: { label: "Live + demo data", dot: "#f5a524", bg: "#fef5e4", ink: "#9a5b00", tip: "Some events in this window are synthetic demo sessions. Demo rows are marked." },
  empty: { label: "No data in window", dot: "#94a3b8", bg: "#f1f4f9", ink: "#4d5d73", tip: "Nothing has been recorded in the selected time window." },
};

export function ModeBadge({ mode }: { mode: Mode | undefined }) {
  const m = MODE[mode ?? "empty"];
  return (
    <span className="pill h-7 gap-2 px-2.5 text-[12px]" style={{ background: m.bg, color: m.ink }} title={m.tip}>
      <span className={`size-2 rounded-full ${mode === "live" ? "live-dot" : ""}`} style={{ background: m.dot }} />
      {m.label}
    </span>
  );
}

export function DemoTag() {
  return (
    <span className="pill h-[18px] px-1.5 text-[10px]" style={{ background: "#fef5e4", color: "#9a5b00" }} title="Synthetic demo session">
      Demo
    </span>
  );
}

/**
 * Info icon with a floating explanation. The popover is portalled to <body> and sits
 * above the icon (outside its card) with an arrow, flipping below only when there is
 * no room — so it never covers the number it explains.
 */
export function Definition({ text }: { text: string }) {
  const anchor = useRef<HTMLSpanElement>(null);
  const pop = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number; arrow: number; below: boolean } | null>(null);

  useLayoutEffect(() => {
    if (!open || !anchor.current || !pop.current) return;
    const place = () => {
      const a = anchor.current!.getBoundingClientRect();
      const p = pop.current!.getBoundingClientRect();
      const gap = 10;
      const below = a.top - p.height - gap < 8; // flip only at the very top of the window
      const cx = a.left + a.width / 2;
      const left = Math.min(Math.max(8, cx - p.width / 2), window.innerWidth - p.width - 8);
      const top = below ? a.bottom + gap : a.top - p.height - gap;
      setPos({ left, top, arrow: cx - left, below });
    };
    place();
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);
    return () => {
      window.removeEventListener("scroll", place, true);
      window.removeEventListener("resize", place);
    };
  }, [open]);

  return (
    <span
      ref={anchor}
      className="inline-flex cursor-help rounded-full text-ink-3 outline-none hover:text-ink-2 focus-visible:ring-2 focus-visible:ring-blue/40"
      tabIndex={0}
      aria-label={text}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      <Info className="size-3.5" />
      {open &&
        createPortal(
          <div
            ref={pop}
            role="tooltip"
            className="pointer-events-none fixed z-[100] w-64 rounded-xl border border-white/90 bg-white/85 px-3.5 py-2.5 text-[12px] font-normal leading-snug text-ink-2 shadow-[0_0_0_1px_rgb(20_36_58/0.07),0_12px_32px_-8px_rgb(15_40_90/0.28)] backdrop-blur-xl backdrop-saturate-150"
            style={{ left: pos?.left ?? -9999, top: pos?.top ?? -9999, opacity: pos ? 1 : 0, transition: "opacity .12s" }}
          >
            {text}
            {pos && (
              <span
                className="absolute size-2.5 rotate-45 border-white/90 bg-white"
                style={{
                  left: pos.arrow - 5,
                  ...(pos.below
                    ? { top: -5, borderLeftWidth: 1, borderTopWidth: 1 }
                    : { bottom: -5, borderRightWidth: 1, borderBottomWidth: 1 }),
                }}
              />
            )}
          </div>,
          document.body,
        )}
    </span>
  );
}

export function Empty({ title, children, icon }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      {icon && <div className="text-ink-3">{icon}</div>}
      <div className="text-[13px] font-medium text-ink-2">{title}</div>
      {children && <div className="max-w-sm text-[12px] text-ink-3">{children}</div>}
    </div>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} />;
}

export function ErrorState({ error }: { error: unknown }) {
  return (
    <Empty title="Couldn't load this data">
      {String((error as Error)?.message ?? error)}. The controller may be restarting; it retries automatically.
    </Empty>
  );
}

export function PageHead({ title, sub, right }: { title: string; sub?: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-[20px] font-semibold tracking-[-0.02em]">{title}</h1>
        {sub && <p className="mt-0.5 text-[13px] text-ink-3">{sub}</p>}
      </div>
      {right && <div className="flex items-center gap-2">{right}</div>}
    </div>
  );
}
