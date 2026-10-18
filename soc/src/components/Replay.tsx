import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { Pause, Play, RotateCcw, SkipBack, SkipForward } from "lucide-react";
import type { SocEvent } from "../lib/api";
import { DECEPTION_LABEL, TACTICS, TACTIC_COLOR, TECHNIQUE_TACTIC, clock } from "../lib/format";

/**
 * Attack replay: steps through one session's real events in order. Each step
 * lights the ATT&CK tactic it maps to and prints what the attacker typed and
 * what the honeypot answered. Timing is compressed (real gaps are shown, not
 * waited for) so a 20-minute session replays in under a minute.
 */
export function Replay({ events, autoplay = true }: { events: SocEvent[]; autoplay?: boolean }) {
  const reduce = useReducedMotion();
  const steps = useMemo(
    () => events.filter((e) => e.event_type !== "auth_failure" || e === events.find((x) => x.event_type === "auth_failure")),
    [events],
  );
  const failures = events.filter((e) => e.event_type === "auth_failure").length;
  const [i, setI] = useState(0);
  const [playing, setPlaying] = useState(autoplay && !reduce);
  const [speed, setSpeed] = useState(1);
  const term = useRef<HTMLDivElement>(null);
  const sessionKey = events[0]?.session_id;

  useEffect(() => {
    setI(reduce ? steps.length : 0);
    setPlaying(autoplay && !reduce);
  }, [sessionKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!playing) return;
    if (i >= steps.length) {
      setPlaying(false);
      return;
    }
    const cur = steps[i];
    const prev = steps[i - 1];
    const gap = prev ? (new Date(cur.timestamp).getTime() - new Date(prev.timestamp).getTime()) / 1000 : 0;
    // compressed: 450 ms base, plus a little for long real pauses
    const delay = (450 + Math.min(1100, Math.sqrt(Math.max(0, gap)) * 140)) / speed;
    const t = window.setTimeout(() => setI((x) => x + 1), delay);
    return () => window.clearTimeout(t);
  }, [playing, i, steps, speed]);

  useEffect(() => {
    term.current?.scrollTo({ top: term.current.scrollHeight, behavior: reduce ? "auto" : "smooth" });
  }, [i, reduce]);

  const shown = steps.slice(0, i);
  const reached = new Map<string, number>();
  for (const e of shown) {
    const tac = e.technique ? TECHNIQUE_TACTIC[e.technique] : e.event_type === "auth_success" ? "Initial Access" : undefined;
    if (tac) reached.set(tac, (reached.get(tac) ?? 0) + 1);
  }
  const current = shown[shown.length - 1];
  const currentTactic = current?.technique ? TECHNIQUE_TACTIC[current.technique] : current?.event_type === "auth_success" ? "Initial Access" : undefined;
  const t0 = steps[0] ? new Date(steps[0].timestamp).getTime() : 0;

  return (
    <div className="flex min-h-0 flex-col gap-3">
      {/* kill chain rail */}
      <div className="grid grid-cols-12 gap-1" aria-label="ATT&CK tactics reached so far">
        {TACTICS.map((t) => {
          const n = reached.get(t) ?? 0;
          const active = t === currentTactic;
          return (
            <div key={t} className="min-w-0" title={`${t}: ${n} step${n === 1 ? "" : "s"}`}>
              <div className="relative h-1.5 overflow-hidden rounded-full bg-line-2">
                <motion.div
                  className="absolute inset-y-0 left-0 rounded-full"
                  style={{ background: TACTIC_COLOR[t] }}
                  initial={false}
                  animate={{ width: n ? "100%" : "0%" }}
                  transition={{ duration: reduce ? 0 : 0.4, ease: [0.22, 1, 0.36, 1] }}
                />
              </div>
              <div
                className={`mt-1 line-clamp-2 min-h-[2.4em] text-[10px] leading-[1.2] transition-colors ${active ? "font-semibold" : n ? "text-ink-2" : "text-ink-3/70"}`}
                style={active ? { color: TACTIC_COLOR[t] } : undefined}
              >
                {t}
              </div>
            </div>
          );
        })}
      </div>

      {/* terminal */}
      <div
        ref={term}
        className="mono min-h-[300px] flex-1 overflow-y-auto rounded-xl border border-line bg-[#fbfcfe] p-4 text-[12.5px] leading-relaxed"
        aria-live="polite"
      >
        {failures > 0 && (
          <div className="text-ink-3">
            # {failures} failed login{failures > 1 ? "s" : ""} before this session
            {events.find((e) => e.event_type === "auth_failure")?.extra?.username
              ? ` (tried ${[...new Set(events.filter((e) => e.event_type === "auth_failure").map((e) => e.extra?.username))].slice(0, 5).join(", ")})`
              : ""}
          </div>
        )}
        <AnimatePresence initial={false}>
          {shown.map((e, idx) => (
            <motion.div
              key={e.seq}
              initial={reduce ? false : { opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2 }}
              className={`group relative -mx-2 rounded-md px-2 py-0.5 ${idx === shown.length - 1 ? "bg-blue-soft/60" : ""}`}
            >
              <Line e={e} t0={t0} />
            </motion.div>
          ))}
        </AnimatePresence>
        {playing && i < steps.length && <span className="ml-0.5 inline-block h-[14px] w-[7px] translate-y-[2px] animate-pulse bg-ink/70" />}
        {steps.length === 0 && <div className="text-ink-3"># no events in this session</div>}
      </div>

      {/* transport */}
      <div className="flex items-center gap-2">
        <button className="btn" onClick={() => { setI(0); setPlaying(true); }} aria-label="Restart replay">
          <RotateCcw className="size-3.5" />
        </button>
        <button className="btn" onClick={() => setI((x) => Math.max(0, x - 1))} aria-label="Step back">
          <SkipBack className="size-3.5" />
        </button>
        <button
          className="btn min-w-[84px] justify-center border-blue bg-blue text-white hover:bg-[#1d4fd0] hover:text-white"
          onClick={() => (i >= steps.length ? (setI(0), setPlaying(true)) : setPlaying((p) => !p))}
        >
          {playing ? <Pause className="size-3.5" /> : <Play className="size-3.5" />}
          {playing ? "Pause" : i >= steps.length ? "Replay" : "Play"}
        </button>
        <button className="btn" onClick={() => setI((x) => Math.min(steps.length, x + 1))} aria-label="Step forward">
          <SkipForward className="size-3.5" />
        </button>
        <input
          type="range"
          min={0}
          max={steps.length}
          value={i}
          onChange={(e) => { setI(+e.target.value); setPlaying(false); }}
          className="mx-2 h-1 flex-1 accent-[#2563eb]"
          aria-label="Replay position"
        />
        <span className="num w-16 text-right text-[12px] text-ink-3">
          {i}/{steps.length}
        </span>
        <select value={speed} onChange={(e) => setSpeed(+e.target.value)} className="field h-[30px] text-[12px]" aria-label="Replay speed">
          {[0.5, 1, 2, 4].map((s) => (
            <option key={s} value={s}>
              {s}×
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}

function Line({ e, t0 }: { e: SocEvent; t0: number }) {
  const rel = Math.max(0, Math.round((new Date(e.timestamp).getTime() - t0) / 1000));
  const stamp = <span className="mr-2 inline-block w-[52px] text-ink-3/80">+{rel}s</span>;
  if (e.event_type === "auth_failure" || e.event_type === "auth_success") {
    return (
      <div className="text-ink-2">
        {stamp}
        <span className={e.event_type === "auth_success" ? "text-green-ink" : "text-red-ink"}>
          {e.event_type === "auth_success" ? "✓ login" : "✗ login"} as {e.extra?.username ?? "?"}
        </span>
        <span className="text-ink-3"> from {e.source_ip}</span>
      </div>
    );
  }
  if (e.event_type === "deception_action") {
    return (
      <div className="font-sans text-[12px] text-green-ink">
        {stamp}
        <span className="font-semibold">↳ deception {e.extra?.action}</span> · {DECEPTION_LABEL[e.extra?.action ?? ""]}
        <span className="text-ink-3"> — {e.extra?.reason}</span>
      </div>
    );
  }
  if (e.event_type === "lateral_movement") {
    return (
      <div className="text-red-ink">
        {stamp}
        <span className="font-semibold">⇢ pivot</span> {e.extra?.from_host} → {e.target_host} <span className="text-ink-3">({e.command})</span>
      </div>
    );
  }
  const tac = e.technique ? TECHNIQUE_TACTIC[e.technique] : undefined;
  const out = (e.result || "").split("\n").slice(0, 4);
  return (
    <div>
      <div className="flex items-baseline gap-0">
        {stamp}
        <span className="text-ink-3">{e.target_host}$&nbsp;</span>
        <span className="font-medium text-ink">{e.command}</span>
        {e.technique && (
          <span
            className="ml-auto shrink-0 pl-3 font-sans text-[10.5px] font-semibold"
            style={{ color: tac ? TACTIC_COLOR[tac] : undefined }}
            title={`${e.technique_name ?? ""} · ${tac ?? ""}`}
          >
            {e.technique}
          </span>
        )}
      </div>
      {out[0] && (
        <div className="whitespace-pre-wrap break-all pl-[60px] text-[11.5px] text-ink-3">
          {out.join("\n")}
          {(e.result || "").split("\n").length > 4 ? "\n…" : ""}
        </div>
      )}
    </div>
  );
}

export { clock };
