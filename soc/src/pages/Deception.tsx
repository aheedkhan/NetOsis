import { motion, useReducedMotion } from "motion/react";
import { Workflow } from "lucide-react";
import { useDeception } from "../lib/api";
import { href } from "../lib/router";
import { DECEPTION_LABEL, ago, clock } from "../lib/format";
import { Card, CardHead, DemoTag, Empty, ErrorState, PageHead, Skeleton } from "../components/ui";

export default function Deception() {
  const { data, isLoading, error } = useDeception();
  const reduce = useReducedMotion();
  if (error) return <ErrorState error={error} />;
  const maxScore = Math.max(10, ...(data?.ladder ?? []).map((l) => l.min_score));
  const maxFired = Math.max(1, ...(data?.ladder ?? []).map((l) => l.fired));

  return (
    <>
      <PageHead
        title="Deception engine"
        sub="The adaptive policy ladder: as a session's risk score climbs, each rung fires once and changes what that attacker sees."
      />
      {data?.policy_error && (
        <div className="card mb-4 border-amber/50 bg-amber-soft p-3 text-[12.5px] text-amber-ink">
          Policy file could not be read on the controller: {data.policy_error}. Fired responses below are still real.
        </div>
      )}
      <div className="grid grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] gap-4 max-xl:grid-cols-1">
        <Card>
          <CardHead title="Policy ladder" sub="Thresholds from policy/rules/baseline.yml · bar = how often the rung fired in this window" />
          {isLoading ? (
            <Skeleton className="m-4 h-[420px]" />
          ) : (
            <ol className="relative grid gap-2 p-4">
              <span className="absolute bottom-8 left-[38px] top-8 w-px bg-line" aria-hidden />
              {data!.ladder.map((l, i) => (
                <motion.li
                  key={l.id}
                  initial={reduce ? false : { opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.25, delay: reduce ? 0 : i * 0.05 }}
                  className="relative grid grid-cols-[48px_minmax(0,1fr)_120px] items-center gap-3 rounded-lg px-1 py-2 hover:bg-hover"
                >
                  <span
                    className={`relative z-[1] grid size-[38px] place-items-center rounded-full text-[12px] font-semibold ${l.fired ? "bg-blue text-white" : "border border-line bg-white text-ink-3"}`}
                  >
                    {l.id}
                  </span>
                  <span className="min-w-0">
                    <span className="block text-[13px] font-semibold">{DECEPTION_LABEL[l.id] ?? l.name}</span>
                    <span className="block truncate text-[12px] text-ink-3" title={l.description}>
                      {l.description}
                    </span>
                    <span className="mt-1 block text-[11px] text-ink-3">
                      fires at risk score ≥ <span className="num font-medium text-ink-2">{l.min_score}</span>
                      <span className="ml-2 inline-block h-1 w-24 rounded-full bg-line-2 align-middle">
                        <span className="block h-1 rounded-full bg-ink-3/60" style={{ width: `${(l.min_score / maxScore) * 100}%` }} />
                      </span>
                    </span>
                  </span>
                  <span className="text-right">
                    <span className="num block text-[18px] font-semibold leading-none">{l.fired}</span>
                    <span className="block text-[11px] text-ink-3">{l.last ? `last ${ago(l.last)}` : "never fired"}</span>
                    <span className="ml-auto mt-1 block h-1 w-full rounded-full bg-line-2">
                      <motion.span
                        className="block h-1 rounded-full bg-blue"
                        initial={false}
                        animate={{ width: `${(l.fired / maxFired) * 100}%` }}
                      />
                    </span>
                  </span>
                </motion.li>
              ))}
            </ol>
          )}
        </Card>

        <Card className="flex max-h-[calc(100vh-170px)] min-h-[480px] flex-col">
          <CardHead title="Response history" sub="Each row is a real deception_action event shipped by a honeypot" />
          <div className="min-h-0 flex-1 overflow-y-auto px-2 pb-2 pt-2">
            {!data || data.history.length === 0 ? (
              <Empty title="No deception responses yet" icon={<Workflow className="size-6" />}>
                Rungs fire as an attacker's risk score passes each threshold.
              </Empty>
            ) : (
              data.history.slice(0, 120).map((e) => (
                <a key={e.seq} href={href("sessions", { id: e.session_id })} className="flex items-start gap-3 rounded-lg px-2 py-2 hover:bg-hover">
                  <span className="mono mt-0.5 grid h-6 w-9 shrink-0 place-items-center rounded-md bg-blue-soft text-[11px] font-semibold text-blue">
                    {e.extra?.action}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-[12.5px] font-medium">{DECEPTION_LABEL[e.extra?.action ?? ""] ?? e.extra?.name}</span>
                    <span className="block truncate text-[11.5px] text-ink-3">
                      for <span className="mono">{e.source_ip}</span> on {e.target_host} · {e.extra?.reason}
                    </span>
                    <span className="mono block truncate text-[11px] text-ink-3">triggered by: {e.command}</span>
                  </span>
                  <span className="flex shrink-0 flex-col items-end gap-1">
                    <span className="num text-[11px] text-ink-3">{clock(e.timestamp)}</span>
                    {e.demo && <DemoTag />}
                  </span>
                </a>
              ))
            )}
          </div>
        </Card>
      </div>

      {data && Object.keys(data.weights).length > 0 && (
        <Card className="mt-4">
          <CardHead title="Risk weights" sub="How much each kind of behaviour adds to a session's score (policy/rules/baseline.yml)" />
          <div className="grid grid-cols-4 gap-x-6 gap-y-1 p-4 max-lg:grid-cols-2">
            {Object.entries(data.weights)
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) => (
                <div key={k} className="flex items-center justify-between border-b border-line-2 py-1.5 text-[12.5px]">
                  <span className="text-ink-2">{k.replace(/_/g, " ")}</span>
                  <span className="num font-semibold">+{v}</span>
                </div>
              ))}
          </div>
        </Card>
      )}
    </>
  );
}
