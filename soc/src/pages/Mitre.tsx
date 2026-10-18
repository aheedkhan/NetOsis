import { useMemo, useState } from "react";
import { motion, useReducedMotion } from "motion/react";
import { ArrowRight, Grid3x3 } from "lucide-react";
import { useAttack, useEvents, type AttackTech } from "../lib/api";
import { href } from "../lib/router";
import { TACTIC_COLOR, ago, clock } from "../lib/format";
import { Card, CardHead, DemoTag, Empty, ErrorState, PageHead, Skeleton } from "../components/ui";
import { TacticDonut, TechniqueBars } from "../components/Charts";

export default function Mitre({ params }: { params?: URLSearchParams }) {
  const { data, isLoading, error } = useAttack();
  const reduce = useReducedMotion();
  const [tactic, setTactic] = useState<string | null>(params?.get("tactic") ?? null);
  const [tech, setTech] = useState<string | null>(params?.get("technique") ?? null);
  const [showUnseen, setShowUnseen] = useState(false);

  const all = useMemo(() => data?.tactics.flatMap((t) => t.techniques) ?? [], [data]);
  const max = Math.max(1, ...all.map((t) => t.count));
  const seen = new Set(all.map((t) => t.id));
  const picked = all.find((t) => t.id === tech) ?? null;
  const top = [...all].sort((a, b) => b.count - a.count).slice(0, 10);

  if (error) return <ErrorState error={error} />;
  return (
    <>
      <PageHead
        title="MITRE ATT&CK"
        sub={
          data
            ? `${data.total_techniques} of ${data.supported.length} techniques NetOsis can detect were seen · ${data.total_events.toLocaleString()} mapped events`
            : "Loading…"
        }
        right={
          <button className="btn" aria-pressed={showUnseen} onClick={() => setShowUnseen((v) => !v)}>
            Show techniques not seen
          </button>
        }
      />
      <div className="grid gap-4">
        <Card className="overflow-hidden">
          <CardHead title="Technique matrix" sub="Only techniques the NetOsis mapper can emit. Shade = how often; click to inspect." />
          {isLoading ? (
            <Skeleton className="m-4 h-[420px]" />
          ) : (
            <div className="overflow-x-auto p-4">
              <div className="grid min-w-[1180px] grid-cols-12 gap-1.5">
                {data!.tactics.map((col, ci) => {
                  const unseen = showUnseen
                    ? data!.supported.filter((s) => s.tactic === col.tactic && !seen.has(s.id))
                    : [];
                  const dim = tactic && tactic !== col.tactic;
                  return (
                    <div key={col.tactic} className={`flex min-w-0 flex-col gap-1.5 transition-opacity ${dim ? "opacity-35" : ""}`}>
                      <button
                        onClick={() => setTactic(tactic === col.tactic ? null : col.tactic)}
                        className="rounded-lg border border-line bg-[#fafbfd] p-2 text-left hover:bg-hover"
                        aria-pressed={tactic === col.tactic}
                      >
                        <span className="block h-0.5 w-6 rounded" style={{ background: TACTIC_COLOR[col.tactic] }} />
                        <span className="mt-1.5 block text-[11.5px] font-semibold leading-tight">{col.tactic}</span>
                        <span className="num mt-1 block text-[11px] text-ink-3">{col.count ? `${col.count} events` : "—"}</span>
                      </button>
                      {col.techniques.map((t, i) => {
                        const k = t.count / max;
                        return (
                          <motion.button
                            key={t.id}
                            onClick={() => setTech(t.id)}
                            initial={reduce ? false : { opacity: 0, y: 6 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ duration: 0.25, delay: reduce ? 0 : ci * 0.02 + i * 0.02 }}
                            className={`rounded-lg border p-2 text-left transition-shadow hover:shadow-[var(--shadow-float)] ${tech === t.id ? "ring-2 ring-blue" : ""}`}
                            style={{
                              borderColor: TACTIC_COLOR[col.tactic] + (k > 0.5 ? "" : "55"),
                              background: mix(TACTIC_COLOR[col.tactic], 0.06 + Math.sqrt(k) * 0.3),
                            }}
                          >
                            <span className="flex items-baseline justify-between gap-1">
                              <span className="mono text-[10.5px] font-semibold">{t.id}</span>
                              <span className="num rounded bg-white/70 px-1 text-[10.5px] font-semibold">{t.count}</span>
                            </span>
                            <span className="mt-0.5 block text-[11px] leading-tight text-ink-2">{t.name}</span>
                          </motion.button>
                        );
                      })}
                      {unseen.map((s) => (
                        <div key={s.id} className="rounded-lg border border-dashed border-line p-2 text-left text-ink-3">
                          <span className="mono text-[11px]">{s.id}</span>
                          <span className="mt-0.5 block text-[11px] leading-tight">{s.name}</span>
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </Card>

        <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)] gap-4 max-lg:grid-cols-1">
          <Card>
            <CardHead title="Tactic distribution" sub="Click a slice to focus the matrix" />
            {data && data.total_events > 0 ? (
              <TacticDonut tactics={data.tactics} total={data.total_events} height={220} onSelect={(t) => setTactic(t)} />
            ) : (
              <Empty title="No mapped events yet" icon={<Grid3x3 className="size-6" />} />
            )}
          </Card>
          <Card>
            <CardHead title="Most frequent techniques" />
            {top.length ? (
              <div className="px-2 pb-2">
                <TechniqueBars rows={top} height={Math.max(160, top.length * 26)} onSelect={setTech} />
              </div>
            ) : (
              <Empty title="Nothing yet" />
            )}
          </Card>
        </div>
      </div>
      {picked && <TechniqueDetail t={picked} onClose={() => setTech(null)} />}
    </>
  );
}

function TechniqueDetail({ t, onClose }: { t: AttackTech; onClose: () => void }) {
  const { data: events } = useEvents({ q: t.id, limit: "200" });
  const rows = (events ?? []).filter((e) => e.technique === t.id).slice(-25).reverse();
  return (
    <Card className="mt-4">
      <CardHead
        title={
          <span className="flex items-center gap-2">
            <span className="mono">{t.id}</span> {t.name}
          </span>
        }
        sub={`${t.tactic} · ${t.count} events from ${t.actors} source${t.actors === 1 ? "" : "s"} · last seen ${ago(t.last_seen)}`}
        right={
          <>
            <a className="link" href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`} target="_blank" rel="noreferrer">
              MITRE reference <ArrowRight className="size-3" />
            </a>
            <button className="btn" onClick={onClose}>
              Close
            </button>
          </>
        }
      />
      <div className="overflow-x-auto p-4 pt-3">
        <table className="table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Honeypot</th>
              <th>Command that mapped to {t.id}</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.seq} className="cursor-pointer" onClick={() => (window.location.hash = href("sessions", { id: e.session_id }).slice(1))}>
                <td className="num whitespace-nowrap text-ink-3">{clock(e.timestamp)}</td>
                <td className="mono whitespace-nowrap">
                  {e.source_ip} {e.demo && <DemoTag />}
                </td>
                <td className="whitespace-nowrap">{e.target_host}</td>
                <td className="mono max-w-[520px] truncate">{e.command}</td>
                <td className="num">{e.technique_confidence ? `${Math.round(e.technique_confidence * 100)}%` : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <Empty title="No events for this technique in the window" />}
      </div>
    </Card>
  );
}

function mix(hex: string, a: number) {
  const n = parseInt(hex.slice(1), 16);
  const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  const m = (c: number) => Math.round(255 - (255 - c) * a);
  return `rgb(${m(r)},${m(g)},${m(b)})`;
}
