import { useMemo, useState } from "react";
import { ArrowRight, Fingerprint, Globe2 } from "lucide-react";
import { useGeo, type GeoPoint } from "../lib/api";
import { href } from "../lib/router";
import { LEVEL, ago } from "../lib/format";
import { Card, CardHead, DemoTag, Empty, ErrorState, LevelPill, PageHead, Skeleton } from "../components/ui";
import { Globe, GeoProvenance, REGIONS, getCountryFlag, inRegion } from "../components/Globe";

export default function GlobalMap() {
  const { data, isLoading, error } = useGeo();
  const [region, setRegion] = useState("world");
  const [country, setCountry] = useState<string | null>(null);
  const [sel, setSel] = useState<GeoPoint | null>(null);

  const pts = useMemo(
    () => (data?.points ?? []).filter((p) => inRegion(p, region) && (!country || p.country === country)),
    [data, region, country],
  );
  const countries = useMemo(() => {
    const m = new Map<string, { n: number; events: number; worst: keyof typeof LEVEL; iso?: string; top: GeoPoint; personas: Map<string, number> }>();
    for (const p of (data?.points ?? []).filter((x) => inRegion(x, region))) {
      const c = p.country ?? "Unknown";
      const v = m.get(c) ?? { n: 0, events: 0, worst: "LOW", iso: p.iso, top: p, personas: new Map() };
      v.n += 1;
      v.events += p.events;
      if (LEVEL[p.level].rank > LEVEL[v.worst].rank) v.worst = p.level;
      if (p.events > v.top.events) v.top = p;
      v.personas.set(p.persona, (v.personas.get(p.persona) ?? 0) + 1);
      m.set(c, v);
    }
    return [...m.entries()].sort((a, b) => b[1].events - a[1].events);
  }, [data, region]);

  if (error) return <ErrorState error={error} />;
  const filtered = data ? { ...data, points: pts } : undefined;
  const maxEv = Math.max(1, ...countries.map(([, v]) => v.events));
  const totalEv = countries.reduce((n, [, v]) => n + v.events, 0);

  return (
    <>
      <PageHead
        title="Global attack map"
        sub="Approximate registered location of each attacking network. An IP's location is not a verified attacker location; private and lab addresses are never mapped."
        right={
          <div className="flex flex-wrap gap-1">
            {REGIONS.map((r) => (
              <button key={r.id} className="btn" aria-pressed={region === r.id} onClick={() => { setRegion(r.id); setCountry(null); }}>
                {r.label}
              </button>
            ))}
          </div>
        }
      />
      <div className="grid grid-cols-[minmax(0,1fr)_340px] items-start gap-4 max-xl:grid-cols-1">
        <Card className="overflow-hidden">
          {isLoading ? (
            <Skeleton className="m-4 h-[620px]" />
          ) : data && data.points.length === 0 ? (
            <div className="grid h-[620px] place-items-center">
              <Empty title="No sources can be placed on the map" icon={<Fingerprint className="size-6" />}>
                <GeoProvenance data={data} />
              </Empty>
            </div>
          ) : (
            <Globe data={filtered} height={640} region={region} selected={sel?.ip} onSelect={setSel} />
          )}
          <div className="border-t border-line-2 px-4 py-2.5">
            <GeoProvenance data={data} />
            {data && !data.geodb.available && (
              <p className="mt-1 text-[11.5px] text-ink-3">
                Live public-IP lookup needs a MaxMind GeoLite2 database at <span className="mono">data/geoip/</span> on the controller (free licence), plus{" "}
                <span className="mono">NETOSIS_SITE_LAT/LNG</span> for the lab's own location.
              </p>
            )}
          </div>
        </Card>

        <div className="flex flex-col gap-4">
          {sel && (
            <Card>
              <CardHead
                title={`${getCountryFlag(sel.iso)}  ${sel.city ? `${sel.city}, ` : ""}${sel.country ?? "Unknown"}`}
                sub={sel.source === "demo" ? "Illustrative demo location" : `Approximate · ${sel.source}`}
                right={<button className="btn" onClick={() => setSel(null)}>Close</button>}
              />
              <div className="grid gap-2 p-4 pt-3 text-[12.5px]">
                <div className="flex items-center gap-2">
                  <span className="mono font-semibold">{sel.ip}</span> <LevelPill level={sel.level} /> {sel.demo && <DemoTag />}
                </div>
                <div className="text-ink-2">
                  {sel.persona} · {sel.events} events · {sel.sessions} session{sel.sessions === 1 ? "" : "s"}
                </div>
                <div className="text-ink-3">Reached: {sel.hosts.join(", ") || "—"} · last seen {ago(sel.last_seen)}</div>
                <a className="link" href={href("sessions", { ip: sel.ip })}>
                  Replay sessions <ArrowRight className="size-3" />
                </a>
              </div>
            </Card>
          )}
          <Card className={`flex min-h-0 flex-col ${sel ? "max-h-[520px]" : "max-h-[716px]"}`}>
            <CardHead
              title="Top source countries"
              sub={country ? `Filtered to ${country} — click again to clear` : "Attacks per country in this region, busiest first"}
              right={country ? <button className="btn" onClick={() => setCountry(null)}>Clear</button> : undefined}
            />
            <div className="min-h-0 flex-1 overflow-y-auto p-2">
              {countries.length === 0 && <Empty title="No mapped sources here" icon={<Globe2 className="size-6" />} />}
              {countries.map(([c, v], i) => {
                const active = country === c;
                const persona = [...v.personas.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
                return (
                  <button
                    key={c}
                    onClick={() => {
                      setCountry(active ? null : c);
                      setSel(active ? null : v.top); // fly to its busiest source
                    }}
                    aria-pressed={active}
                    className={`grid w-full grid-cols-[22px_minmax(0,1fr)_auto] items-center gap-x-2.5 rounded-xl px-2.5 py-2 text-left transition-colors hover:bg-hover ${active ? "bg-blue-soft" : ""}`}
                  >
                    <span className="num text-[11px] text-ink-3">{i + 1}</span>
                    <span className="min-w-0">
                      <span className="flex items-center gap-1.5 text-[13px] font-semibold">
                        <span className="text-[15px] leading-none">{getCountryFlag(v.iso)}</span>
                        <span className="truncate">{c}</span>
                        <span className="size-1.5 shrink-0 rounded-full" style={{ background: LEVEL[v.worst].fill }} title={LEVEL[v.worst].label} />
                      </span>
                      <span className="block truncate text-[11px] text-ink-3">
                        {v.n} source{v.n === 1 ? "" : "s"}
                        {persona ? ` · mostly ${persona.toLowerCase()}` : ""}
                      </span>
                    </span>
                    <span className="text-right">
                      <span className="num block text-[13px] font-semibold">{v.events.toLocaleString()}</span>
                      <span className="num block text-[10.5px] text-ink-3">{totalEv ? Math.round((v.events / totalEv) * 100) : 0}%</span>
                    </span>
                    <span className="col-span-3 mt-1.5 h-1 rounded-full bg-line-2">
                      <span className="block h-1 rounded-full" style={{ width: `${(v.events / maxEv) * 100}%`, background: LEVEL[v.worst].fill }} />
                    </span>
                  </button>
                );
              })}
            </div>
          </Card>
        </div>
      </div>

      <Card className="mt-4">
        <CardHead title="Sources" sub={`${pts.length} mapped source${pts.length === 1 ? "" : "s"}${country ? ` in ${country}` : ""}`} />
        <div className="max-h-[360px] overflow-auto">
          <table className="table mt-2">
            <thead>
              <tr>
                <th>Source</th>
                <th>Location</th>
                <th>Behaviour</th>
                <th>Risk</th>
                <th>Events</th>
                <th>Reached</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {[...pts].sort((a, b) => LEVEL[b.level].rank - LEVEL[a.level].rank || b.events - a.events).slice(0, 200).map((p) => (
                <tr key={p.ip} className="cursor-pointer" data-selected={sel?.ip === p.ip} onClick={() => setSel(p)}>
                  <td className="mono whitespace-nowrap">
                    {p.ip} {p.demo && <DemoTag />}
                  </td>
                  <td className="whitespace-nowrap">
                    <span className="mr-1.5">{getCountryFlag(p.iso)}</span>
                    {p.city ? `${p.city}, ` : ""}
                    {p.country}
                  </td>
                  <td>{p.persona}</td>
                  <td><LevelPill level={p.level} /></td>
                  <td className="num">{p.events}</td>
                  <td className="whitespace-nowrap">{p.hosts.join(", ")}</td>
                  <td className="num whitespace-nowrap text-ink-3">{ago(p.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
